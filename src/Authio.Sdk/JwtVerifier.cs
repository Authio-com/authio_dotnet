using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Authio;

/// <summary>
/// Verifies Authio access-token JWTs against the remote JWKS.
///
/// <para>Authio signs tokens with <b>EdDSA</b> (Ed25519). This verifier parses
/// the compact JWT and JWKS with System.Text.Json and performs the signature
/// check with the vetted BouncyCastle Ed25519 primitive (pure-managed,
/// cross-platform, no native dependency).</para>
///
/// <para>JWKS responses are cached in-memory with a TTL; an unknown <c>kid</c>
/// triggers at most one refetch per cooldown window (handles key rotation).</para>
/// </summary>
public sealed class JwtVerifier
{
    private static readonly TimeSpan CacheTtl = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan RefetchCooldown = TimeSpan.FromSeconds(30);
    private const long ClockSkewSeconds = 60;

    private readonly string _jwksUrl;
    private readonly string? _issuer;
    private readonly string? _audience;
    private readonly HttpClient _http;
    private readonly SemaphoreSlim _lock = new(1, 1);

    private Dictionary<string, byte[]>? _keysByKid; // kid -> raw 32-byte Ed25519 public key
    private DateTimeOffset _fetchedAt = DateTimeOffset.MinValue;

    public JwtVerifier(string jwksUrl, string? issuer, string? audience, HttpClient? http = null)
    {
        _jwksUrl = jwksUrl;
        _issuer = issuer;
        _audience = audience;
        _http = http ?? new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
    }

    /// <summary>
    /// Verify a token and return its claims as a JSON object. Throws
    /// <see cref="AuthioException"/> (code <c>invalid_token</c>) on any failure.
    /// </summary>
    public async Task<JsonElement> VerifyAsync(string token, CancellationToken ct = default)
    {
        var parts = token.Split('.');
        if (parts.Length != 3)
            throw Invalid("malformed JWT");

        JsonElement header;
        try
        {
            header = JsonSerializer.Deserialize<JsonElement>(Base64Url.Decode(parts[0]));
        }
        catch (Exception ex)
        {
            throw Invalid("malformed JWT header", ex);
        }

        var alg = header.TryGetProperty("alg", out var a) ? a.GetString() : null;
        if (alg != "EdDSA")
            throw Invalid($"unexpected JWS algorithm: {alg}");
        var kid = header.TryGetProperty("kid", out var k) ? k.GetString() : null;

        var key = await ResolveKeyAsync(kid, ct).ConfigureAwait(false);
        var signingInput = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);
        var sig = Base64Url.Decode(parts[2]);
        if (!VerifyEd25519(key, signingInput, sig))
            throw Invalid("signature verification failed");

        JsonElement claims;
        try
        {
            claims = JsonSerializer.Deserialize<JsonElement>(Base64Url.Decode(parts[1]));
        }
        catch (Exception ex)
        {
            throw Invalid("unreadable claims", ex);
        }

        ValidateClaims(claims);
        return claims;
    }

    private void ValidateClaims(JsonElement claims)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (claims.TryGetProperty("exp", out var exp) && exp.ValueKind == JsonValueKind.Number)
        {
            if (now > exp.GetInt64() + ClockSkewSeconds)
                throw Invalid("token expired");
        }
        if (claims.TryGetProperty("nbf", out var nbf) && nbf.ValueKind == JsonValueKind.Number)
        {
            if (now < nbf.GetInt64() - ClockSkewSeconds)
                throw Invalid("token not yet valid");
        }
        if (_issuer is not null)
        {
            var iss = claims.TryGetProperty("iss", out var i) ? i.GetString() : null;
            if (iss != _issuer)
                throw Invalid("issuer mismatch");
        }
        if (_audience is not null && !AudienceContains(claims, _audience))
            throw Invalid("audience mismatch");

        var sub = claims.TryGetProperty("sub", out var s) ? s.GetString() : null;
        if (string.IsNullOrEmpty(sub))
            throw Invalid("missing sub claim");
    }

    private static bool AudienceContains(JsonElement claims, string audience)
    {
        if (!claims.TryGetProperty("aud", out var aud))
            return false;
        if (aud.ValueKind == JsonValueKind.String)
            return aud.GetString() == audience;
        if (aud.ValueKind == JsonValueKind.Array)
            return aud.EnumerateArray().Any(e => e.ValueKind == JsonValueKind.String && e.GetString() == audience);
        return false;
    }

    private static bool VerifyEd25519(byte[] rawPublicKey, byte[] message, byte[] signature)
    {
        try
        {
            var pub = new Ed25519PublicKeyParameters(rawPublicKey, 0);
            var verifier = new Ed25519Signer();
            verifier.Init(false, pub);
            verifier.BlockUpdate(message, 0, message.Length);
            return verifier.VerifySignature(signature);
        }
        catch
        {
            return false;
        }
    }

    private async Task<byte[]> ResolveKeyAsync(string? kid, CancellationToken ct)
    {
        var keys = await JwksAsync(false, ct).ConfigureAwait(false);
        if (TryGet(keys, kid, out var key))
            return key;

        keys = await JwksAsync(true, ct).ConfigureAwait(false);
        if (TryGet(keys, kid, out key))
            return key;

        throw Invalid($"no signing key for kid={kid}");
    }

    private static bool TryGet(Dictionary<string, byte[]> keys, string? kid, out byte[] key)
    {
        if (kid is not null && keys.TryGetValue(kid, out var byKid))
        {
            key = byKid;
            return true;
        }
        if (kid is null && keys.Count > 0)
        {
            key = keys.Values.First();
            return true;
        }
        key = Array.Empty<byte>();
        return false;
    }

    private async Task<Dictionary<string, byte[]>> JwksAsync(bool forceRefetch, CancellationToken ct)
    {
        var local = _keysByKid;
        var fresh = local is not null && DateTimeOffset.UtcNow < _fetchedAt + CacheTtl;
        if (!forceRefetch && fresh)
            return local!;
        if (forceRefetch && local is not null && DateTimeOffset.UtcNow < _fetchedAt + RefetchCooldown)
            return local;

        await _lock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (!forceRefetch && _keysByKid is not null && DateTimeOffset.UtcNow < _fetchedAt + CacheTtl)
                return _keysByKid;

            using var req = new HttpRequestMessage(HttpMethod.Get, _jwksUrl);
            req.Headers.Add("User-Agent", SdkVersion.UserAgent);
            req.Headers.Add("Accept", "application/json");
            var res = await _http.SendAsync(req, ct).ConfigureAwait(false);
            if ((int)res.StatusCode != 200)
            {
                if (_keysByKid is not null) return _keysByKid;
                throw new AuthioException("jwks_fetch_failed", $"JWKS endpoint returned {(int)res.StatusCode}", (int)res.StatusCode);
            }
            var body = await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            _keysByKid = ParseJwks(body);
            _fetchedAt = DateTimeOffset.UtcNow;
            return _keysByKid;
        }
        catch (AuthioException)
        {
            throw;
        }
        catch (Exception ex)
        {
            if (_keysByKid is not null) return _keysByKid;
            throw new AuthioException("jwks_fetch_failed", ex.Message, 0, inner: ex);
        }
        finally
        {
            _lock.Release();
        }
    }

    private static Dictionary<string, byte[]> ParseJwks(string json)
    {
        var map = new Dictionary<string, byte[]>();
        using var doc = JsonDocument.Parse(json);
        if (!doc.RootElement.TryGetProperty("keys", out var keys))
            return map;
        var idx = 0;
        foreach (var jwk in keys.EnumerateArray())
        {
            var kty = jwk.TryGetProperty("kty", out var t) ? t.GetString() : null;
            var crv = jwk.TryGetProperty("crv", out var c) ? c.GetString() : null;
            if (kty != "OKP" || crv != "Ed25519")
                continue;
            if (!jwk.TryGetProperty("x", out var x) || x.ValueKind != JsonValueKind.String)
                continue;
            var raw = Base64Url.Decode(x.GetString()!);
            var kid = jwk.TryGetProperty("kid", out var k) ? k.GetString() : null;
            map[kid ?? $"__index_{idx}"] = raw;
            idx++;
        }
        return map;
    }

    private static AuthioException Invalid(string message, Exception? inner = null) =>
        new("invalid_token", "authio: " + message, 401, inner: inner);
}

/// <summary>Base64url (RFC 7515) decoding without padding.</summary>
internal static class Base64Url
{
    public static byte[] Decode(string input)
    {
        var s = input.Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4)
        {
            case 2: s += "=="; break;
            case 3: s += "="; break;
        }
        return Convert.FromBase64String(s);
    }
}

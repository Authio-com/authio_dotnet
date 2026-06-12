using System.Text;
using Authio;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Xunit;

namespace Authio.Sdk.Tests;

/// <summary>
/// End-to-end verification: mint a real Ed25519 keypair (BouncyCastle), serve a
/// JWKS via the fake handler, hand-sign a compact JWT, and assert the verifier
/// accepts valid tokens and rejects tampered/expired ones.
/// </summary>
public class JwtVerifierTests
{
    private static string B64(byte[] b) =>
        Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static string B64(string s) => B64(Encoding.UTF8.GetBytes(s));

    private sealed record Keys(Ed25519PrivateKeyParameters Priv, Ed25519PublicKeyParameters Pub);

    private static Keys NewKeys()
    {
        var gen = new Ed25519KeyPairGenerator();
        gen.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        var kp = gen.GenerateKeyPair();
        return new Keys((Ed25519PrivateKeyParameters)kp.Private, (Ed25519PublicKeyParameters)kp.Public);
    }

    private static string SignJwt(Ed25519PrivateKeyParameters priv, string kid, string claimsJson)
    {
        var header = B64($"{{\"alg\":\"EdDSA\",\"typ\":\"JWT\",\"kid\":\"{kid}\"}}");
        var payload = B64(claimsJson);
        var signingInput = header + "." + payload;
        var signer = new Ed25519Signer();
        signer.Init(true, priv);
        var msg = Encoding.ASCII.GetBytes(signingInput);
        signer.BlockUpdate(msg, 0, msg.Length);
        return signingInput + "." + B64(signer.GenerateSignature());
    }

    private static string Jwks(Ed25519PublicKeyParameters pub, string kid) =>
        $"{{\"keys\":[{{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"use\":\"sig\",\"alg\":\"EdDSA\",\"kid\":\"{kid}\",\"x\":\"{B64(pub.GetEncoded())}\"}}]}}";

    private static AuthioClient Client(TestHandler h, string? iss = null, string? aud = null) =>
        new(new AuthioOptions
        {
            ApiKey = "sk_test",
            ApiUrl = "https://api.test",
            AuthCoreUrl = "https://api.test",
            JwtIssuer = iss,
            JwtAudience = aud,
            HttpClient = new HttpClient(h),
        });

    private static long Exp(int deltaSeconds) => DateTimeOffset.UtcNow.ToUnixTimeSeconds() + deltaSeconds;

    [Fact]
    public async Task VerifiesValidTokenAndBuildsSession()
    {
        var k = NewKeys();
        var h = TestHandler.Sequence(new Canned(200, Jwks(k.Pub, "key-1")));
        var a = Client(h);
        var token = SignJwt(k.Priv, "key-1",
            $"{{\"sub\":\"user_1\",\"sid\":\"sess_1\",\"act_org\":\"org_1\",\"act_role\":\"admin\",\"exp\":{Exp(3600)},\"plan\":\"pro\"}}");

        var session = await a.Sessions.VerifyAsync(token);
        Assert.NotNull(session);
        Assert.Equal("user_1", session!.UserId);
        Assert.Equal("sess_1", session.SessionId);
        Assert.Equal("org_1", session.OrgId);
        Assert.Equal("admin", session.Role);
        Assert.True(session.Claims.ContainsKey("plan"));
        Assert.False(session.Claims.ContainsKey("sub"));
    }

    [Fact]
    public async Task ReturnsNullForTamperedToken()
    {
        var k = NewKeys();
        var h = TestHandler.Sequence(new Canned(200, Jwks(k.Pub, "key-1")));
        var a = Client(h);
        var token = SignJwt(k.Priv, "key-1", $"{{\"sub\":\"user_1\",\"exp\":{Exp(3600)}}}");
        var tampered = token[..^4] + "AAAA";
        Assert.Null(await a.Sessions.VerifyAsync(tampered));
    }

    [Fact]
    public async Task RejectsExpiredToken()
    {
        var k = NewKeys();
        var h = TestHandler.Sequence(new Canned(200, Jwks(k.Pub, "key-1")));
        var a = Client(h);
        var token = SignJwt(k.Priv, "key-1", $"{{\"sub\":\"user_1\",\"exp\":{Exp(-3600)}}}");
        Assert.Null(await a.Sessions.VerifyAsync(token));
        var err = await Assert.ThrowsAsync<AuthioException>(() => a.Sessions.VerifyOrThrowAsync(token));
        Assert.Equal("invalid_token", err.Code);
    }

    [Fact]
    public async Task EnforcesIssuerAndAudienceWhenConfigured()
    {
        var k = NewKeys();
        var h = TestHandler.Sequence(new Canned(200, Jwks(k.Pub, "key-1")));
        var a = Client(h, iss: "https://api.authio.com", aud: "authio");
        var wrong = SignJwt(k.Priv, "key-1",
            $"{{\"sub\":\"u\",\"exp\":{Exp(3600)},\"iss\":\"https://evil.example\",\"aud\":\"authio\"}}");
        Assert.Null(await a.Sessions.VerifyAsync(wrong));
        var ok = SignJwt(k.Priv, "key-1",
            $"{{\"sub\":\"u\",\"exp\":{Exp(3600)},\"iss\":\"https://api.authio.com\",\"aud\":\"authio\"}}");
        Assert.NotNull(await a.Sessions.VerifyAsync(ok));
    }
}

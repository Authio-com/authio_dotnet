using System.Security.Cryptography;
using System.Text;

namespace Authio;

/// <summary>
/// Verifies inbound Authio webhook signatures.
///
/// <para>Mirrors the platform signing primitive exactly (authio_webhooks
/// <c>internal/signing</c>). The <c>Authio-Signature</c> header is Stripe-style:</para>
///
/// <code>Authio-Signature: t=&lt;unix-seconds&gt;,v1=&lt;hex-hmac-sha256&gt;</code>
///
/// <para>The signature is HMAC-SHA256 over <c>&lt;t&gt;.&lt;raw-body&gt;</c> using
/// the per-endpoint <c>whsec_…</c> secret. Verify against the <b>raw</b> request
/// body (pre-JSON-parse). A tolerance window (default 5 minutes) defeats replay;
/// pass <c>0</c> to disable the time check.</para>
/// </summary>
public static class WebhookSignature
{
    /// <summary>Default replay tolerance: 5 minutes, matching the platform receivers.</summary>
    public const long DefaultToleranceSeconds = 300;

    /// <summary>Verify a signature header against a raw body.</summary>
    public static bool Verify(string secret, string body, string signatureHeader, long toleranceSeconds = DefaultToleranceSeconds)
    {
        if (secret is null || body is null || signatureHeader is null)
            return false;

        string? t = null, v1 = null;
        foreach (var part in signatureHeader.Split(','))
        {
            if (part.StartsWith("t=", StringComparison.Ordinal))
                t = part[2..];
            else if (part.StartsWith("v1=", StringComparison.Ordinal))
                v1 = part[3..];
        }
        if (string.IsNullOrEmpty(t) || string.IsNullOrEmpty(v1))
            return false;
        if (!long.TryParse(t, out var ts))
            return false;

        if (toleranceSeconds > 0)
        {
            var age = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - ts;
            if (age > toleranceSeconds || age < -toleranceSeconds)
                return false;
        }

        var want = HmacSha256(secret, t + "." + body);
        var got = DecodeHex(v1);
        if (got is null)
            return false;
        return CryptographicOperations.FixedTimeEquals(want, got);
    }

    /// <summary>Compute the <c>Authio-Signature</c> header value (useful for tests/replay).</summary>
    public static string Sign(string secret, string body, long unixSeconds)
    {
        var t = unixSeconds.ToString();
        return $"t={t},v1={Convert.ToHexString(HmacSha256(secret, t + "." + body)).ToLowerInvariant()}";
    }

    private static byte[] HmacSha256(string secret, string data)
    {
        using var mac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        return mac.ComputeHash(Encoding.UTF8.GetBytes(data));
    }

    private static byte[]? DecodeHex(string s)
    {
        if ((s.Length & 1) != 0)
            return null;
        try
        {
            return Convert.FromHexString(s);
        }
        catch (FormatException)
        {
            return null;
        }
    }
}

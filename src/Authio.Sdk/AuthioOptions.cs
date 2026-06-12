namespace Authio;

/// <summary>
/// Configuration for an <see cref="AuthioClient"/>.
/// Defaults target the production API (<c>https://api.authio.com</c>, the single
/// server declared in the OpenAPI contract). The auth-core surface
/// (<c>/v1/auth/token</c> + JWKS) lives on the same origin by default; override
/// <see cref="AuthCoreUrl"/> for split deployments.
/// </summary>
public sealed class AuthioOptions
{
    public const string DefaultApiUrl = "https://api.authio.com";

    /// <summary>Secret API key (<c>sk_live_…</c> / <c>sk_test_…</c>). Required.</summary>
    public string ApiKey { get; set; } = "";

    /// <summary>Management API base URL.</summary>
    public string ApiUrl { get; set; } = DefaultApiUrl;

    /// <summary>Auth-core base URL (token + JWKS). Defaults to <see cref="ApiUrl"/> when null.</summary>
    public string? AuthCoreUrl { get; set; }

    /// <summary>Required JWT issuer for session verification. Not enforced when null.</summary>
    public string? JwtIssuer { get; set; }

    /// <summary>Required JWT audience for session verification. Not enforced when null.</summary>
    public string? JwtAudience { get; set; }

    /// <summary>Per-request timeout. Defaults to 30s.</summary>
    public TimeSpan RequestTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Max automatic retries on 429/5xx. Defaults to 3 (0 disables).</summary>
    public int MaxRetries { get; set; } = 3;

    /// <summary>Base delay for exponential backoff between retries. Defaults to 250ms.</summary>
    public TimeSpan RetryBaseDelay { get; set; } = TimeSpan.FromMilliseconds(250);

    /// <summary>Optional injected <see cref="HttpClient"/> (e.g. for tests / proxies).</summary>
    public HttpClient? HttpClient { get; set; }

    internal string ResolvedApiUrl => Trim(ApiUrl);
    internal string ResolvedAuthCoreUrl => Trim(string.IsNullOrEmpty(AuthCoreUrl) ? ApiUrl : AuthCoreUrl!);

    private static string Trim(string s) => s.TrimEnd('/');
}

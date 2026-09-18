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

    /// <summary>
    /// Issuer and audience auth-core stamps on every token. These properties
    /// used to default to null, and <see cref="JwtVerifier"/> skips a check
    /// whose expected value is null — so out of the box the SDK verified the
    /// signature and nothing else. Every Authio tenant shares one signing
    /// key, so a signature-only check accepts tokens from the whole platform.
    /// </summary>
    public const string DefaultIssuer = "https://identity.authio.com";

    /// <summary>Audience auth-core stamps on every token.</summary>
    public const string DefaultAudience = "authio";

    /// <summary>Secret API key (<c>sk_live_…</c> / <c>sk_test_…</c>). Required.</summary>
    public string ApiKey { get; set; } = "";

    /// <summary>Management API base URL.</summary>
    public string ApiUrl { get; set; } = DefaultApiUrl;

    /// <summary>Auth-core base URL (token + JWKS). Defaults to <see cref="ApiUrl"/> when null.</summary>
    public string? AuthCoreUrl { get; set; }

    /// <summary>Required JWT issuer for session verification.</summary>
    public string? JwtIssuer { get; set; } = DefaultIssuer;

    /// <summary>Required JWT audience for session verification.</summary>
    public string? JwtAudience { get; set; } = DefaultAudience;

    /// <summary>
    /// Your Authio project id (<c>proj_…</c>). Defaults to the
    /// <c>AUTHIO_PROJECT_ID</c> environment variable.
    ///
    /// Signature, issuer and audience are identical for every Authio tenant,
    /// so <c>project_id</c> is the only claim that says a token was minted
    /// for you rather than in someone else's Authio project. Sign-up is
    /// self-serve, so a valid foreign token is free to obtain. Leave it unset
    /// and the check is skipped, with a one-time warning.
    /// </summary>
    public string? ProjectId { get; set; } =
        string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("AUTHIO_PROJECT_ID"))
            ? null
            : Environment.GetEnvironmentVariable("AUTHIO_PROJECT_ID")!.Trim();

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

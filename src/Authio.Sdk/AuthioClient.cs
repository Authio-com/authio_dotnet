using Authio.Models;

namespace Authio;

/// <summary>
/// The entrypoint for server-side calls into Authio.
///
/// <para>Multi-org-first: a verified <see cref="Session"/> always identifies the
/// user (<c>UserId</c>); the active organization (<c>OrgId</c>) is only set once
/// the user has selected one of their memberships.</para>
///
/// <code>
/// var authio = new AuthioClient(new AuthioOptions { ApiKey = "sk_live_..." });
/// var session = await authio.Sessions.VerifyAsync(accessToken);
/// if (session is not null)
/// {
///     var users = await authio.Users.ListAsync();
/// }
/// </code>
/// </summary>
public sealed class AuthioClient
{
    private const string JwksPath = "/v1/auth/.well-known/jwks.json";
    private const string TokenPath = "/v1/auth/token";

    private readonly AuthioOptions _options;
    private readonly Transport _transport;

    public UsersApi Users { get; }
    public OrganizationsApi Organizations { get; }
    public MembershipsApi Memberships { get; }
    public InvitesApi Invites { get; }
    public WebhooksApi Webhooks { get; }
    public EventsApi Events { get; }
    public PortalApi Portal { get; }
    public SessionsApi Sessions { get; }

    /// <summary>The shared JWT verifier (for verifying widget/M2M tokens directly).</summary>
    public JwtVerifier Verifier { get; }

    public AuthioClient(AuthioOptions options)
    {
        if (string.IsNullOrEmpty(options.ApiKey))
            throw new ArgumentException("Authio: ApiKey is required. Pass it directly or set AUTHIO_SECRET_KEY.", nameof(options));

        _options = options;
        _transport = new Transport(options);
        Verifier = new JwtVerifier(
            options.ResolvedAuthCoreUrl + JwksPath,
            options.JwtIssuer,
            options.JwtAudience,
            options.HttpClient);

        Users = new UsersApi(_transport);
        Organizations = new OrganizationsApi(_transport);
        Memberships = new MembershipsApi(_transport);
        Invites = new InvitesApi(_transport);
        Webhooks = new WebhooksApi(_transport);
        Events = new EventsApi(_transport);
        Portal = new PortalApi(_transport);
        Sessions = new SessionsApi(Verifier);
    }

    /// <summary>Convenience overload: construct from an API key with defaults.</summary>
    public AuthioClient(string apiKey) : this(new AuthioOptions { ApiKey = apiKey })
    {
    }

    public AuthioOptions Options => _options;

    /// <summary>
    /// Exchange OAuth client credentials for a short-lived access token (M2M).
    /// Targets auth-core's <c>POST /v1/auth/token</c> as
    /// <c>application/x-www-form-urlencoded</c> per the OpenAPI contract.
    /// </summary>
    public async Task<TokenResponse> TokenAsync(ClientCredentialsInput input, CancellationToken ct = default)
    {
        var form = new List<KeyValuePair<string, string?>>
        {
            new("grant_type", "client_credentials"),
            new("client_id", input.ClientId),
            new("client_secret", input.ClientSecret),
            new("scope", input.Scope),
        };
        return (await _transport.PostFormAsync<TokenResponse>(TokenPath, form, ct).ConfigureAwait(false))!;
    }
}

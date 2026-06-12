using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using Authio.Models;

namespace Authio;

/// <summary>The <c>Users</c> namespace.</summary>
public sealed class UsersApi
{
    private readonly Transport _t;
    internal UsersApi(Transport t) => _t = t;

    /// <summary>List users in the project (email / limit / cursor filters).</summary>
    public async Task<UserList> ListAsync(ListUsersOptions? opts = null, CancellationToken ct = default)
    {
        var q = new QueryBuilder();
        if (opts is not null)
        {
            q.Add("email", opts.Email);
            q.Add("limit", opts.Limit?.ToString());
            q.Add("cursor", opts.Cursor);
        }
        return (await _t.RequestAsync<UserList>(HttpMethod.Get, "/v1/users" + q, ct: ct).ConfigureAwait(false))!;
    }

    /// <summary>Fetch a single user by id.</summary>
    public async Task<User> GetAsync(string userId, CancellationToken ct = default) =>
        (await _t.RequestAsync<User>(HttpMethod.Get, $"/v1/users/{Esc(userId)}", ct: ct).ConfigureAwait(false))!;

    /// <summary>List every org membership for a user (project-scoped).</summary>
    public async Task<List<MembershipWithOrganization>> ListMembershipsAsync(string userId, CancellationToken ct = default) =>
        (await _t.RequestAsync<List<MembershipWithOrganization>>(HttpMethod.Get, $"/v1/users/{Esc(userId)}/memberships", ct: ct).ConfigureAwait(false))!;

    private static string Esc(string s) => Uri.EscapeDataString(s);
}

/// <summary>The <c>Organizations</c> namespace.</summary>
public sealed class OrganizationsApi
{
    private readonly Transport _t;
    internal OrganizationsApi(Transport t) => _t = t;

    /// <summary>List all organizations in the project.</summary>
    public async Task<List<Organization>> ListAsync(CancellationToken ct = default) =>
        (await _t.RequestAsync<List<Organization>>(HttpMethod.Get, "/v1/organizations", ct: ct).ConfigureAwait(false))!;

    /// <summary>Create an organization.</summary>
    public async Task<Organization> CreateAsync(CreateOrganizationInput input, CancellationToken ct = default) =>
        (await _t.RequestAsync<Organization>(HttpMethod.Post, "/v1/organizations", input, ct).ConfigureAwait(false))!;

    /// <summary>Fetch a single organization by id.</summary>
    public async Task<Organization> GetAsync(string orgId, CancellationToken ct = default) =>
        (await _t.RequestAsync<Organization>(HttpMethod.Get, $"/v1/organizations/{Uri.EscapeDataString(orgId)}", ct: ct).ConfigureAwait(false))!;
}

/// <summary>The <c>Memberships</c> namespace (organization membership management).</summary>
public sealed class MembershipsApi
{
    private readonly Transport _t;
    internal MembershipsApi(Transport t) => _t = t;

    /// <summary>List members of an organization (joined with user records).</summary>
    public async Task<List<MembershipWithUser>> ListForOrganizationAsync(string orgId, CancellationToken ct = default) =>
        (await _t.RequestAsync<List<MembershipWithUser>>(HttpMethod.Get, $"/v1/organizations/{Esc(orgId)}/memberships", ct: ct).ConfigureAwait(false))!;

    /// <summary>Add an existing user to an organization.</summary>
    public async Task<Membership> AddAsync(string orgId, AddMembershipInput input, CancellationToken ct = default) =>
        (await _t.RequestAsync<Membership>(HttpMethod.Post, $"/v1/organizations/{Esc(orgId)}/memberships", input, ct).ConfigureAwait(false))!;

    /// <summary>Update a membership's role and/or status.</summary>
    public async Task<Membership> UpdateAsync(string orgId, string membershipId, UpdateMembershipInput input, CancellationToken ct = default) =>
        (await _t.RequestAsync<Membership>(new HttpMethod("PATCH"), $"/v1/organizations/{Esc(orgId)}/memberships/{Esc(membershipId)}", input, ct).ConfigureAwait(false))!;

    /// <summary>Remove a user's membership in one organization.</summary>
    public async Task RemoveAsync(string orgId, string membershipId, CancellationToken ct = default) =>
        await _t.RequestAsync<Unit>(HttpMethod.Delete, $"/v1/organizations/{Esc(orgId)}/memberships/{Esc(membershipId)}", ct: ct).ConfigureAwait(false);

    private static string Esc(string s) => Uri.EscapeDataString(s);
}

/// <summary>The <c>Invites</c> namespace.</summary>
public sealed class InvitesApi
{
    private readonly Transport _t;
    internal InvitesApi(Transport t) => _t = t;

    /// <summary>Invite a user to an organization by email.</summary>
    public async Task<Invitation> CreateAsync(string orgId, CreateInvitationInput input, CancellationToken ct = default) =>
        (await _t.RequestAsync<Invitation>(HttpMethod.Post, $"/v1/organizations/{Uri.EscapeDataString(orgId)}/invitations", input, ct).ConfigureAwait(false))!;
}

/// <summary>The <c>Portal</c> namespace (Admin Portal link generation).</summary>
public sealed class PortalApi
{
    private readonly Transport _t;
    internal PortalApi(Transport t) => _t = t;

    /// <summary>Mint a one-time, organization-scoped setup link (WorkOS-parity generate_link).</summary>
    public async Task<PortalLink> GenerateLinkAsync(GenerateLinkInput input, CancellationToken ct = default) =>
        (await _t.RequestAsync<PortalLink>(HttpMethod.Post, "/v1/portal/setup-links", input, ct).ConfigureAwait(false))!;
}

/// <summary>The <c>Webhooks</c> namespace. For verifying payloads see <see cref="WebhookSignature"/>.</summary>
public sealed class WebhooksApi
{
    private readonly Transport _t;
    internal WebhooksApi(Transport t) => _t = t;

    /// <summary>List delivery attempts for a webhook endpoint (cursor-paginated).</summary>
    public async Task<WebhookDeliveriesPage> ListDeliveriesAsync(string webhookId, string? cursor = null, CancellationToken ct = default)
    {
        var q = new QueryBuilder();
        q.Add("cursor", cursor);
        return (await _t.RequestAsync<WebhookDeliveriesPage>(HttpMethod.Get, $"/v1/webhooks/{Uri.EscapeDataString(webhookId)}/deliveries" + q, ct: ct).ConfigureAwait(false))!;
    }
}

/// <summary>The <c>Events</c> namespace — cursor-paginated, WorkOS-shaped audit events.</summary>
public sealed class EventsApi
{
    private readonly Transport _t;
    internal EventsApi(Transport t) => _t = t;

    /// <summary>Fetch a single page of events.</summary>
    public async Task<EventList> ListAsync(ListEventsOptions? opts = null, CancellationToken ct = default)
    {
        var q = new QueryBuilder();
        if (opts is not null)
        {
            if (opts.Events is not null)
                foreach (var e in opts.Events) q.Add("events[]", e);
            q.Add("range_start", opts.RangeStart);
            q.Add("range_end", opts.RangeEnd);
            q.Add("limit", opts.Limit?.ToString());
            q.Add("after", opts.After);
        }
        return (await _t.RequestAsync<EventList>(HttpMethod.Get, "/v1/events" + q, ct: ct).ConfigureAwait(false))!;
    }

    /// <summary>
    /// Auto-paginating async stream. Walks <c>after</c> cursors until the API
    /// returns no more rows, yielding each event exactly once.
    /// </summary>
    public async IAsyncEnumerable<Event> IterateAsync(ListEventsOptions? opts = null, [EnumeratorCancellation] CancellationToken ct = default)
    {
        var after = opts?.After;
        var limit = opts?.Limit ?? 100;
        while (true)
        {
            var page = await ListAsync(new ListEventsOptions
            {
                Events = opts?.Events,
                RangeStart = opts?.RangeStart,
                RangeEnd = opts?.RangeEnd,
                Limit = limit,
                After = after,
            }, ct).ConfigureAwait(false);

            foreach (var ev in page.Data)
                yield return ev;

            after = page.ListMetadata?.After;
            if (string.IsNullOrEmpty(after) || page.Data.Count == 0)
                yield break;
        }
    }
}

/// <summary>The <c>Sessions</c> namespace — verify access-token JWTs.</summary>
public sealed class SessionsApi
{
    private static readonly HashSet<string> Reserved = new()
    {
        "iss", "sub", "aud", "exp", "iat", "jti", "nbf", "scope", "scopes", "sid",
        "act_org", "act_role", "client_id", "token_type", "project_id", "kind",
        "is_impersonation", "impersonator_user_id", "impersonator_email", "imp_grant_id",
    };

    private readonly JwtVerifier _verifier;
    internal SessionsApi(JwtVerifier verifier) => _verifier = verifier;

    /// <summary>Verify an access token; returns null when invalid or expired.</summary>
    public async Task<Session?> VerifyAsync(string? accessToken, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(accessToken))
            return null;
        try
        {
            return await VerifyOrThrowAsync(accessToken, ct).ConfigureAwait(false);
        }
        catch (AuthioException)
        {
            return null;
        }
    }

    /// <summary>Like <see cref="VerifyAsync"/>, but throws <see cref="AuthioException"/> on failure.</summary>
    public async Task<Session> VerifyOrThrowAsync(string accessToken, CancellationToken ct = default)
    {
        var claims = await _verifier.VerifyAsync(accessToken, ct).ConfigureAwait(false);

        var merged = new Dictionary<string, JsonElement>();
        foreach (var prop in claims.EnumerateObject())
        {
            if (!Reserved.Contains(prop.Name))
                merged[prop.Name] = prop.Value.Clone();
        }

        var expiresAt = DateTimeOffset.UtcNow.ToString("o");
        if (claims.TryGetProperty("exp", out var exp) && exp.ValueKind == JsonValueKind.Number)
            expiresAt = DateTimeOffset.FromUnixTimeSeconds(exp.GetInt64()).ToString("o");

        var actOrg = Str(claims, "act_org");
        var actRole = Str(claims, "act_role");
        var impersonation = claims.TryGetProperty("is_impersonation", out var imp)
                            && imp.ValueKind == JsonValueKind.True;

        return new Session
        {
            SessionId = Str(claims, "sid") ?? "",
            UserId = Str(claims, "sub") ?? "",
            OrgId = string.IsNullOrEmpty(actOrg) ? null : actOrg,
            Role = string.IsNullOrEmpty(actRole) ? null : actRole,
            ExpiresAt = expiresAt,
            Claims = merged,
            Impersonation = impersonation,
            ImpersonatorEmail = impersonation ? Str(claims, "impersonator_email") : null,
        };
    }

    private static string? Str(JsonElement obj, string name) =>
        obj.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
}

/// <summary>Tiny query-string builder with URL escaping.</summary>
internal sealed class QueryBuilder
{
    private readonly StringBuilder _sb = new();

    public void Add(string key, string? value)
    {
        if (value is null) return;
        _sb.Append(_sb.Length == 0 ? '?' : '&');
        _sb.Append(Uri.EscapeDataString(key)).Append('=').Append(Uri.EscapeDataString(value));
    }

    public override string ToString() => _sb.ToString();
}

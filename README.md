# Authio.Sdk

> Part of **[Authio Lobby](https://authio.com/products/lobby)** —
> Authio's drop-in passwordless authentication. Learn more at
> https://authio.com/products/lobby.

Official server-side **.NET** SDK for Authio. Use it from any .NET 8+ backend
(ASP.NET Core, minimal APIs, worker services, ...) to verify session JWTs,
manage users, organizations, memberships, invitations, read the events feed,
generate Admin Portal links, mint M2M tokens, and verify inbound webhook
signatures.

Hand-written and contract-driven: every type and route mirrors the Authio
OpenAPI source of truth in
[`authio_proto`](https://github.com/Authio-com/authio_proto). No generated
client, no heavyweight framework — just `HttpClient`, `System.Text.Json`, and
BouncyCastle for the EdDSA (Ed25519) signature primitive.

## Install

.NET 8+ required.

```bash
dotnet add package Authio.Sdk
```

## Quick start

Verify a session JWT, list users, and generate a portal link:

```csharp
using Authio;
using Authio.Models;

var authio = new AuthioClient(Environment.GetEnvironmentVariable("AUTHIO_SECRET_KEY")!);

// 1. Verify a session access token (EdDSA JWT, verified against the JWKS).
//    Returns null when the token is invalid or expired.
Session? session = await authio.Sessions.VerifyAsync(accessToken);
if (session is null)
{
    // 401 Unauthorized
    return;
}
// session.UserId is always set; session.OrgId only once the user picked an org.
Console.WriteLine($"user={session.UserId} org={session.OrgId}");

// 2. List users in the project.
UserList users = await authio.Users.ListAsync();
foreach (var u in users.Data)
    Console.WriteLine(u.Email);

// 3. Mint a one-time Admin Portal setup link and redirect your IT admin to it.
PortalLink link = await authio.Portal.GenerateLinkAsync(new GenerateLinkInput
{
    OrganizationId = "org_123",
    Intent = PortalIntent.Sso,
    SuccessUrl = "https://app.example.com/settings/sso?done=1",
});
// return Results.Redirect(link.Link);
```

### Configuration

```csharp
var authio = new AuthioClient(new AuthioOptions
{
    ApiKey = "sk_live_...",
    ApiUrl = "https://api.authio.com",       // management API base (default)
    AuthCoreUrl = "https://api.authio.com",  // token + JWKS origin (defaults to ApiUrl)
    JwtIssuer = "https://api.authio.com",     // optional: enforce iss on verify
    JwtAudience = "authio",                    // optional: enforce aud on verify
    RequestTimeout = TimeSpan.FromSeconds(30),
    MaxRetries = 3,                            // retries 429/5xx with exp. backoff
});
```

The `Authorization: Bearer <apiKey>` and `X-Authio-SDK: dotnet/<version>` headers
are sent on every management request. Requests automatically retry on `429`
and `5xx` with exponential backoff + jitter.

### Auto-paginating events iterator

The Events API is WorkOS-shaped (`{ data, list_metadata.after }`). Stream the
whole feed with no gaps or duplicates — cursoring is handled for you:

```csharp
await foreach (var ev in authio.Events.IterateAsync(new ListEventsOptions
{
    Events = new() { "user.created" },
}))
{
    Console.WriteLine($"{ev.Id} {ev.Action} {ev.CreatedAt}");
}
```

### M2M (client credentials) token

```csharp
TokenResponse t = await authio.TokenAsync(new ClientCredentialsInput
{
    ClientId = "m2m_...",
    ClientSecret = "secret_...",
    Scope = "users:read",
});
// t.AccessToken is a Bearer JWT; verify it with authio.Verifier.
```

### Verify an inbound webhook

Authio signs outbound webhooks with `Authio-Signature: t=<unix>,v1=<hmac-sha256>`
over `<t>.<raw-body>` using the endpoint's `whsec_…` secret. Verify against the
**raw** request body (5-minute replay tolerance by default):

```csharp
using Authio;

bool ok = WebhookSignature.Verify(
    Environment.GetEnvironmentVariable("AUTHIO_WEBHOOK_SECRET")!,  // whsec_...
    rawRequestBody,
    request.Headers["Authio-Signature"]!);
if (!ok)
{
    // 400 Bad Request — reject
}
```

### Typed errors

Every non-2xx API response throws `AuthioException` carrying the wire shape
(`Code`, `Message`, `RequestId`) plus the HTTP `Status`. Transport/network
failures surface as `AuthioException` with `Status == 0`.

```csharp
try
{
    await authio.Organizations.GetAsync("org_missing");
}
catch (AuthioException e)
{
    Console.WriteLine($"{e.Code} / {e.Status} / {e.RequestId}");
}
```

## Namespaces

| Namespace | Method | Wire endpoint |
|---|---|---|
| `Sessions` | `VerifyAsync(token)` / `VerifyOrThrowAsync(token)` | JWKS + EdDSA verify |
| `Users` | `ListAsync(opts)` | `GET /v1/users` |
| `Users` | `GetAsync(id)` | `GET /v1/users/{id}` |
| `Users` | `ListMembershipsAsync(id)` | `GET /v1/users/{id}/memberships` |
| `Organizations` | `ListAsync()` | `GET /v1/organizations` |
| `Organizations` | `CreateAsync(input)` | `POST /v1/organizations` |
| `Organizations` | `GetAsync(id)` | `GET /v1/organizations/{id}` |
| `Memberships` | `ListForOrganizationAsync(orgId)` | `GET /v1/organizations/{id}/memberships` |
| `Memberships` | `AddAsync(orgId, input)` | `POST /v1/organizations/{id}/memberships` |
| `Memberships` | `UpdateAsync(orgId, memId, input)` | `PATCH /v1/organizations/{id}/memberships/{memId}` |
| `Memberships` | `RemoveAsync(orgId, memId)` | `DELETE /v1/organizations/{id}/memberships/{memId}` |
| `Invites` | `CreateAsync(orgId, input)` | `POST /v1/organizations/{id}/invitations` |
| `Events` | `ListAsync(opts)` / `IterateAsync(opts)` | `GET /v1/events` |
| `Portal` | `GenerateLinkAsync(input)` | `POST /v1/portal/setup-links` |
| `Webhooks` | `ListDeliveriesAsync(id, cursor)` | `GET /v1/webhooks/{id}/deliveries` |
| `TokenAsync(input)` | M2M client credentials | `POST /v1/auth/token` |
| `WebhookSignature` | `Verify(...)` / `Sign(...)` | HMAC-SHA256 helper |

### Not yet covered

SSO connection and SCIM directory reads are exposed in the OpenAPI spec only
behind the **session/operator** bearer scheme (not the `sk_` API-key scheme),
so they are intentionally omitted from this server SDK. Per-user create/update/
delete is likewise not part of the public `sk_` surface. These will be added if
and when API-key-scoped routes ship.

## Develop

```bash
dotnet build
dotnet test
```

## License

MIT

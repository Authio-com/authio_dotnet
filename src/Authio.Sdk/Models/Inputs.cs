namespace Authio.Models;

/// <summary>
/// Filters for <c>Users.ListAsync</c>. Per the OpenAPI contract the supported
/// params are <c>email</c>, <c>limit</c> (max 200, default 50) and <c>cursor</c>.
/// </summary>
public sealed class ListUsersOptions
{
    public string? Email { get; set; }
    public int? Limit { get; set; }
    public string? Cursor { get; set; }
}

/// <summary>Filters for <c>Events.ListAsync</c> / <c>Events.IterateAsync</c>.</summary>
public sealed class ListEventsOptions
{
    public List<string>? Events { get; set; }
    public string? RangeStart { get; set; }
    public string? RangeEnd { get; set; }
    public int? Limit { get; set; }
    public string? After { get; set; }
}

/// <summary>Body for <c>Organizations.CreateAsync</c>.</summary>
public sealed class CreateOrganizationInput
{
    public string Name { get; set; } = "";
    public string? Slug { get; set; }
    public string? Domain { get; set; }
}

/// <summary>Body for <c>Memberships.AddAsync</c>.</summary>
public sealed class AddMembershipInput
{
    public string UserId { get; set; } = "";
    public string Role { get; set; } = "";
}

/// <summary>Body for <c>Memberships.UpdateAsync</c> (role and/or status).</summary>
public sealed class UpdateMembershipInput
{
    public string? Role { get; set; }
    public string? Status { get; set; }
}

/// <summary>Body for <c>Invites.CreateAsync</c>.</summary>
public sealed class CreateInvitationInput
{
    public string Email { get; set; } = "";
    public string? Role { get; set; }
    public string? RedirectUri { get; set; }
}

/// <summary>What the IT admin will configure via the Admin Portal.</summary>
public enum PortalIntent
{
    Sso,
    Scim,
    Domain,
}

/// <summary>Body for <c>Portal.GenerateLinkAsync</c> (WorkOS-parity generate_link).</summary>
public sealed class GenerateLinkInput
{
    public string OrganizationId { get; set; } = "";
    public PortalIntent Intent { get; set; } = PortalIntent.Sso;
    public string? ReturnUrl { get; set; }
    public string? SuccessUrl { get; set; }
    public List<string>? ItContactEmails { get; set; }
    public int? ExpiresInMinutes { get; set; }
}

/// <summary>
/// Input for the M2M client_credentials token exchange. Sent to auth-core's
/// <c>POST /v1/auth/token</c> as <c>application/x-www-form-urlencoded</c>.
/// </summary>
public sealed class ClientCredentialsInput
{
    public string ClientId { get; set; } = "";
    public string ClientSecret { get; set; } = "";
    public string? Scope { get; set; }
}

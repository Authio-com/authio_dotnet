using System.Text.Json;

namespace Authio.Models;

/// <summary>A user identity. Mirrors the wire <c>User</c> schema.</summary>
public sealed class User
{
    public string Id { get; set; } = "";
    public string ProjectId { get; set; } = "";
    public string Email { get; set; } = "";
    public bool EmailVerified { get; set; }
    public string? Name { get; set; }
    public string? AvatarUrl { get; set; }
    public string? DefaultOrganizationId { get; set; }
    public string? CreatedAt { get; set; }
    public string? UpdatedAt { get; set; }
}

/// <summary>A verified email domain routed to an organization for SSO/JIT.</summary>
public sealed class OrganizationDomain
{
    public string Domain { get; set; } = "";
    public bool Verified { get; set; }
    public string? AutoJoinRole { get; set; }
}

/// <summary>An organization. Mirrors the wire <c>Organization</c> schema.</summary>
public sealed class Organization
{
    public string Id { get; set; } = "";
    public string ProjectId { get; set; } = "";
    public string Name { get; set; } = "";
    public string Slug { get; set; } = "";
    public List<OrganizationDomain>? Domains { get; set; }
    public Dictionary<string, JsonElement>? Branding { get; set; }
    public string? CreatedAt { get; set; }
}

/// <summary>Ties a <see cref="User"/> to an <see cref="Organization"/> with a role.</summary>
public class Membership
{
    public string Id { get; set; } = "";
    public string ProjectId { get; set; } = "";
    public string UserId { get; set; } = "";
    public string OrganizationId { get; set; } = "";
    public string Role { get; set; } = "";

    /// <summary>Lifecycle state: <c>invited</c> | <c>active</c> | <c>suspended</c> | <c>deactivated</c>.</summary>
    public string Status { get; set; } = "";

    public string? JoinedAt { get; set; }
    public string? InvitedBy { get; set; }
    public string? LastActiveAt { get; set; }
    public string? PreferredLoginMethod { get; set; }
}

/// <summary>A membership row joined with its <see cref="Organization"/>.</summary>
public sealed class MembershipWithOrganization : Membership
{
    public Organization? Organization { get; set; }
}

/// <summary>A membership row joined with its <see cref="User"/>.</summary>
public sealed class MembershipWithUser : Membership
{
    public User? User { get; set; }
}

/// <summary>
/// A page of users. Uses <c>next_cursor</c> pagination (distinct from the
/// Events API's WorkOS-shaped <c>list_metadata.after</c>).
/// </summary>
public sealed class UserList
{
    public List<User> Data { get; set; } = new();
    public string? NextCursor { get; set; }
}

/// <summary>The payload of an audit <see cref="Event"/>.</summary>
public sealed class EventData
{
    public string? OrganizationId { get; set; }
    public string? UserId { get; set; }
    public string? ActorType { get; set; }
    public string? ActorId { get; set; }
    public string? TargetType { get; set; }
    public string? TargetId { get; set; }
    public Dictionary<string, JsonElement>? Metadata { get; set; }
}

/// <summary>A single audit event. Mirrors the wire <c>Event</c> schema.</summary>
public sealed class Event
{
    public string Id { get; set; } = "";

    /// <summary>The event action, e.g. <c>user.created</c>.</summary>
    [System.Text.Json.Serialization.JsonPropertyName("event")]
    public string Action { get; set; } = "";

    public string? CreatedAt { get; set; }
    public EventData? Data { get; set; }
}

/// <summary>Cursor wrapper for the Events API.</summary>
public sealed class ListMetadata
{
    /// <summary>Cursor for the next page, or <c>null</c> when fully drained.</summary>
    public string? After { get; set; }
}

/// <summary>A page of events, WorkOS-shaped: <c>{ data, list_metadata.after }</c>.</summary>
public sealed class EventList
{
    public List<Event> Data { get; set; } = new();
    public ListMetadata ListMetadata { get; set; } = new();
}

/// <summary>An organization invitation. Mirrors the wire <c>Invitation</c> schema.</summary>
public sealed class Invitation
{
    public string Id { get; set; } = "";
    public string OrganizationId { get; set; } = "";
    public string Email { get; set; } = "";
    public string? Role { get; set; }
    public string? Status { get; set; }
    public string? ExpiresAt { get; set; }
    public string? CreatedAt { get; set; }
}

/// <summary>OAuth 2.0 token endpoint response (client_credentials grant).</summary>
public sealed class TokenResponse
{
    public string AccessToken { get; set; } = "";
    public string TokenType { get; set; } = "";
    public long ExpiresIn { get; set; }
    public string? Scope { get; set; }
}

/// <summary>Result of <c>Portal.GenerateLinkAsync</c> — a ready-to-redirect link.</summary>
public sealed class PortalLink
{
    public string Link { get; set; } = "";
    public string? ExpiresAt { get; set; }
}

/// <summary>A single webhook delivery attempt record.</summary>
public sealed class WebhookDelivery
{
    public string Id { get; set; } = "";
    public string WebhookId { get; set; } = "";
    public string? EventId { get; set; }
    public string EventType { get; set; } = "";
    public string Status { get; set; } = "";
    public int AttemptCount { get; set; }
    public string? LastAttemptAt { get; set; }
    public int? ResponseStatus { get; set; }
    public bool IsTest { get; set; }
    public string? CreatedAt { get; set; }
}

/// <summary>A status rollup for a webhook endpoint's deliveries.</summary>
public sealed class WebhookDeliverySummary
{
    public int Succeeded { get; set; }
    public int Failed { get; set; }
    public int Pending { get; set; }
    public int Dead { get; set; }
}

/// <summary>A page of webhook deliveries plus a status rollup.</summary>
public sealed class WebhookDeliveriesPage
{
    public List<WebhookDelivery> Data { get; set; } = new();
    public string? NextCursor { get; set; }
    public WebhookDeliverySummary? Summary { get; set; }
}

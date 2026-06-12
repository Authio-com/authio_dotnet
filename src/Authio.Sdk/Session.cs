using System.Text.Json;

namespace Authio;

/// <summary>
/// A verified Authio session, decoded from an access-token JWT.
/// The session always identifies the user (<see cref="UserId"/>); the active
/// organization (<see cref="OrgId"/>) is only set after the user has selected
/// one of their memberships.
/// </summary>
public sealed class Session
{
    public string SessionId { get; init; } = "";
    public string UserId { get; init; } = "";
    public string? OrgId { get; init; }
    public string? Role { get; init; }
    public string ExpiresAt { get; init; } = "";

    /// <summary>Custom (T2.4) claims merged into the token, minus reserved claim names.</summary>
    public IReadOnlyDictionary<string, JsonElement> Claims { get; init; } =
        new Dictionary<string, JsonElement>();

    /// <summary>True when the session was minted by an operator impersonating the user.</summary>
    public bool Impersonation { get; init; }

    /// <summary>Admin email when <see cref="Impersonation"/> is true; otherwise null.</summary>
    public string? ImpersonatorEmail { get; init; }
}

namespace Authio;

/// <summary>
/// A typed Authio API error. Mirrors the wire <c>Error</c> schema
/// (<c>{ code, message, request_id }</c>) plus the HTTP status code.
/// Network/transport failures surface with <see cref="Status"/> == 0 and
/// code <c>network_error</c>.
/// </summary>
public sealed class AuthioException : Exception
{
    /// <summary>Stable machine-readable error code, e.g. <c>membership_not_found</c>.</summary>
    public string Code { get; }

    /// <summary>HTTP status code. <c>0</c> for transport/network failures.</summary>
    public int Status { get; }

    /// <summary>Server-provided correlation id, when present.</summary>
    public string? RequestId { get; }

    public AuthioException(string code, string message, int status, string? requestId = null, Exception? inner = null)
        : base(message, inner)
    {
        Code = code;
        Status = status;
        RequestId = requestId;
    }

    public override string ToString() =>
        $"AuthioException{{code={Code}, status={Status}, requestId={RequestId}, message={Message}}}";
}

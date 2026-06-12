using System.Text.Json;
using System.Text.Json.Serialization;

namespace Authio;

/// <summary>
/// Shared System.Text.Json options mirroring the Authio wire contract:
/// snake_case keys, case-insensitive reads, and null omission on writes.
/// </summary>
internal static class Json
{
    public static readonly JsonSerializerOptions Options = Build();

    private static JsonSerializerOptions Build()
    {
        var o = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
            DictionaryKeyPolicy = JsonNamingPolicy.SnakeCaseLower,
            PropertyNameCaseInsensitive = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        };
        o.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower));
        return o;
    }
}

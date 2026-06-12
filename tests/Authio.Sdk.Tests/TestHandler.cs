using System.Collections.Concurrent;

namespace Authio.Sdk.Tests;

/// <summary>A recorded inbound request.</summary>
public sealed class RecordedRequest
{
    public required string Method { get; init; }
    public required string Path { get; init; }
    public required string? Query { get; init; }
    public required IReadOnlyDictionary<string, string> Headers { get; init; }
    public required string? ContentType { get; init; }
    public required string Body { get; init; }

    public string? Header(string name) =>
        Headers.TryGetValue(name.ToLowerInvariant(), out var v) ? v : null;
}

/// <summary>A canned response.</summary>
public sealed record Canned(int Status, string Body);

/// <summary>
/// A fake <see cref="HttpMessageHandler"/> that records requests and returns
/// canned responses — the hand-rolled "mock server" for transport tests.
/// </summary>
public sealed class TestHandler : HttpMessageHandler
{
    public readonly List<RecordedRequest> Requests = new();
    private readonly Func<RecordedRequest, Canned> _handler;

    public TestHandler(Func<RecordedRequest, Canned> handler) => _handler = handler;

    public static TestHandler Sequence(params Canned[] responses)
    {
        var list = responses.ToList();
        var i = 0;
        return new TestHandler(_ =>
        {
            var r = list[Math.Min(i, list.Count - 1)];
            i++;
            return r;
        });
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(cancellationToken);
        var headers = new ConcurrentDictionary<string, string>();
        foreach (var h in request.Headers)
            headers[h.Key.ToLowerInvariant()] = string.Join(",", h.Value);
        string? contentType = null;
        if (request.Content is not null)
        {
            foreach (var h in request.Content.Headers)
            {
                headers[h.Key.ToLowerInvariant()] = string.Join(",", h.Value);
                if (h.Key.Equals("Content-Type", StringComparison.OrdinalIgnoreCase))
                    contentType = string.Join(",", h.Value);
            }
        }

        var rec = new RecordedRequest
        {
            Method = request.Method.Method,
            Path = request.RequestUri!.AbsolutePath,
            Query = string.IsNullOrEmpty(request.RequestUri.Query) ? null : request.RequestUri.Query.TrimStart('?'),
            Headers = headers,
            ContentType = contentType,
            Body = body,
        };
        lock (Requests) { Requests.Add(rec); }

        var canned = _handler(rec);
        return new HttpResponseMessage((System.Net.HttpStatusCode)canned.Status)
        {
            Content = new StringContent(canned.Body, System.Text.Encoding.UTF8, "application/json"),
        };
    }
}

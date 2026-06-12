using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace Authio;

/// <summary>
/// Internal HTTP plumbing: bearer auth, the <c>X-Authio-SDK</c> header on every
/// request, typed error mapping, and automatic retry-with-backoff on 429/5xx.
/// </summary>
internal sealed class Transport
{
    private readonly AuthioOptions _opts;
    private readonly HttpClient _http;

    public Transport(AuthioOptions opts)
    {
        _opts = opts;
        _http = opts.HttpClient ?? new HttpClient();
        _http.Timeout = opts.RequestTimeout;
    }

    /// <summary>Authenticated JSON request against the management API.</summary>
    public async Task<T?> RequestAsync<T>(HttpMethod method, string path, object? body = null, CancellationToken ct = default)
    {
        HttpRequestMessage NewRequest()
        {
            var req = new HttpRequestMessage(method, _opts.ResolvedApiUrl + path);
            AddBaseHeaders(req);
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _opts.ApiKey);
            if (body is not null)
            {
                var json = JsonSerializer.Serialize(body, Json.Options);
                req.Content = new StringContent(json, Encoding.UTF8, "application/json");
            }
            return req;
        }

        return await SendAsync<T>(NewRequest, ct).ConfigureAwait(false);
    }

    /// <summary>Unauthenticated form-urlencoded POST against auth-core (token endpoint).</summary>
    public async Task<T?> PostFormAsync<T>(string path, IEnumerable<KeyValuePair<string, string?>> form, CancellationToken ct = default)
    {
        var pairs = form
            .Where(kv => kv.Value is not null)
            .Select(kv => new KeyValuePair<string, string>(kv.Key, kv.Value!))
            .ToList();

        HttpRequestMessage NewRequest()
        {
            var req = new HttpRequestMessage(HttpMethod.Post, _opts.ResolvedAuthCoreUrl + path);
            AddBaseHeaders(req);
            req.Content = new FormUrlEncodedContent(pairs);
            return req;
        }

        return await SendAsync<T>(NewRequest, ct).ConfigureAwait(false);
    }

    private void AddBaseHeaders(HttpRequestMessage req)
    {
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        req.Headers.UserAgent.ParseAdd(SdkVersion.UserAgent);
        req.Headers.Add("X-Authio-SDK", SdkVersion.Header);
    }

    private async Task<T?> SendAsync<T>(Func<HttpRequestMessage> factory, CancellationToken ct)
    {
        var attempt = 0;
        while (true)
        {
            HttpResponseMessage res;
            using var req = factory();
            try
            {
                res = await _http.SendAsync(req, ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not AuthioException && ex is not OperationCanceledException)
            {
                if (attempt < _opts.MaxRetries)
                {
                    await BackoffAsync(attempt++, ct).ConfigureAwait(false);
                    continue;
                }
                throw new AuthioException("network_error", ex.Message, 0, inner: ex);
            }

            using (res)
            {
                var status = (int)res.StatusCode;
                if (IsRetryable(status) && attempt < _opts.MaxRetries)
                {
                    await BackoffAsync(attempt++, ct).ConfigureAwait(false);
                    continue;
                }

                var bytes = await res.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
                if (status >= 400)
                {
                    throw ToError(status, bytes);
                }
                return Deserialize<T>(bytes);
            }
        }
    }

    private static bool IsRetryable(int status) => status == 429 || (status >= 500 && status <= 599);

    private async Task BackoffAsync(int attempt, CancellationToken ct)
    {
        var baseMs = _opts.RetryBaseDelay.TotalMilliseconds;
        var delay = baseMs * Math.Pow(2, attempt);
        var jitter = Random.Shared.NextDouble() * baseMs;
        await Task.Delay(TimeSpan.FromMilliseconds(delay + jitter), ct).ConfigureAwait(false);
    }

    private static AuthioException ToError(int status, byte[] body)
    {
        var code = "request_failed";
        var message = $"Request failed with status {status}";
        string? requestId = null;
        try
        {
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;
            if (root.TryGetProperty("code", out var c) && c.ValueKind == JsonValueKind.String)
                code = c.GetString()!;
            else if (root.TryGetProperty("error", out var e) && e.ValueKind == JsonValueKind.String)
                code = e.GetString()!; // RFC 6749 §5.2 envelope (token endpoint).

            if (root.TryGetProperty("message", out var m) && m.ValueKind == JsonValueKind.String)
                message = m.GetString()!;
            else if (root.TryGetProperty("error_description", out var ed) && ed.ValueKind == JsonValueKind.String)
                message = ed.GetString()!;

            if (root.TryGetProperty("request_id", out var rid) && rid.ValueKind == JsonValueKind.String)
                requestId = rid.GetString();
        }
        catch
        {
            // Non-JSON body — keep the generic message.
        }
        return new AuthioException(code, message, status, requestId);
    }

    private static T? Deserialize<T>(byte[] body)
    {
        if (typeof(T) == typeof(Unit) || body.Length == 0)
            return default;
        try
        {
            return JsonSerializer.Deserialize<T>(body, Json.Options);
        }
        catch (Exception ex)
        {
            throw new AuthioException("deserialization_error", ex.Message, 0, inner: ex);
        }
    }
}

/// <summary>Marker for void responses (HTTP 204 / no body).</summary>
public readonly struct Unit
{
}

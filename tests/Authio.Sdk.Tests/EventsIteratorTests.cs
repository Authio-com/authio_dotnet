using Authio;
using Authio.Models;
using Xunit;

namespace Authio.Sdk.Tests;

public class EventsIteratorTests
{
    private static AuthioClient Client(TestHandler h) =>
        new(new AuthioOptions
        {
            ApiKey = "sk_test",
            ApiUrl = "https://api.test",
            AuthCoreUrl = "https://api.test",
            HttpClient = new HttpClient(h),
        });

    private static string Page(string? after, params string[] ids)
    {
        var rows = string.Join(",", ids.Select(id =>
            $"{{\"id\":\"{id}\",\"event\":\"user.created\",\"created_at\":\"2026-06-11T00:00:00Z\",\"data\":{{\"actor_type\":\"user\"}}}}"));
        var afterJson = after is null ? "null" : $"\"{after}\"";
        return $"{{\"data\":[{rows}],\"list_metadata\":{{\"after\":{afterJson}}}}}";
    }

    [Fact]
    public async Task ListSerializesQueryAndMapsListMetadata()
    {
        var h = TestHandler.Sequence(new Canned(200, Page("cur1", "evt_1")));
        var a = Client(h);
        var res = await a.Events.ListAsync(new ListEventsOptions
        {
            Events = new List<string> { "user.created", "session.created" },
            RangeStart = "2026-06-01T00:00:00Z",
            Limit = 50,
            After = "abc",
        });
        Assert.Single(res.Data);
        Assert.Equal("evt_1", res.Data[0].Id);
        Assert.Equal("user.created", res.Data[0].Action);
        Assert.Equal("cur1", res.ListMetadata.After);
        var q = h.Requests[0].Query!;
        Assert.Contains("events%5B%5D=user.created", q);
        Assert.Contains("events%5B%5D=session.created", q);
        Assert.Contains("range_start=", q);
        Assert.Contains("limit=50", q);
        Assert.Contains("after=abc", q);
    }

    [Fact]
    public async Task IterateWalksEveryPageOnceUntilAfterNull()
    {
        var h = TestHandler.Sequence(
            new Canned(200, Page("c1", "evt_1", "evt_2")),
            new Canned(200, Page("c2", "evt_3", "evt_4")),
            new Canned(200, Page(null, "evt_5")));
        var a = Client(h);

        var seen = new List<string>();
        await foreach (var e in a.Events.IterateAsync(new ListEventsOptions { Events = new() { "user.created" } }))
            seen.Add(e.Id);

        Assert.Equal(new[] { "evt_1", "evt_2", "evt_3", "evt_4", "evt_5" }, seen);
        Assert.Equal(5, seen.Distinct().Count());
        Assert.DoesNotContain("after=", h.Requests[0].Query ?? "");
        Assert.Contains("after=c1", h.Requests[1].Query);
        Assert.Contains("after=c2", h.Requests[2].Query);
    }

    [Fact]
    public async Task IterateStopsCleanlyOnEmptyFirstPage()
    {
        var h = TestHandler.Sequence(new Canned(200, Page(null)));
        var a = Client(h);
        var count = 0;
        await foreach (var _ in a.Events.IterateAsync())
            count++;
        Assert.Equal(0, count);
        Assert.Single(h.Requests);
    }
}

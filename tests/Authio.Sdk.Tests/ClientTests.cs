using Authio;
using Authio.Models;
using Xunit;

namespace Authio.Sdk.Tests;

public class ClientTests
{
    private static AuthioClient Client(TestHandler handler) =>
        new(new AuthioOptions
        {
            ApiKey = "sk_test_abc",
            ApiUrl = "https://api.test",
            AuthCoreUrl = "https://api.test",
            MaxRetries = 2,
            RetryBaseDelay = TimeSpan.FromMilliseconds(1),
            HttpClient = new HttpClient(handler),
        });

    [Fact]
    public void RequiresApiKey()
    {
        Assert.Throws<ArgumentException>(() => new AuthioClient(new AuthioOptions { ApiKey = "" }));
        Assert.Throws<ArgumentException>(() => new AuthioClient(""));
    }

    [Fact]
    public async Task SendsAuthAndSdkHeaders()
    {
        var h = TestHandler.Sequence(new Canned(200, "{\"data\":[],\"next_cursor\":null}"));
        var a = Client(h);
        await a.Users.ListAsync();
        var r = h.Requests[0];
        Assert.Equal("Bearer sk_test_abc", r.Header("Authorization"));
        Assert.Equal("dotnet/" + SdkVersion.Version, r.Header("X-Authio-SDK"));
        Assert.StartsWith("authio-dotnet/", r.Header("User-Agent"));
    }

    [Fact]
    public async Task UsersListSerializesQueryAndParses()
    {
        var h = TestHandler.Sequence(new Canned(200,
            "{\"data\":[{\"id\":\"user_1\",\"project_id\":\"p\",\"email\":\"a@b.com\",\"email_verified\":true}],\"next_cursor\":\"cur2\"}"));
        var a = Client(h);
        var res = await a.Users.ListAsync(new ListUsersOptions { Email = "a@b.com", Limit = 50, Cursor = "cur1" });
        Assert.Single(res.Data);
        Assert.Equal("user_1", res.Data[0].Id);
        Assert.True(res.Data[0].EmailVerified);
        Assert.Equal("cur2", res.NextCursor);
        var r = h.Requests[0];
        Assert.Equal("/v1/users", r.Path);
        Assert.Contains("email=a%40b.com", r.Query);
        Assert.Contains("limit=50", r.Query);
        Assert.Contains("cursor=cur1", r.Query);
    }

    [Fact]
    public async Task MapsTypedError()
    {
        var h = TestHandler.Sequence(new Canned(404,
            "{\"code\":\"organization_not_found\",\"message\":\"no such org\",\"request_id\":\"req_42\"}"));
        var a = Client(h);
        var err = await Assert.ThrowsAsync<AuthioException>(() => a.Organizations.GetAsync("org_x"));
        Assert.Equal("organization_not_found", err.Code);
        Assert.Equal(404, err.Status);
        Assert.Equal("req_42", err.RequestId);
        Assert.Equal("no such org", err.Message);
    }

    [Fact]
    public async Task RetriesOn429ThenSucceeds()
    {
        var calls = 0;
        var h = new TestHandler(_ =>
        {
            calls++;
            if (calls < 3)
                return new Canned(429, "{\"code\":\"rate_limit_exceeded\"}");
            return new Canned(200,
                "[{\"id\":\"org_1\",\"project_id\":\"p\",\"name\":\"Acme\",\"slug\":\"acme\",\"created_at\":\"2026-01-01T00:00:00Z\"}]");
        });
        var a = Client(h);
        var orgs = await a.Organizations.ListAsync();
        Assert.Single(orgs);
        Assert.Equal("Acme", orgs[0].Name);
        Assert.Equal(3, calls);
    }

    [Fact]
    public async Task RetriesExhaustedThrows()
    {
        var h = TestHandler.Sequence(new Canned(503, "{\"code\":\"unavailable\"}"));
        var a = Client(h);
        var err = await Assert.ThrowsAsync<AuthioException>(() => a.Organizations.ListAsync());
        Assert.Equal(503, err.Status);
        Assert.Equal(3, h.Requests.Count); // 1 initial + 2 retries
    }

    [Fact]
    public async Task CreateOrganizationSendsJsonBody()
    {
        var h = TestHandler.Sequence(new Canned(201,
            "{\"id\":\"org_9\",\"project_id\":\"p\",\"name\":\"Acme\",\"slug\":\"acme\",\"created_at\":\"2026-01-01T00:00:00Z\"}"));
        var a = Client(h);
        var org = await a.Organizations.CreateAsync(new CreateOrganizationInput { Name = "Acme", Slug = "acme" });
        Assert.Equal("org_9", org.Id);
        var r = h.Requests[0];
        Assert.Equal("POST", r.Method);
        Assert.StartsWith("application/json", r.ContentType);
        Assert.Contains("\"name\":\"Acme\"", r.Body);
        Assert.Contains("\"slug\":\"acme\"", r.Body);
    }

    [Fact]
    public async Task TokenPostsFormUrlEncoded()
    {
        var h = TestHandler.Sequence(new Canned(200,
            "{\"access_token\":\"jwt.value\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"scope\":\"users:read\"}"));
        var a = Client(h);
        var res = await a.TokenAsync(new ClientCredentialsInput { ClientId = "m2m_abc", ClientSecret = "secret_xyz", Scope = "users:read" });
        Assert.Equal("jwt.value", res.AccessToken);
        Assert.Equal("Bearer", res.TokenType);
        Assert.Equal(3600, res.ExpiresIn);
        var r = h.Requests[0];
        Assert.Equal("/v1/auth/token", r.Path);
        Assert.StartsWith("application/x-www-form-urlencoded", r.ContentType);
        Assert.Contains("grant_type=client_credentials", r.Body);
        Assert.Contains("client_id=m2m_abc", r.Body);
        Assert.Contains("client_secret=secret_xyz", r.Body);
        Assert.Null(r.Header("Authorization")); // token endpoint is unauthenticated
    }

    [Fact]
    public async Task TokenMapsRfc6749ErrorEnvelope()
    {
        var h = TestHandler.Sequence(new Canned(401,
            "{\"error\":\"invalid_client\",\"error_description\":\"unknown client\"}"));
        var a = Client(h);
        var err = await Assert.ThrowsAsync<AuthioException>(() =>
            a.TokenAsync(new ClientCredentialsInput { ClientId = "m2m_abc", ClientSecret = "wrong" }));
        Assert.Equal("invalid_client", err.Code);
        Assert.Equal(401, err.Status);
        Assert.Equal("unknown client", err.Message);
    }

    [Fact]
    public async Task PortalGenerateLink()
    {
        var h = TestHandler.Sequence(new Canned(201,
            "{\"link\":\"https://admin-portal.authio.com/setup/abc\",\"expires_at\":\"2026-06-11T00:05:00Z\"}"));
        var a = Client(h);
        var link = await a.Portal.GenerateLinkAsync(new GenerateLinkInput
        {
            OrganizationId = "org_1",
            Intent = PortalIntent.Sso,
            SuccessUrl = "https://app.example.com/done",
        });
        Assert.Equal("2026-06-11T00:05:00Z", link.ExpiresAt);
        var r = h.Requests[0];
        Assert.Contains("\"organization_id\":\"org_1\"", r.Body);
        Assert.Contains("\"intent\":\"sso\"", r.Body);
        Assert.Contains("\"success_url\":\"https://app.example.com/done\"", r.Body);
    }
}

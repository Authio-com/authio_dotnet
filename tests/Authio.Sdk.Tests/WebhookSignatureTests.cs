using Authio;
using Xunit;

namespace Authio.Sdk.Tests;

public class WebhookSignatureTests
{
    private static long Now => DateTimeOffset.UtcNow.ToUnixTimeSeconds();

    [Fact]
    public void RoundTripsWithDefaultTolerance()
    {
        var sig = WebhookSignature.Sign("whsec_test", "hello", Now);
        Assert.True(WebhookSignature.Verify("whsec_test", "hello", sig));
    }

    [Fact]
    public void RejectsTamperedBody()
    {
        var sig = WebhookSignature.Sign("whsec_test", "hello", Now);
        Assert.False(WebhookSignature.Verify("whsec_test", "tampered", sig));
    }

    [Fact]
    public void RejectsWrongSecret()
    {
        var sig = WebhookSignature.Sign("whsec_test", "hello", Now);
        Assert.False(WebhookSignature.Verify("whsec_other", "hello", sig));
    }

    [Fact]
    public void RejectsReplayOutsideTolerance()
    {
        var sig = WebhookSignature.Sign("whsec_test", "hello", Now - 600);
        Assert.False(WebhookSignature.Verify("whsec_test", "hello", sig, 300));
        Assert.True(WebhookSignature.Verify("whsec_test", "hello", sig, 0));
    }

    [Fact]
    public void RejectsMalformedHeader()
    {
        Assert.False(WebhookSignature.Verify("whsec_test", "hello", "garbage"));
        Assert.False(WebhookSignature.Verify("whsec_test", "hello", "t=,v1="));
    }

    [Fact]
    public void MatchesPlatformVectorFixedTimestamp()
    {
        // Mirrors authio_webhooks signing.SelfTest (t=1700000000, body="hello").
        var sig = WebhookSignature.Sign("whsec_test", "hello", 1700000000L);
        Assert.StartsWith("t=1700000000,v1=", sig);
        Assert.True(WebhookSignature.Verify("whsec_test", "hello", sig, 0));
    }
}

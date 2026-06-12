namespace Authio;

/// <summary>SDK version metadata. Stamped into the <c>X-Authio-SDK</c> header.</summary>
public static class SdkVersion
{
    /// <summary>Semantic version of this SDK release.</summary>
    public const string Version = "0.1.0";

    /// <summary>Value sent in the <c>X-Authio-SDK</c> request header.</summary>
    public const string Header = "dotnet/" + Version;

    /// <summary>Value sent in the <c>User-Agent</c> request header.</summary>
    public const string UserAgent = "authio-dotnet/" + Version;
}

using Microsoft.Extensions.Logging;

namespace deadlock_dotnet_sdk;

public static partial class Log
{
    /*
    [LoggerMessage(
        EventId = 0,
        Level = LogLevel.Critical,
        Message = "Could not open socket to `{hostName}`")]
    public static partial void CouldNotOpenSocket(
        this ILogger logger, string hostName); */

    [LoggerMessage(
        EventId = 0,
        Level = LogLevel.Information,
        Message = $"Calls to {nameof(Windows.Win32.PInvoke.IsDebugModeEnabled)} and-if not enabled-{nameof(System.Diagnostics.Process.EnterDebugMode)} succeeded"
    )]
    public static partial void DebugModeCheckAndEnableSucceeded(this ILogger logger);

    [LoggerMessage(
        EventId = 0,
        Level = LogLevel.Error,
        Message = $"{nameof(Windows.Win32.PInvoke.IsDebugModeEnabled)} or {nameof(System.Diagnostics.Process.EnterDebugMode)} failed. This DeadLock instance will have significantly reduced functionality."
    )]
    public static partial void DebugModeCheckAndEnableFailed(this ILogger logger);
}

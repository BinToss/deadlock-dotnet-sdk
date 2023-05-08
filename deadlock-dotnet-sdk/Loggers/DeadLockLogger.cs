using Microsoft.Extensions.Logging;

namespace deadlock_dotnet_sdk.Loggers;

public partial class DeadLockLogger : ILogger<DeadLock>
{
    private readonly ILogger<DeadLock> _logger;

    public DeadLockLogger(ILogger<DeadLock> logger) => _logger = logger;

    #region interface
    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => _logger.BeginScope(state);
    public bool IsEnabled(LogLevel logLevel) => _logger.IsEnabled(logLevel);
    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) => _logger.Log(logLevel, eventId, state, exception, formatter);
    #endregion interface

    #region messages

    [LoggerMessage(
        EventId = _,
        Level = LogLevel.Information,
        Message = "RethrowExceptions set to '`{rethrowExceptions`}'"
    )]
    public partial void SetRethrowExceptions(bool rethrowExceptions);

    #endregion messages
}

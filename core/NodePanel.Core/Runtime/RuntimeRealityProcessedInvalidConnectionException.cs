using System.Security.Authentication;

namespace NodePanel.Core.Runtime;

internal sealed class RuntimeRealityProcessedInvalidConnectionException : AuthenticationException
{
    public const string DefaultMessage = "REALITY: processed invalid connection.";

    public RuntimeRealityProcessedInvalidConnectionException()
        : base(DefaultMessage)
    {
    }

    public static bool ShouldPreserveTransport(Exception? exception)
    {
        while (exception is AggregateException { InnerExceptions.Count: 1 } aggregateException &&
               aggregateException.InnerException is not null)
        {
            exception = aggregateException.InnerException;
        }

        return exception is RuntimeRealityProcessedInvalidConnectionException;
    }
}

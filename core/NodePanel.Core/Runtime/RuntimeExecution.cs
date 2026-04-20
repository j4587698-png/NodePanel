namespace NodePanel.Core.Runtime;

public interface IRuntimeExecution : IAsyncDisposable
{
    RuntimePlan Plan { get; }

    Task Startup { get; }

    bool IsCancellationRequested { get; }

    void Cancel();

    Exception? GetImmediateFailure();
}

public interface IRuntimeExecutionFactory
{
    IRuntimeExecution Create(RuntimeExecutionContext context);
}

public sealed class RuntimeExecutionContext
{
    public required RuntimePlan Plan { get; init; }

    public required RuntimeComponentResolver Resolver { get; init; }

    public required RuntimeExecutionCallbacks Callbacks { get; init; }

    public required RuntimeTransportLimits InboundLimits { get; init; }

    public required RuntimeTlsOptions? InboundTls { get; init; }

    public required RuntimeRealityServerOptions? InboundReality { get; init; }

    public required ProxyInboundServerLimits ProxyInboundLimits { get; init; }
}

public sealed class RuntimeExecutionCallbacks
{
    private Action<IRuntimeExecution, string, IReadOnlyList<string>, Exception>? _runtimeTaskFaulted;

    public required Action<int, IReadOnlyList<string>, string> InboundListenerStarted { get; init; }

    public required Action<int, string, ProxyInboundListenerDefinition, string> ProxyInboundListenerStarted { get; init; }

    public required Action<int, RuntimeInboundConnectionErrorReport> InboundConnectionError { get; init; }

    public required Action<int, RuntimeInboundClientHelloRejectedReport> InboundClientHelloRejected { get; init; }

    public required Action<int, RuntimeInboundUnknownServerNameRejectedReport> InboundUnknownServerNameRejected { get; init; }

    public Action<IRuntimeExecution, string, IReadOnlyList<string>, Exception> RuntimeTaskFaulted
    {
        get => _runtimeTaskFaulted
               ?? throw new InvalidOperationException("Runtime task fault callback is not configured.");
        init => _runtimeTaskFaulted = value ?? throw new ArgumentNullException(nameof(value));
    }
}

internal sealed class DefaultRuntimeExecutionFactory : IRuntimeExecutionFactory
{
    public IRuntimeExecution Create(RuntimeExecutionContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        context.Resolver.InitializeGraph();

        var inboundComposition = context.Resolver.GetRequired<IRuntimeInboundComposition>();
        var startup = new RuntimeStartupCoordinator(inboundComposition.CountStartupSignals(context.Plan));
        var runtimeInstance = RuntimeInstance.Create(context, inboundComposition, startup);
        runtimeInstance.Start();
        var lifetime = new CancellationTokenSource();
        return runtimeInstance.CreateExecution(startup, lifetime, context.Callbacks.RuntimeTaskFaulted);
    }
}

internal sealed class DefaultRuntimeExecution : IRuntimeExecution
{
    private readonly RuntimeStartupCoordinator _startup;
    private readonly Func<Exception?> _getImmediateFailure;
    private readonly RuntimeInstance _runtimeInstance;
    private readonly CancellationTokenSource _lifetime;
    private Task[] _drainTasks = Array.Empty<Task>();
    private int _disposed;
    private int _faulted;

    public DefaultRuntimeExecution(
        RuntimePlan plan,
        RuntimeStartupCoordinator startup,
        CancellationTokenSource lifetime,
        RuntimeInstance runtimeInstance,
        Func<Exception?> getImmediateFailure)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(startup);
        ArgumentNullException.ThrowIfNull(lifetime);
        ArgumentNullException.ThrowIfNull(runtimeInstance);
        ArgumentNullException.ThrowIfNull(getImmediateFailure);

        Plan = plan;
        _startup = startup;
        _lifetime = lifetime;
        _runtimeInstance = runtimeInstance;
        _getImmediateFailure = getImmediateFailure;
    }

    public RuntimePlan Plan { get; }

    public Task Startup => _startup.Completion;

    public bool IsCancellationRequested => _lifetime.IsCancellationRequested;

    public void Cancel() => _lifetime.Cancel();

    public Exception? GetImmediateFailure() => _getImmediateFailure();

    internal void SetDrainTasks(Task[] drainTasks)
    {
        ArgumentNullException.ThrowIfNull(drainTasks);
        _drainTasks = drainTasks;
    }

    internal void ReportExecutionTaskFault(
        RuntimeExecutionTask executionTask,
        Exception exception,
        Action<IRuntimeExecution, string, IReadOnlyList<string>, Exception> runtimeTaskFaulted)
    {
        ArgumentNullException.ThrowIfNull(executionTask);
        ArgumentNullException.ThrowIfNull(exception);
        ArgumentNullException.ThrowIfNull(runtimeTaskFaulted);

        if (Interlocked.CompareExchange(ref _faulted, 1, 0) != 0)
        {
            return;
        }

        _startup.ReportFault(exception);
        _lifetime.Cancel();
        runtimeTaskFaulted(this, executionTask.Name, executionTask.ListenerKeys, exception);
    }

    internal void ReportExecutionTaskStopped(
        RuntimeExecutionTask executionTask,
        Action<IRuntimeExecution, string, IReadOnlyList<string>, Exception> runtimeTaskFaulted)
    {
        ArgumentNullException.ThrowIfNull(executionTask);
        ArgumentNullException.ThrowIfNull(runtimeTaskFaulted);

        ReportExecutionTaskFault(
            executionTask,
            new InvalidOperationException($"Runtime task '{executionTask.Name}' stopped unexpectedly."),
            runtimeTaskFaulted);
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _lifetime.Cancel();

        foreach (var task in _drainTasks)
        {
            await DrainTaskAsync(task).ConfigureAwait(false);
        }

        await _runtimeInstance.DisposeAsync().ConfigureAwait(false);

        _lifetime.Dispose();
    }

    private static async Task DrainTaskAsync(Task task)
    {
        try
        {
            await task.ConfigureAwait(false);
        }
        catch
        {
        }
    }
}

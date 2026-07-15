namespace NodePanel.Core.Runtime;

internal sealed class RuntimeInstance : IAsyncDisposable
{
    private readonly IRuntimeStartable[] _startables;
    private readonly IAsyncDisposable[] _asyncDisposables;
    private int _disposed;

    private RuntimeInstance(
        RuntimePlan plan,
        IInboundManager inboundManager,
        IOutboundManager outboundManager,
        IRuntimeStartable[] startables,
        IAsyncDisposable[] asyncDisposables)
    {
        Plan = plan ?? throw new ArgumentNullException(nameof(plan));
        InboundManager = inboundManager ?? throw new ArgumentNullException(nameof(inboundManager));
        OutboundManager = outboundManager ?? throw new ArgumentNullException(nameof(outboundManager));
        _startables = startables ?? throw new ArgumentNullException(nameof(startables));
        _asyncDisposables = asyncDisposables ?? throw new ArgumentNullException(nameof(asyncDisposables));
    }

    public RuntimePlan Plan { get; }

    public IInboundManager InboundManager { get; }

    public IOutboundManager OutboundManager { get; }

    public static RuntimeInstance Create(
        RuntimeExecutionContext context,
        IRuntimeInboundComposition inboundComposition,
        RuntimeStartupCoordinator startup)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(inboundComposition);
        ArgumentNullException.ThrowIfNull(startup);

        var callbacks = new RuntimeInboundEventBridge(
            context.Plan.Revision,
            startup,
            context.Callbacks.InboundListenerStarted,
            context.Callbacks.ProxyInboundListenerStarted,
            context.Callbacks.InboundConnectionError,
            context.Callbacks.InboundClientHelloRejected,
            context.Callbacks.InboundUnknownServerNameRejected,
            context.Callbacks.ProxyConnectionAccessed);
        var inboundManager = inboundComposition.CreateManager(
            new RuntimeInboundHandlerContext
            {
                Plan = context.Plan,
                Resolver = context.Resolver,
                Callbacks = callbacks,
                InboundLimits = context.InboundLimits,
                InboundTls = context.InboundTls,
                InboundReality = context.InboundReality,
                ProxyInboundLimits = context.ProxyInboundLimits
            });
        var outboundManager = context.Resolver.GetRequired<IOutboundManager>();

        return new RuntimeInstance(
            context.Plan,
            inboundManager,
            outboundManager,
            CollectStartables(context.Resolver, outboundManager, inboundManager),
            CollectAsyncDisposables(context.Resolver, outboundManager, inboundManager));
    }

    public void Start()
    {
        ThrowIfDisposed();

        foreach (var startable in _startables)
        {
            startable.Start();
        }
    }

    public IRuntimeExecution CreateExecution(
        RuntimeStartupCoordinator startup,
        CancellationTokenSource lifetime,
        Action<IRuntimeExecution, string, IReadOnlyList<string>, Exception> runtimeTaskFaulted)
    {
        ArgumentNullException.ThrowIfNull(startup);
        ArgumentNullException.ThrowIfNull(lifetime);
        ArgumentNullException.ThrowIfNull(runtimeTaskFaulted);

        return InboundManager is IRuntimeManagedInboundManager managedInboundManager
            ? CreateManagedExecution(startup, lifetime, managedInboundManager, runtimeTaskFaulted)
            : CreateFallbackExecution(startup, lifetime, runtimeTaskFaulted);
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        foreach (var disposable in _asyncDisposables)
        {
            await disposable.DisposeAsync().ConfigureAwait(false);
        }
    }

    private IRuntimeExecution CreateManagedExecution(
        RuntimeStartupCoordinator startup,
        CancellationTokenSource lifetime,
        IRuntimeManagedInboundManager inboundManager,
        Action<IRuntimeExecution, string, IReadOnlyList<string>, Exception> runtimeTaskFaulted)
    {
        var execution = new DefaultRuntimeExecution(
            Plan,
            startup,
            lifetime,
            this,
            inboundManager.GetImmediateFailure);

        try
        {
            inboundManager.Start(
                new RuntimeManagedInboundManagerStartContext
                {
                    CancellationToken = lifetime.Token,
                    Faulted = (executionTask, exception) => execution.ReportExecutionTaskFault(executionTask, exception, runtimeTaskFaulted),
                    UnexpectedStopped = executionTask => execution.ReportExecutionTaskStopped(executionTask, runtimeTaskFaulted)
                });
            return execution;
        }
        catch
        {
            execution.DisposeAsync().AsTask().GetAwaiter().GetResult();
            throw;
        }
    }

    private IRuntimeExecution CreateFallbackExecution(
        RuntimeStartupCoordinator startup,
        CancellationTokenSource lifetime,
        Action<IRuntimeExecution, string, IReadOnlyList<string>, Exception> runtimeTaskFaulted)
    {
        var executionTasks = InboundManager.ListHandlers()
            .Select(handler => new RuntimeExecutionTask(
                handler.Name,
                handler.ListenerKeys,
                handler.RunAsync(lifetime.Token)))
            .ToArray();
        var execution = new DefaultRuntimeExecution(
            Plan,
            startup,
            lifetime,
            this,
            () => GetImmediateFailure(executionTasks, lifetime));

        try
        {
            var observerTasks = executionTasks
                .Select(executionTask => ObserveExecutionTaskAsync(executionTask, lifetime, execution, runtimeTaskFaulted))
                .ToArray();
            execution.SetDrainTasks(executionTasks
                .Select(executionTask => executionTask.Task)
                .Concat(observerTasks)
                .ToArray());
            return execution;
        }
        catch
        {
            execution.DisposeAsync().AsTask().GetAwaiter().GetResult();
            throw;
        }
    }

    private static Exception? GetImmediateFailure(
        IReadOnlyList<RuntimeExecutionTask> executionTasks,
        CancellationTokenSource lifetime)
    {
        ArgumentNullException.ThrowIfNull(executionTasks);
        ArgumentNullException.ThrowIfNull(lifetime);

        foreach (var executionTask in executionTasks)
        {
            if (executionTask.Task.IsFaulted)
            {
                return executionTask.Task.Exception?.InnerExceptions.Count == 1
                    ? executionTask.Task.Exception.InnerExceptions[0]
                    : executionTask.Task.Exception;
            }

            if (executionTask.Task.IsCompleted && !lifetime.IsCancellationRequested)
            {
                return new InvalidOperationException($"Runtime task '{executionTask.Name}' stopped unexpectedly.");
            }
        }

        return null;
    }

    private static Task ObserveExecutionTaskAsync(
        RuntimeExecutionTask executionTask,
        CancellationTokenSource lifetime,
        DefaultRuntimeExecution execution,
        Action<IRuntimeExecution, string, IReadOnlyList<string>, Exception> runtimeTaskFaulted)
    {
        ArgumentNullException.ThrowIfNull(executionTask);
        ArgumentNullException.ThrowIfNull(lifetime);
        ArgumentNullException.ThrowIfNull(execution);
        ArgumentNullException.ThrowIfNull(runtimeTaskFaulted);

        return Task.Run(
            async () =>
            {
                try
                {
                    await executionTask.Task.ConfigureAwait(false);
                    if (lifetime.IsCancellationRequested)
                    {
                        return;
                    }

                    execution.ReportExecutionTaskStopped(executionTask, runtimeTaskFaulted);
                }
                catch (OperationCanceledException) when (lifetime.IsCancellationRequested)
                {
                }
                catch (ObjectDisposedException) when (lifetime.IsCancellationRequested)
                {
                }
                catch (Exception ex)
                {
                    if (lifetime.IsCancellationRequested)
                    {
                        return;
                    }

                    execution.ReportExecutionTaskFault(executionTask, ex, runtimeTaskFaulted);
                }
            });
    }

    private static IRuntimeStartable[] CollectStartables(
        RuntimeComponentResolver resolver,
        IOutboundManager outboundManager,
        IInboundManager inboundManager)
    {
        ArgumentNullException.ThrowIfNull(resolver);
        ArgumentNullException.ThrowIfNull(outboundManager);
        ArgumentNullException.ThrowIfNull(inboundManager);

        var startables = new List<IRuntimeStartable>();
        var seen = new HashSet<object>(System.Collections.Generic.ReferenceEqualityComparer.Instance);
        var lifecycleStartables = resolver.Lifecycle.GetStartables();
        var managesOutboundLifecycle = outboundManager is IRuntimeManagedOutboundManager ||
                                       lifecycleStartables.Any(static startable => startable is IRuntimeManagedOutboundManager);

        AddUnique(startables, seen, lifecycleStartables);
        AddUnique(startables, seen, OfType<IRuntimeStartable>(outboundManager));
        if (!managesOutboundLifecycle)
        {
            AddUnique(startables, seen, outboundManager.ListHandlers().OfType<IRuntimeStartable>());
        }

        AddUnique(startables, seen, OfType<IRuntimeStartable>(inboundManager));
        AddUnique(startables, seen, inboundManager.ListHandlers().OfType<IRuntimeStartable>());

        return startables.ToArray();
    }

    private static IAsyncDisposable[] CollectAsyncDisposables(
        RuntimeComponentResolver resolver,
        IOutboundManager outboundManager,
        IInboundManager inboundManager)
    {
        ArgumentNullException.ThrowIfNull(resolver);
        ArgumentNullException.ThrowIfNull(outboundManager);
        ArgumentNullException.ThrowIfNull(inboundManager);

        var disposables = new List<IAsyncDisposable>();
        var seen = new HashSet<object>(System.Collections.Generic.ReferenceEqualityComparer.Instance);
        var lifecycleDisposables = resolver.Lifecycle.GetAsyncDisposables();
        var managesOutboundLifecycle = outboundManager is IRuntimeManagedOutboundManager ||
                                       lifecycleDisposables.Any(static disposable => disposable is IRuntimeManagedOutboundManager);

        AddUnique(disposables, seen, lifecycleDisposables);
        AddUnique(disposables, seen, OfType<IAsyncDisposable>(outboundManager));
        if (!managesOutboundLifecycle)
        {
            AddUnique(disposables, seen, outboundManager.ListHandlers().OfType<IAsyncDisposable>());
        }

        AddUnique(disposables, seen, OfType<IAsyncDisposable>(inboundManager));
        if (inboundManager is not IRuntimeManagedInboundManager)
        {
            AddUnique(disposables, seen, inboundManager.ListHandlers());
        }

        return disposables.ToArray();
    }

    private static IEnumerable<TService> OfType<TService>(object instance)
        where TService : class
    {
        ArgumentNullException.ThrowIfNull(instance);
        return instance is TService service ? [service] : [];
    }

    private static void AddUnique<TService>(
        List<TService> items,
        HashSet<object> seen,
        IEnumerable<TService> candidates)
        where TService : class
    {
        ArgumentNullException.ThrowIfNull(items);
        ArgumentNullException.ThrowIfNull(seen);
        ArgumentNullException.ThrowIfNull(candidates);

        foreach (var candidate in candidates)
        {
            if (seen.Add(candidate))
            {
                items.Add(candidate);
            }
        }
    }

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(RuntimeInstance));
        }
    }
}

namespace NodePanel.Core.Runtime;

public sealed class DefaultInboundManager : IInboundManager, IRuntimeManagedInboundManager
{
    private readonly Dictionary<string, ManagedInboundHandlerRegistration> _handlersByName = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _sync = new();
    private RuntimeManagedInboundManagerStartContext? _startContext;
    private bool _running;
    private int _disposed;
    private Exception? _immediateFailure;

    public DefaultInboundManager()
    {
    }

    public DefaultInboundManager(IEnumerable<IInboundHandler> handlers)
    {
        ArgumentNullException.ThrowIfNull(handlers);

        foreach (var handler in handlers)
        {
            AddHandler(handler);
        }
    }

    public void AddHandler(IInboundHandler handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        ArgumentException.ThrowIfNullOrWhiteSpace(handler.Name);

        ManagedInboundHandlerRegistration registration;
        var shouldStart = false;
        lock (_sync)
        {
            ThrowIfDisposed();

            registration = new ManagedInboundHandlerRegistration(handler);
            if (!_handlersByName.TryAdd(handler.Name.Trim(), registration))
            {
                throw new InvalidOperationException($"Inbound handler '{handler.Name}' is already registered.");
            }

            shouldStart = _running;
        }

        if (shouldStart)
        {
            StartRegistration(registration, GetRequiredStartContext());
        }
    }

    public bool RemoveHandler(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return false;
        }

        ManagedInboundHandlerRegistration? registration;
        lock (_sync)
        {
            if (!_handlersByName.Remove(name.Trim(), out registration))
            {
                return false;
            }
        }

        if (registration.ExecutionTask is not null)
        {
            registration.Cancellation?.Cancel();
            DrainTaskAsync(registration.ExecutionTask.Task).GetAwaiter().GetResult();
        }

        registration.Handler.DisposeAsync().AsTask().GetAwaiter().GetResult();
        registration.Cancellation?.Dispose();
        return true;
    }

    public IInboundHandler? GetHandler(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return null;
        }

        lock (_sync)
        {
            return _handlersByName.TryGetValue(name.Trim(), out var registration)
                ? registration.Handler
                : null;
        }
    }

    public IReadOnlyList<IInboundHandler> ListHandlers()
    {
        lock (_sync)
        {
            return _handlersByName.Values
                .Select(static registration => registration.Handler)
                .ToArray();
        }
    }

    public void Start(CancellationToken cancellationToken)
    {
        StartCore(
            new RuntimeManagedInboundManagerStartContext
            {
                CancellationToken = cancellationToken,
                Faulted = static (_, _) => { },
                UnexpectedStopped = static _ => { }
            });
    }

    void IRuntimeManagedInboundManager.Start(RuntimeManagedInboundManagerStartContext context)
    {
        StartCore(context);
    }

    public Exception? GetImmediateFailure()
        => Volatile.Read(ref _immediateFailure);

    private void StartCore(RuntimeManagedInboundManagerStartContext context)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(context);

        ManagedInboundHandlerRegistration[] registrations;
        lock (_sync)
        {
            if (_running)
            {
                return;
            }

            _startContext = context;
            _running = true;
            registrations = _handlersByName.Values.ToArray();
        }

        foreach (var registration in registrations)
        {
            StartRegistration(registration, context);
        }
    }

    IReadOnlyList<RuntimeExecutionTask> IRuntimeManagedInboundManager.ListExecutionTasks()
    {
        lock (_sync)
        {
            return _handlersByName.Values
                .Select(static registration => registration.ExecutionTask)
                .Where(static task => task is not null)
                .Cast<RuntimeExecutionTask>()
                .ToArray();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        ManagedInboundHandlerRegistration[] registrations;
        lock (_sync)
        {
            _running = false;
            registrations = _handlersByName.Values.ToArray();
        }

        foreach (var registration in registrations)
        {
            registration.Cancellation?.Cancel();
        }

        foreach (var registration in registrations)
        {
            if (registration.ExecutionTask is not null)
            {
                await DrainTaskAsync(registration.ExecutionTask.Task).ConfigureAwait(false);
            }

            if (registration.ObserverTask is not null)
            {
                await DrainTaskAsync(registration.ObserverTask).ConfigureAwait(false);
            }

            await registration.Handler.DisposeAsync().ConfigureAwait(false);
            registration.Cancellation?.Dispose();
        }
    }

    private void StartRegistration(
        ManagedInboundHandlerRegistration registration,
        RuntimeManagedInboundManagerStartContext context)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);

        CancellationTokenSource? linkedCancellation = null;
        lock (_sync)
        {
            if (registration.ExecutionTask is not null)
            {
                return;
            }

            registration.Cancellation ??= CancellationTokenSource.CreateLinkedTokenSource(context.CancellationToken);
            linkedCancellation = registration.Cancellation;
        }

        Task task;
        try
        {
            task = registration.Handler.RunAsync(linkedCancellation.Token);
        }
        catch
        {
            linkedCancellation.Dispose();
            lock (_sync)
            {
                if (ReferenceEquals(registration.Cancellation, linkedCancellation))
                {
                    registration.Cancellation = null;
                }
            }

            throw;
        }

        lock (_sync)
        {
            if (registration.ExecutionTask is not null)
            {
                return;
            }

            var executionTask = new RuntimeExecutionTask(
                registration.Handler.Name,
                registration.Handler.ListenerKeys,
                task);
            registration.ExecutionTask = executionTask;
            registration.ObserverTask = ObserveExecutionTaskAsync(registration, executionTask, context);
        }
    }

    private Task ObserveExecutionTaskAsync(
        ManagedInboundHandlerRegistration registration,
        RuntimeExecutionTask executionTask,
        RuntimeManagedInboundManagerStartContext context)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(executionTask);
        ArgumentNullException.ThrowIfNull(context);

        return Task.Run(
            async () =>
            {
                try
                {
                    await executionTask.Task.ConfigureAwait(false);
                    if (IsCancellationRequested(registration, context))
                    {
                        return;
                    }

                    var exception = new InvalidOperationException($"Runtime task '{executionTask.Name}' stopped unexpectedly.");
                    RecordImmediateFailure(exception);
                    context.UnexpectedStopped(executionTask);
                }
                catch (OperationCanceledException) when (IsCancellationRequested(registration, context))
                {
                }
                catch (ObjectDisposedException) when (IsCancellationRequested(registration, context))
                {
                }
                catch (Exception ex)
                {
                    if (IsCancellationRequested(registration, context))
                    {
                        return;
                    }

                    RecordImmediateFailure(ex);
                    context.Faulted(executionTask, ex);
                }
            });
    }

    private static bool IsCancellationRequested(
        ManagedInboundHandlerRegistration registration,
        RuntimeManagedInboundManagerStartContext context)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);

        return context.CancellationToken.IsCancellationRequested ||
               registration.Cancellation?.IsCancellationRequested == true;
    }

    private void RecordImmediateFailure(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        Interlocked.CompareExchange(ref _immediateFailure, exception, null);
    }

    private RuntimeManagedInboundManagerStartContext GetRequiredStartContext()
    {
        lock (_sync)
        {
            return _startContext
                   ?? throw new InvalidOperationException("Inbound manager is not started.");
        }
    }

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(DefaultInboundManager));
        }
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

    private sealed class ManagedInboundHandlerRegistration
    {
        public ManagedInboundHandlerRegistration(IInboundHandler handler)
        {
            Handler = handler;
        }

        public IInboundHandler Handler { get; }

        public CancellationTokenSource? Cancellation { get; set; }

        public RuntimeExecutionTask? ExecutionTask { get; set; }

        public Task? ObserverTask { get; set; }
    }
}

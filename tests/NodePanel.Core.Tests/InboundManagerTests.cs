using NodePanel.Core.Protocol;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class InboundManagerTests
{
    [Fact]
    public void Constructor_indexes_handlers_by_name()
    {
        var first = new TestInboundHandler("trojan-inbound", InboundProtocols.Trojan);
        var second = new TestInboundHandler("socks-local", ProxyInboundProtocols.Socks);
        var manager = new DefaultInboundManager([first, second]);

        Assert.Same(first, manager.GetHandler("trojan-inbound"));
        Assert.Same(second, manager.GetHandler("socks-local"));
        Assert.Equal([first, second], manager.ListHandlers());
    }

    [Fact]
    public void Constructor_rejects_duplicate_names()
    {
        var first = new TestInboundHandler("shared", InboundProtocols.Trojan);
        var second = new TestInboundHandler("shared", InboundProtocols.Vless);

        var exception = Assert.Throws<InvalidOperationException>(() => new DefaultInboundManager([first, second]));
        Assert.Contains("already registered", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void RemoveHandler_removes_registered_handler()
    {
        var handler = new TestInboundHandler("trojan-inbound", InboundProtocols.Trojan);
        var manager = new DefaultInboundManager();
        manager.AddHandler(handler);

        var removed = manager.RemoveHandler("trojan-inbound");

        Assert.True(removed);
        Assert.Null(manager.GetHandler("trojan-inbound"));
        Assert.Empty(manager.ListHandlers());
        Assert.Equal(1, handler.DisposeCallCount);
    }

    [Fact]
    public async Task Start_starts_registered_handlers_and_exposes_execution_tasks()
    {
        await using var manager = new DefaultInboundManager();
        var handler = new TestInboundHandler("trojan-inbound", InboundProtocols.Trojan, keepAlive: true);
        manager.AddHandler(handler);

        manager.Start(CancellationToken.None);
        await handler.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(1, handler.RunCallCount);
        var executionTask = Assert.Single(((IRuntimeManagedInboundManager)manager).ListExecutionTasks());
        Assert.Equal(handler.Name, executionTask.Name);
        Assert.Equal(handler.ListenerKeys, executionTask.ListenerKeys);
        Assert.False(executionTask.Task.IsCompleted);
    }

    [Fact]
    public async Task AddHandler_starts_immediately_when_manager_is_running()
    {
        await using var manager = new DefaultInboundManager();
        manager.Start(CancellationToken.None);

        var handler = new TestInboundHandler("socks-local", ProxyInboundProtocols.Socks, keepAlive: true);
        manager.AddHandler(handler);

        await handler.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(1, handler.RunCallCount);
        Assert.Single(((IRuntimeManagedInboundManager)manager).ListExecutionTasks());
    }

    [Fact]
    public async Task Start_records_immediate_failure_and_reports_faulted_execution_task()
    {
        await using var manager = new DefaultInboundManager();
        var completionGate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var faulted = new TaskCompletionSource<(RuntimeExecutionTask ExecutionTask, Exception Exception)>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var unexpectedStoppedCount = 0;
        var handler = new TestInboundHandler(
            "trojan-inbound",
            InboundProtocols.Trojan,
            terminationMode: TestInboundHandlerTerminationMode.Fault,
            completionGate: completionGate);
        manager.AddHandler(handler);

        ((IRuntimeManagedInboundManager)manager).Start(
            new RuntimeManagedInboundManagerStartContext
            {
                CancellationToken = CancellationToken.None,
                Faulted = (executionTask, exception) => faulted.TrySetResult((executionTask, exception)),
                UnexpectedStopped = _ => Interlocked.Increment(ref unexpectedStoppedCount)
            });

        await handler.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        completionGate.TrySetResult();

        var (executionTask, exception) = await faulted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var immediateFailure = Assert.IsType<InvalidOperationException>(
            ((IRuntimeManagedInboundManager)manager).GetImmediateFailure());
        Assert.Same(immediateFailure, exception);
        Assert.Equal("Inbound handler failed after start.", immediateFailure.Message);
        Assert.Equal(handler.Name, executionTask.Name);
        Assert.Equal(handler.ListenerKeys, executionTask.ListenerKeys);
        Assert.Equal(0, Volatile.Read(ref unexpectedStoppedCount));
    }

    [Fact]
    public async Task Start_records_unexpected_stop_and_reports_stopped_execution_task()
    {
        await using var manager = new DefaultInboundManager();
        var completionGate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var unexpectedStopped = new TaskCompletionSource<RuntimeExecutionTask>(TaskCreationOptions.RunContinuationsAsynchronously);
        var faultedCount = 0;
        var handler = new TestInboundHandler(
            "trojan-inbound",
            InboundProtocols.Trojan,
            terminationMode: TestInboundHandlerTerminationMode.StopUnexpectedly,
            completionGate: completionGate);
        manager.AddHandler(handler);

        ((IRuntimeManagedInboundManager)manager).Start(
            new RuntimeManagedInboundManagerStartContext
            {
                CancellationToken = CancellationToken.None,
                Faulted = (_, _) => Interlocked.Increment(ref faultedCount),
                UnexpectedStopped = executionTask => unexpectedStopped.TrySetResult(executionTask)
            });

        await handler.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        completionGate.TrySetResult();

        var executionTask = await unexpectedStopped.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var immediateFailure = Assert.IsType<InvalidOperationException>(
            ((IRuntimeManagedInboundManager)manager).GetImmediateFailure());
        Assert.Equal("Runtime task 'trojan-inbound' stopped unexpectedly.", immediateFailure.Message);
        Assert.Equal(handler.Name, executionTask.Name);
        Assert.Equal(handler.ListenerKeys, executionTask.ListenerKeys);
        Assert.Equal(0, Volatile.Read(ref faultedCount));
    }

    [Fact]
    public async Task DisposeAsync_cancels_and_disposes_started_handlers()
    {
        var manager = new DefaultInboundManager();
        var handler = new TestInboundHandler("trojan-inbound", InboundProtocols.Trojan, keepAlive: true);
        manager.AddHandler(handler);
        manager.Start(CancellationToken.None);

        await handler.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await manager.DisposeAsync();

        await handler.Canceled.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(1, handler.DisposeCallCount);
    }

    private sealed class TestInboundHandler : IInboundHandler
    {
        private readonly bool _keepAlive;
        private readonly TestInboundHandlerTerminationMode _terminationMode;
        private readonly TaskCompletionSource? _completionGate;

        public TestInboundHandler(
            string name,
            string protocol,
            bool keepAlive = false,
            TestInboundHandlerTerminationMode terminationMode = TestInboundHandlerTerminationMode.None,
            TaskCompletionSource? completionGate = null)
        {
            Name = name;
            Protocol = protocol;
            _keepAlive = keepAlive;
            _terminationMode = terminationMode;
            _completionGate = completionGate;
        }

        public string Name { get; }

        public string Protocol { get; }

        public IReadOnlyList<string> ListenerKeys { get; } = ["listener"];

        public int StartupSignalCount => 0;

        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource Canceled { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public int RunCallCount { get; private set; }

        public int DisposeCallCount { get; private set; }

        public async Task RunAsync(CancellationToken cancellationToken)
        {
            RunCallCount++;
            Started.TrySetResult();

            try
            {
                if (_keepAlive)
                {
                    await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
                    return;
                }

                if (_completionGate is not null)
                {
                    await _completionGate.Task.WaitAsync(cancellationToken);
                }

                switch (_terminationMode)
                {
                    case TestInboundHandlerTerminationMode.Fault:
                        throw new InvalidOperationException("Inbound handler failed after start.");
                    case TestInboundHandlerTerminationMode.StopUnexpectedly:
                        return;
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                Canceled.TrySetResult();
            }
        }

        public ValueTask DisposeAsync()
        {
            DisposeCallCount++;
            return ValueTask.CompletedTask;
        }
    }

    private enum TestInboundHandlerTerminationMode
    {
        None,
        Fault,
        StopUnexpectedly
    }
}

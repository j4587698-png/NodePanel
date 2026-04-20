namespace NodePanel.Core.Runtime;

public interface IDispatcher
{
    ValueTask<Stream> DispatchTcpAsync(
        DispatchContext context,
        DispatchDestination destination,
        CancellationToken cancellationToken);

    ValueTask<IOutboundUdpTransport> DispatchUdpAsync(
        DispatchContext context,
        CancellationToken cancellationToken);
}

public interface IRuntimeDispatcherAccessor
{
    IDispatcher GetRequiredDispatcher();
}

public interface IRuntimeDispatcherController : IRuntimeDispatcherAccessor, IServiceProvider
{
    void SetDispatcher(IDispatcher dispatcher);

    void ClearDispatcher();
}

public interface IInboundManager
{
    void AddHandler(IInboundHandler handler);

    bool RemoveHandler(string name);

    IInboundHandler? GetHandler(string name);

    IReadOnlyList<IInboundHandler> ListHandlers();
}

internal interface IRuntimeManagedInboundManager : IAsyncDisposable
{
    void Start(RuntimeManagedInboundManagerStartContext context);

    Exception? GetImmediateFailure();

    IReadOnlyList<RuntimeExecutionTask> ListExecutionTasks();
}

internal sealed class RuntimeManagedInboundManagerStartContext
{
    public required CancellationToken CancellationToken { get; init; }

    public required Action<RuntimeExecutionTask, Exception> Faulted { get; init; }

    public required Action<RuntimeExecutionTask> UnexpectedStopped { get; init; }
}

public interface IInboundHandler : IAsyncDisposable
{
    string Name { get; }

    string Protocol { get; }

    IReadOnlyList<string> ListenerKeys { get; }

    int StartupSignalCount { get; }

    Task RunAsync(CancellationToken cancellationToken);
}

public interface IOutboundManager
{
    void AddHandler(IOutboundHandler handler);

    bool RemoveHandler(string protocol);

    IOutboundHandler? GetHandler(string tag);

    IOutboundHandler GetDefaultHandler();

    IReadOnlyList<IOutboundHandler> ListHandlers();
}

internal interface IRuntimeManagedOutboundManager : IRuntimeStartable, IAsyncDisposable
{
}

public interface IOutboundRouter
{
    ResolvedOutboundRoute Resolve(DispatchContext context, DispatchDestination? destination);
}

public interface IRuntimeRoutingService
{
    bool TryPickRoute(DispatchContext context, out OutboundRouteDecision route);

    OutboundRouteDecision PickRoute(DispatchContext context);

    void AddRule(IRoutingRuleDefinition rule, bool shouldAppend = true);

    void AddRules(IReadOnlyList<IRoutingRuleDefinition> rules, bool shouldAppend);

    bool RemoveRule(string ruleTag);

    IReadOnlyList<RoutingRuleRuntime> ListRules();
}

public interface IOutboundHandler
{
    string Protocol { get; }

    ValueTask<Stream> OpenTcpAsync(
        DispatchContext context,
        DispatchDestination destination,
        CancellationToken cancellationToken);

    ValueTask<IOutboundUdpTransport> OpenUdpAsync(
        DispatchContext context,
        CancellationToken cancellationToken);
}

public interface IOutboundUdpTransport : IAsyncDisposable
{
    ValueTask SendAsync(
        DispatchDestination destination,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken);

    ValueTask<DispatchDatagram?> ReceiveAsync(CancellationToken cancellationToken);
}

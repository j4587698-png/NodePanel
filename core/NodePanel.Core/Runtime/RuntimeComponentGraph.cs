namespace NodePanel.Core.Runtime;

internal abstract class RuntimeComponentResolution
{
    public abstract void Invoke(RuntimeComponentResolver resolver);
}

internal sealed class RuntimeComponentResolution<TService> : RuntimeComponentResolution
    where TService : class
{
    private readonly Action<TService> _callback;

    public RuntimeComponentResolution(Action<TService> callback)
    {
        ArgumentNullException.ThrowIfNull(callback);
        _callback = callback;
    }

    public override void Invoke(RuntimeComponentResolver resolver)
    {
        ArgumentNullException.ThrowIfNull(resolver);
        _callback(resolver.GetRequired<TService>());
    }
}

internal sealed class RuntimeComponentResolution<TService1, TService2> : RuntimeComponentResolution
    where TService1 : class
    where TService2 : class
{
    private readonly Action<TService1, TService2> _callback;

    public RuntimeComponentResolution(Action<TService1, TService2> callback)
    {
        ArgumentNullException.ThrowIfNull(callback);
        _callback = callback;
    }

    public override void Invoke(RuntimeComponentResolver resolver)
    {
        ArgumentNullException.ThrowIfNull(resolver);
        _callback(
            resolver.GetRequired<TService1>(),
            resolver.GetRequired<TService2>());
    }
}

internal sealed class RuntimeOptionalComponentResolution<TService> : RuntimeComponentResolution
    where TService : class
{
    private readonly Action<TService> _callback;

    public RuntimeOptionalComponentResolution(Action<TService> callback)
    {
        ArgumentNullException.ThrowIfNull(callback);
        _callback = callback;
    }

    public override void Invoke(RuntimeComponentResolver resolver)
    {
        ArgumentNullException.ThrowIfNull(resolver);

        var service = resolver.GetOptional<TService>();
        if (service is not null)
        {
            _callback(service);
        }
    }
}

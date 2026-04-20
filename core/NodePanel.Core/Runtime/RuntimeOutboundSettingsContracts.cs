namespace NodePanel.Core.Runtime;

public interface IRuntimeOutboundOptions
{
    string Tag { get; }

    string Protocol { get; }
}

public interface IRuntimeOutboundSettingsProvider
{
    bool TryResolve(DispatchContext context, out IRuntimeOutboundOptions settings);

    bool TryResolve<TOptions>(DispatchContext context, out TOptions settings)
        where TOptions : class, IRuntimeOutboundOptions;
}

namespace NodePanel.Core.Runtime;

internal static class DispatchDnsResolution
{
    public static bool ShouldSkipDnsResolve(DispatchContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        return context.Content.SkipDnsResolve;
    }

    public static IDnsResolver ResolveResolver(DispatchContext context, IDnsResolver dnsResolver)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(dnsResolver);
        return ShouldSkipDnsResolve(context)
            ? SystemDnsResolver.Instance
            : dnsResolver;
    }

    public static DispatchContent EnableSkipDnsResolve(DispatchContent content)
    {
        ArgumentNullException.ThrowIfNull(content);
        return content.SkipDnsResolve
            ? content
            : content with
            {
                SkipDnsResolve = true
            };
    }
}

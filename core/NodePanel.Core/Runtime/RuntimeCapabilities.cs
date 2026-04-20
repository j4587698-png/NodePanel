namespace NodePanel.Core.Runtime;

public static class RuntimeCapabilities
{
    public static IReadOnlyList<string> SupportedOutboundProtocols => GetSupportedOutboundProtocols();

    public static IReadOnlyList<string> SupportedInboundProtocols => GetSupportedInboundProtocols();

    public static IReadOnlyList<string> GetSupportedOutboundProtocols(RuntimeComponentCatalog? components = null)
        => (components ?? RuntimeComponentCatalog.Default).SupportedOutboundProtocols;

    public static IReadOnlyList<string> GetSupportedInboundProtocols(RuntimeComponentCatalog? components = null)
        => (components ?? RuntimeComponentCatalog.Default).SupportedInboundProtocols;
}

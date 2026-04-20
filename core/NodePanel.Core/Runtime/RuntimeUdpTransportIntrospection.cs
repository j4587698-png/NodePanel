namespace NodePanel.Core.Runtime;

internal interface IInnerUdpTransportAccessor
{
    IOutboundUdpTransport InnerTransport { get; }
}

internal static class RuntimeUdpTransportClassifier
{
    public static bool IsFlowControlled(IOutboundUdpTransport transport)
    {
        ArgumentNullException.ThrowIfNull(transport);

        var current = transport;
        for (var depth = 0; depth < 32; depth++)
        {
            if (current is FlowControlledUdpTransport)
            {
                return true;
            }

            if (current is not IInnerUdpTransportAccessor accessor ||
                ReferenceEquals(accessor.InnerTransport, current))
            {
                return false;
            }

            current = accessor.InnerTransport;
        }

        return false;
    }
}

namespace NodePanel.Core.Runtime;

public interface IInboundQuicDefinition
{
    RuntimeQuicOptions QuicOptions { get; }
}

internal static class RuntimeQuicOptionsNormalizer
{
    public static RuntimeQuicOptions Normalize(RuntimeQuicOptions? value)
    {
        if (value is null)
        {
            return RuntimeQuicOptions.Empty;
        }

        return new RuntimeQuicOptions
        {
            Congestion = string.IsNullOrWhiteSpace(value.Congestion)
                ? string.Empty
                : value.Congestion.Trim().ToLowerInvariant(),
            BrutalUp = Math.Max(0, value.BrutalUp),
            BrutalDown = Math.Max(0, value.BrutalDown),
            UdpHop = NormalizeUdpHopOptions(value.UdpHop),
            InitStreamReceiveWindow = Math.Max(0, value.InitStreamReceiveWindow),
            MaxStreamReceiveWindow = Math.Max(0, value.MaxStreamReceiveWindow),
            InitConnReceiveWindow = Math.Max(0, value.InitConnReceiveWindow),
            MaxConnReceiveWindow = Math.Max(0, value.MaxConnReceiveWindow),
            MaxIdleTimeoutSeconds = Math.Max(0, value.MaxIdleTimeoutSeconds),
            KeepAlivePeriodSeconds = Math.Max(0, value.KeepAlivePeriodSeconds),
            DisablePathMtuDiscovery = value.DisablePathMtuDiscovery,
            MaxIncomingStreams = Math.Max(0, value.MaxIncomingStreams)
        };
    }

    public static RuntimeUdpHopOptions NormalizeUdpHopOptions(RuntimeUdpHopOptions? value)
    {
        if (value is null)
        {
            return RuntimeUdpHopOptions.Empty;
        }

        return new RuntimeUdpHopOptions
        {
            Ports = (value.Ports ?? Array.Empty<int>())
                .Where(static port => port is > 0 and <= 65535)
                .Distinct()
                .ToArray(),
            IntervalMinSeconds = Math.Max(0, value.IntervalMinSeconds),
            IntervalMaxSeconds = Math.Max(0, value.IntervalMaxSeconds)
        };
    }
}

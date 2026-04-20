using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

internal static class RuntimeSessionPolicyTestHelper
{
    public static RuntimeSessionPolicyCatalog CreateCatalog(
        int level,
        int connectionIdleSeconds,
        int uplinkOnlySeconds,
        int downlinkOnlySeconds,
        int handshakeSeconds = 60)
        => new()
        {
            DefaultPolicy = new RuntimeSessionPolicy
            {
                Timeout = new RuntimeSessionPolicyTimeouts
                {
                    HandshakeSeconds = 60,
                    ConnectionIdleSeconds = 300,
                    UplinkOnlySeconds = 1,
                    DownlinkOnlySeconds = 1
                }
            },
            Levels = new Dictionary<int, RuntimeSessionPolicy>
            {
                [Math.Max(0, level)] = new()
                {
                    Timeout = new RuntimeSessionPolicyTimeouts
                    {
                        HandshakeSeconds = Math.Max(1, handshakeSeconds),
                        ConnectionIdleSeconds = Math.Max(1, connectionIdleSeconds),
                        UplinkOnlySeconds = Math.Max(1, uplinkOnlySeconds),
                        DownlinkOnlySeconds = Math.Max(1, downlinkOnlySeconds)
                    }
                }
            }
        };
}

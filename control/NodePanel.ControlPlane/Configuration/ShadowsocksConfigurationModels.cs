using NodePanel.Core.Runtime;

namespace NodePanel.ControlPlane.Configuration;

public sealed record ShadowsocksUserConfig : IShadowsocksUserDefinition, IShadowsocks2022UserDefinition
{
    public string UserId { get; init; } = string.Empty;

    public int Level { get; init; }

    public string Cipher { get; init; } = string.Empty;

    public string Password { get; init; } = string.Empty;

    public string Address { get; init; } = string.Empty;

    public int Port { get; init; }

    public long BytesPerSecond { get; init; }

    public int DeviceLimit { get; init; }
}

using NodePanel.Core.Runtime;

namespace NodePanel.Core.Protocol;

public enum VmessCommand : byte
{
    Connect = 0x01,
    Udp = 0x02,
    Mux = 0x03
}

internal enum VmessSecurityType : byte
{
    Unknown = 0,
    Auto = 2,
    Aes128Gcm = 3,
    ChaCha20Poly1305 = 4,
    None = 5,
    Zero = 6
}

internal static class VmessRequestOptions
{
    public const byte ChunkStream = 0x01;
    public const byte ChunkMasking = 0x04;
    public const byte GlobalPadding = 0x08;
    public const byte AuthenticatedLength = 0x10;

    public static bool Has(byte value, byte flag)
        => (value & flag) == flag;
}

public sealed record VmessRequest
{
    public byte Version { get; init; }

    public required VmessUser User { get; init; }

    public required byte[] RequestBodyKey { get; init; }

    public required byte[] RequestBodyIv { get; init; }

    public byte ResponseHeader { get; init; }

    public byte Option { get; init; }

    internal VmessSecurityType Security { get; init; }

    public VmessCommand Command { get; init; }

    public string TargetHost { get; init; } = string.Empty;

    public int TargetPort { get; init; }
}

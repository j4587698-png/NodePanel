namespace NodePanel.Core.Runtime;

public interface IRuntimeUserDefinition
{
    string UserId { get; }

    long BytesPerSecond { get; }

    int DeviceLimit { get; }
}

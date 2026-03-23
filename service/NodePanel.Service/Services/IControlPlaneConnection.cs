using NodePanel.ControlPlane.Protocol;

namespace NodePanel.Service.Services;

public interface IControlPlaneConnection
{
    bool IsConnected { get; }

    Task<bool> SendAsync(ControlPlaneEnvelope envelope, CancellationToken cancellationToken);
}

using System.ComponentModel.DataAnnotations;
using NodePanel.ControlPlane.Configuration;
using NodePanel.Core.Runtime;

namespace NodePanel.Panel.Models;

public sealed class OutboundFormInput
{
    public string Tag { get; set; } = string.Empty;

    public bool Enabled { get; set; } = true;

    public string Protocol { get; set; } = OutboundProtocols.Freedom;

    public string Via { get; set; } = string.Empty;

    public string ViaCidr { get; set; } = string.Empty;

    public string TargetStrategy { get; set; } = OutboundTargetStrategies.AsIs;

    public string ProxyOutboundTag { get; set; } = string.Empty;

    public bool MultiplexEnabled { get; set; }

    [Range(0, 1024)]
    public int MultiplexConcurrency { get; set; }

    [Range(0, 1024)]
    public int MultiplexXudpConcurrency { get; set; }

    public string MultiplexXudpProxyUdp443 { get; set; } = OutboundXudpProxyModes.Reject;

    public string Transport { get; set; } = TrojanOutboundTransports.Tls;

    public string ServerHost { get; set; } = string.Empty;

    [Range(0, 65535)]
    public int ServerPort { get; set; } = 443;

    public string ServerName { get; set; } = string.Empty;

    public string WebSocketPath { get; set; } = string.Empty;

    public string WebSocketHeadersText { get; set; } = string.Empty;

    [Range(0, 65535)]
    public int WebSocketEarlyDataBytes { get; set; }

    [Range(0, 3600)]
    public int WebSocketHeartbeatPeriodSeconds { get; set; }

    public string ApplicationProtocols { get; set; } = string.Empty;

    public string Password { get; set; } = string.Empty;

    [Range(0, 600)]
    public int ConnectTimeoutSeconds { get; set; }

    [Range(0, 600)]
    public int HandshakeTimeoutSeconds { get; set; }

    public bool SkipCertificateValidation { get; set; }

    public bool IsEmpty()
        => string.IsNullOrWhiteSpace(Tag) &&
           string.IsNullOrWhiteSpace(Via) &&
           string.IsNullOrWhiteSpace(ViaCidr) &&
           string.IsNullOrWhiteSpace(ProxyOutboundTag) &&
           !MultiplexEnabled &&
           MultiplexConcurrency == 0 &&
           MultiplexXudpConcurrency == 0 &&
           string.Equals(MultiplexXudpProxyUdp443, OutboundXudpProxyModes.Reject, StringComparison.OrdinalIgnoreCase) &&
           string.IsNullOrWhiteSpace(ServerHost) &&
           ServerPort == 443 &&
           string.IsNullOrWhiteSpace(ServerName) &&
           string.IsNullOrWhiteSpace(WebSocketPath) &&
           string.IsNullOrWhiteSpace(WebSocketHeadersText) &&
           WebSocketEarlyDataBytes == 0 &&
           WebSocketHeartbeatPeriodSeconds == 0 &&
           string.IsNullOrWhiteSpace(ApplicationProtocols) &&
           string.IsNullOrWhiteSpace(Password) &&
           ConnectTimeoutSeconds == 0 &&
           HandshakeTimeoutSeconds == 0 &&
           !SkipCertificateValidation &&
           Enabled &&
           string.Equals(OutboundProtocols.Normalize(Protocol), OutboundProtocols.Freedom, StringComparison.Ordinal) &&
           string.Equals(OutboundTargetStrategies.Normalize(TargetStrategy), OutboundTargetStrategies.AsIs, StringComparison.Ordinal) &&
           string.Equals(TrojanOutboundTransports.Normalize(Transport), TrojanOutboundTransports.Tls, StringComparison.Ordinal);

    public bool TryToConfig(out OutboundConfig config, out string error)
    {
        if (string.IsNullOrWhiteSpace(Tag))
        {
            config = new OutboundConfig();
            error = "标签不能为空。";
            return false;
        }

        if (!NodeFormValueCodec.TryParseHeaderLines(WebSocketHeadersText, out var headers, out error))
        {
            config = new OutboundConfig();
            return false;
        }

        config = new OutboundConfig
        {
            Tag = NodeFormValueCodec.TrimOrEmpty(Tag),
            Enabled = Enabled,
            Protocol = Protocol,
            Via = NodeFormValueCodec.TrimOrEmpty(Via),
            ViaCidr = NodeFormValueCodec.TrimOrEmpty(ViaCidr),
            TargetStrategy = TargetStrategy,
            ProxyOutboundTag = NodeFormValueCodec.TrimOrEmpty(ProxyOutboundTag),
            MultiplexSettings = new OutboundMultiplexConfig
            {
                Enabled = MultiplexEnabled,
                Concurrency = MultiplexConcurrency,
                XudpConcurrency = MultiplexXudpConcurrency,
                XudpProxyUdp443 = MultiplexXudpProxyUdp443
            },
            Transport = Transport,
            ServerHost = NodeFormValueCodec.TrimOrEmpty(ServerHost),
            ServerPort = ServerPort,
            ServerName = NodeFormValueCodec.TrimOrEmpty(ServerName),
            WebSocketPath = NodeFormValueCodec.TrimOrEmpty(WebSocketPath),
            WebSocketHeaders = headers,
            WebSocketEarlyDataBytes = WebSocketEarlyDataBytes,
            WebSocketHeartbeatPeriodSeconds = WebSocketHeartbeatPeriodSeconds,
            ApplicationProtocols = NodeFormValueCodec.ParseCsv(ApplicationProtocols),
            Password = NodeFormValueCodec.TrimOrEmpty(Password),
            ConnectTimeoutSeconds = ConnectTimeoutSeconds,
            HandshakeTimeoutSeconds = HandshakeTimeoutSeconds,
            SkipCertificateValidation = SkipCertificateValidation
        };
        error = string.Empty;
        return true;
    }

    public static OutboundFormInput FromConfig(OutboundConfig config)
        => new()
        {
            Tag = config.Tag,
            Enabled = config.Enabled,
            Protocol = config.Protocol,
            Via = config.Via,
            ViaCidr = config.ViaCidr,
            TargetStrategy = config.TargetStrategy,
            ProxyOutboundTag = config.ProxyOutboundTag,
            MultiplexEnabled = config.MultiplexSettings.Enabled,
            MultiplexConcurrency = Math.Clamp(config.MultiplexSettings.Concurrency, 0, 1024),
            MultiplexXudpConcurrency = Math.Clamp(config.MultiplexSettings.XudpConcurrency, 0, 1024),
            MultiplexXudpProxyUdp443 = config.MultiplexSettings.XudpProxyUdp443,
            Transport = config.Transport,
            ServerHost = config.ServerHost,
            ServerPort = Math.Clamp(config.ServerPort, 0, 65535),
            ServerName = config.ServerName,
            WebSocketPath = config.WebSocketPath,
            WebSocketHeadersText = NodeFormValueCodec.FormatHeaderLines(config.WebSocketHeaders),
            WebSocketEarlyDataBytes = Math.Clamp(config.WebSocketEarlyDataBytes, 0, 65535),
            WebSocketHeartbeatPeriodSeconds = Math.Clamp(config.WebSocketHeartbeatPeriodSeconds, 0, 3600),
            ApplicationProtocols = NodeFormValueCodec.JoinCsv(config.ApplicationProtocols),
            Password = config.Password,
            ConnectTimeoutSeconds = Math.Clamp(config.ConnectTimeoutSeconds, 0, 600),
            HandshakeTimeoutSeconds = Math.Clamp(config.HandshakeTimeoutSeconds, 0, 600),
            SkipCertificateValidation = config.SkipCertificateValidation
        };
}

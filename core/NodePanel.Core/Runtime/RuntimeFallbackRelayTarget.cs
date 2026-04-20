using System.Net;

namespace NodePanel.Core.Runtime;

public sealed record RuntimeFallbackRelayTarget(
    string Type,
    string Destination,
    int ProxyProtocolVersion,
    RuntimeFallbackLimitOptions LimitUpload,
    RuntimeFallbackLimitOptions LimitDownload,
    EndPoint? RemoteEndPoint,
    EndPoint? LocalEndPoint);


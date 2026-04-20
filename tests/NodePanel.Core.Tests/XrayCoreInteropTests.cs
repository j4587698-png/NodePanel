using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using NodePanel.Core.Protocol;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

[Trait("Category", "Interop")]
public sealed class XrayCoreInteropTests
{
    private static readonly TimeSpan GoHelperTestTimeout = TimeSpan.FromSeconds(90);
    private const string UserId = "interop-user";
    private const string UserUuid = "33333333-3333-3333-3333-333333333333";
    private const string TrojanSharedPassword = "interop-password";
    private const string VlessGrpcServiceName = "/vless/plain/Tun|TunMulti";
    private const string VmessGrpcServiceName = "/vmess/plain/Tun|TunMulti";
    private const string TrojanGrpcServiceName = "/trojan/plain/Tun|TunMulti";
    private const string V2rayWebSocketHost = "ws.example.com";
    private const string V2rayWebSocketPath = "/v2ray-ws";
    private const string V2rayHttpUpgradeHost = "upgrade.example.com";
    private const string V2rayHttpUpgradePath = "/v2ray-upgrade";
    private const string V2raySplitHttpHost = "xhttp.example.com";
    private const string V2raySplitHttpPath = "/v2ray-xhttp";
    private const string InteropTlsServerName = "tls.example.com";
    private const string InteropRealityServerName = "www.google.com";
    private const string InteropRealityPrivateKey = "aGSYystUbf59_9_6LKRxD27rmSW_-2_nyd9YG_Gwbks";
    private const string InteropRealityPublicKey = "E59WjnvZcQMu7tR7_BgyhycuEdBS-CtKxfImRCdAvFM";
    private const string InteropRealityShortId = "0123456789abcdef";
    private const string TrojanWebSocketHost = "trojan-ws.example.com";
    private const string TrojanWebSocketPath = "/trojan-ws";
    private const string TrojanHttpUpgradeHost = "edge.example.com";
    private const string TrojanHttpUpgradePath = "/upgrade";
    private const string TrojanSplitHttpHost = "trojan-xhttp.example.com";
    private const string TrojanSplitHttpPath = "/trojan-xhttp";

    [Fact]
    public async Task DefaultRuntime_vless_outbound_can_connect_to_xray_core_vless_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(GoHelperTestTimeout);
        var tempDirectory = CreateInteropTempDirectory("dotnet-client-to-xray");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var xrayPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        XrayProcessHandle? xray = null;

        try
        {
            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "vless-server.json",
                CreateXrayVlessServerConfig(xrayPort),
                xrayPort,
                lifetimeCts.Token);

            await runtime.StartAsync(
                CreateDotnetVlessClientPlan(
                    revision: 1,
                    localSocksPort: socksPort,
                    serverPort: xrayPort),
                lifetimeCts.Token);

            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-dotnet-client-to-xray", lifetimeCts.Token);

            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw CreateInteropFailure(
                "Xray-dotnet client -> xray-core server 互通失败。",
                runtime,
                xray,
                ex);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task DefaultRuntime_vless_tls_outbound_can_connect_to_xray_core_vless_tls_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(GoHelperTestTimeout);
        var tempDirectory = CreateInteropTempDirectory("dotnet-vless-tls-client-to-xray");
        var certificateFile = Path.Combine(tempDirectory, "vless-tls-cert.pem");
        var keyFile = Path.Combine(tempDirectory, "vless-tls-key.pem");
        using var certificate = CreateInteropServerCertificate(InteropTlsServerName);
        await WriteXrayCertificateFilesAsync(certificate, certificateFile, keyFile, lifetimeCts.Token);
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var xrayPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xray = null;

        try
        {
            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "vless-tls-server.json",
                CreateXrayVlessServerConfig(
                    xrayPort,
                    security: RuntimeInternetSecurityTypes.Tls,
                    certificateFile: certificateFile,
                    keyFile: keyFile),
                xrayPort,
                lifetimeCts.Token);

            await runtime.StartAsync(
                CreateDotnetVlessClientPlan(
                    revision: 1,
                    localSocksPort: socksPort,
                    serverPort: xrayPort,
                    transport: VlessOutboundTransports.Tls,
                    serverName: InteropTlsServerName,
                    skipCertificateValidation: true),
                lifetimeCts.Token);

            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-dotnet-vless-tls-client-to-xray", lifetimeCts.Token);

            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw CreateInteropFailure(
                "Xray-dotnet VLESS tls client -> xray-core VLESS tls server interop failed.",
                runtime,
                xray,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task DefaultRuntime_vless_mkcp_outbound_can_connect_to_xray_core_vless_mkcp_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(GoHelperTestTimeout);
        var tempDirectory = CreateInteropTempDirectory("dotnet-vless-mkcp-client-to-xray");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var xrayPort = GetAvailableUdpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xray = null;

        try
        {
            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "vless-mkcp-server.json",
                CreateXrayVlessServerConfig(
                    xrayPort,
                    network: RuntimeInternetTransportProtocols.Mkcp),
                xrayPort,
                lifetimeCts.Token,
                listenNetwork: RuntimeInternetTransportProtocols.Mkcp);

            await runtime.StartAsync(
                CreateDotnetVlessClientPlan(
                    revision: 1,
                    localSocksPort: socksPort,
                    serverPort: xrayPort,
                    transport: RuntimeInternetTransportProtocols.Mkcp),
                lifetimeCts.Token);

            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-dotnet-vless-mkcp-client-to-xray", lifetimeCts.Token);

            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw CreateInteropFailure(
                "Xray-dotnet VLESS mkcp client -> xray-core VLESS mkcp server interop failed.",
                runtime,
                xray,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task DefaultRuntime_vless_ws_outbound_can_connect_to_xray_core_vless_ws_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(GoHelperTestTimeout);
        var tempDirectory = CreateInteropTempDirectory("dotnet-vless-ws-client-to-xray");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var xrayPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xray = null;

        try
        {
            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "vless-ws-server.json",
                CreateXrayVlessServerConfig(
                    xrayPort,
                    network: "ws",
                    host: V2rayWebSocketHost,
                    path: V2rayWebSocketPath),
                xrayPort,
                lifetimeCts.Token);

            await runtime.StartAsync(
                CreateDotnetVlessClientPlan(
                    revision: 1,
                    localSocksPort: socksPort,
                    serverPort: xrayPort,
                    transport: VlessOutboundTransports.Ws,
                    host: V2rayWebSocketHost,
                    path: V2rayWebSocketPath),
                lifetimeCts.Token);

            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-dotnet-vless-ws-client-to-xray", lifetimeCts.Token);

            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw CreateInteropFailure(
                "Xray-dotnet VLESS ws client -> xray-core VLESS ws server interop failed.",
                runtime,
                xray,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task DefaultRuntime_vless_httpupgrade_outbound_can_connect_to_xray_core_vless_httpupgrade_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(GoHelperTestTimeout);
        var tempDirectory = CreateInteropTempDirectory("dotnet-vless-httpupgrade-client-to-xray");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var xrayPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xray = null;

        try
        {
            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "vless-httpupgrade-server.json",
                CreateXrayVlessServerConfig(
                    xrayPort,
                    network: "httpupgrade",
                    host: V2rayHttpUpgradeHost,
                    path: V2rayHttpUpgradePath),
                xrayPort,
                lifetimeCts.Token);

            await runtime.StartAsync(
                CreateDotnetVlessClientPlan(
                    revision: 1,
                    localSocksPort: socksPort,
                    serverPort: xrayPort,
                    transport: VlessOutboundTransports.HttpUpgrade,
                    host: V2rayHttpUpgradeHost,
                    path: V2rayHttpUpgradePath),
                lifetimeCts.Token);

            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-dotnet-vless-httpupgrade-client-to-xray", lifetimeCts.Token);

            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw CreateInteropFailure(
                "Xray-dotnet VLESS httpupgrade client -> xray-core VLESS httpupgrade server interop failed.",
                runtime,
                xray,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task DefaultRuntime_vless_grpc_outbound_can_connect_to_xray_core_vless_grpc_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(GoHelperTestTimeout);
        var tempDirectory = CreateInteropTempDirectory("dotnet-vless-grpc-client-to-xray");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var xrayPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xray = null;

        try
        {
            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "vless-grpc-server.json",
                CreateXrayVlessServerConfig(
                    xrayPort,
                    network: "grpc",
                    grpcServiceName: VlessGrpcServiceName),
                xrayPort,
                lifetimeCts.Token);

            await runtime.StartAsync(
                CreateDotnetVlessClientPlan(
                    revision: 1,
                    localSocksPort: socksPort,
                    serverPort: xrayPort,
                    transport: VlessOutboundTransports.Grpc,
                    grpcServiceName: VlessGrpcServiceName),
                lifetimeCts.Token);

            xray.AssertStillRunning();

            await AssertEchoViaSocks5WithRetryAsync(
                socksPort,
                echoPort,
                "hello-dotnet-vless-grpc-client-to-xray",
                lifetimeCts.Token);

            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw CreateInteropFailure(
                "Xray-dotnet VLESS grpc client -> xray-core VLESS grpc server interop failed.",
                runtime,
                xray,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task DefaultRuntime_vless_splithttp_outbound_can_connect_to_xray_core_vless_splithttp_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(GoHelperTestTimeout);
        var tempDirectory = CreateInteropTempDirectory("dotnet-vless-splithttp-client-to-xray");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var xrayPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xray = null;

        try
        {
            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "vless-splithttp-server.json",
                CreateXrayVlessServerConfig(
                    xrayPort,
                    network: "splithttp",
                    host: V2raySplitHttpHost,
                    path: V2raySplitHttpPath),
                xrayPort,
                lifetimeCts.Token);

            await runtime.StartAsync(
                CreateDotnetVlessClientPlan(
                    revision: 1,
                    localSocksPort: socksPort,
                    serverPort: xrayPort,
                    transport: VlessOutboundTransports.SplitHttp,
                    host: V2raySplitHttpHost,
                    path: V2raySplitHttpPath),
                lifetimeCts.Token);

            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-dotnet-vless-splithttp-client-to-xray", lifetimeCts.Token);

            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw CreateInteropFailure(
                "Xray-dotnet VLESS splithttp client -> xray-core VLESS splithttp server interop failed.",
                runtime,
                xray,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task Vless_outbound_handler_can_connect_to_xray_core_vless_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(GoHelperTestTimeout);
        var tempDirectory = CreateInteropTempDirectory("vless-handler-to-xray");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var xrayPort = GetAvailableTcpPort();
        XrayProcessHandle? xray = null;
        VlessOutboundHandler? handler = null;

        try
        {
            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "vless-server.json",
                CreateXrayVlessServerConfig(xrayPort),
                xrayPort,
                lifetimeCts.Token);

            var dispatcher = CreateDirectVlessDispatcher(
                new VlessOutboundSettings
                {
                    Tag = "vless-out",
                    ServerHost = IPAddress.Loopback.ToString(),
                    ServerPort = xrayPort,
                    Transport = VlessOutboundTransports.Tcp,
                    TransportSecurity = RuntimeInternetSecurityTypes.None,
                    UserUuid = UserUuid
                },
                out handler);

            await using var outbound = await dispatcher.DispatchTcpAsync(
                new DispatchContext
                {
                    InboundProtocol = InboundProtocols.Vless,
                    InboundTag = "edge",
                    UserId = UserId,
                    ConnectTimeoutSeconds = 5
                },
                new DispatchDestination
                {
                    Host = "127.0.0.1",
                    Port = echoPort,
                    Network = DispatchNetwork.Tcp
                },
                lifetimeCts.Token);

            xray.AssertStillRunning();
            await AssertEchoAsync(outbound, "hello-vless-handler-to-xray", lifetimeCts.Token);
            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw new InvalidOperationException(
                $"VlessOutboundHandler -> xray-core VLESS inbound 互通失败。{Environment.NewLine}{xray.GetDiagnostics()}",
                ex);
        }
        finally
        {
            if (handler is not null)
            {
                await handler.DisposeAsync();
            }

            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task DefaultRuntime_vless_reality_vision_outbound_can_connect_to_xray_core_vless_reality_vision_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(GoHelperTestTimeout);
        var tempDirectory = CreateInteropTempDirectory("dotnet-vless-reality-vision-client-to-xray");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var xrayPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xray = null;

        try
        {
            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "vless-reality-vision-server.json",
                CreateXrayVlessServerConfig(
                    xrayPort,
                    security: RuntimeInternetSecurityTypes.Reality,
                    flow: VlessFlowTypes.Vision,
                    realitySettings: CreateXrayRealityServerSettings()),
                xrayPort,
                lifetimeCts.Token);

            await runtime.StartAsync(
                CreateDotnetVlessClientPlan(
                    revision: 1,
                    localSocksPort: socksPort,
                    serverPort: xrayPort,
                    transport: VlessOutboundTransports.Tcp,
                    transportSecurity: RuntimeInternetSecurityTypes.Reality,
                    serverName: InteropRealityServerName,
                    realityOptions: CreateInteropRealityClientOptions(),
                    flow: VlessFlowTypes.Vision),
                lifetimeCts.Token);

            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-dotnet-vless-reality-vision-client-to-xray", lifetimeCts.Token);

            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw CreateInteropFailure(
                "Xray-dotnet VLESS REALITY Vision client -> xray-core VLESS REALITY Vision server interop failed.",
                runtime,
                xray,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task Xray_core_vless_outbound_can_connect_to_default_runtime_vless_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(GoHelperTestTimeout);
        var tempDirectory = CreateInteropTempDirectory("xray-client-to-dotnet");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var vlessPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        XrayProcessHandle? xray = null;

        try
        {
            await runtime.StartAsync(
                CreateDotnetVlessServerPlan(
                    revision: 1,
                    inboundPort: vlessPort),
                lifetimeCts.Token);

            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "socks-to-vless.json",
                CreateXraySocksToVlessClientConfig(
                    socksPort,
                    vlessPort),
                socksPort,
                lifetimeCts.Token);

            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-xray-client-to-dotnet", lifetimeCts.Token);

            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw CreateInteropFailure(
                "xray-core client -> Xray-dotnet server 互通失败。",
                runtime,
                xray,
                ex);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task Xray_core_vless_tls_outbound_can_connect_to_default_runtime_vless_tls_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(GoHelperTestTimeout);
        var tempDirectory = CreateInteropTempDirectory("xray-vless-tls-client-to-dotnet");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var vlessPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        using var certificate = CreateInteropServerCertificate(InteropTlsServerName);
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xray = null;

        try
        {
            await runtime.StartAsync(
                CreateDotnetVlessServerPlan(
                    revision: 1,
                    inboundPort: vlessPort,
                    transportSecurity: RuntimeInternetSecurityTypes.Tls,
                    tls: new RuntimeTlsOptions
                    {
                        Certificate = certificate
                    }),
                lifetimeCts.Token);

            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "socks-to-vless-tls.json",
                CreateXraySocksToVlessClientConfig(
                    socksPort,
                    vlessPort,
                    security: RuntimeInternetSecurityTypes.Tls,
                    serverName: InteropTlsServerName,
                    allowInsecure: true),
                socksPort,
                lifetimeCts.Token);

            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-xray-vless-tls-client-to-dotnet", lifetimeCts.Token);

            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw CreateInteropFailure(
                "xray-core VLESS tls client -> Xray-dotnet VLESS tls server interop failed.",
                runtime,
                xray,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task Xray_core_vless_tls_hellogolang_outbound_emits_expected_clienthello_shape()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(GoHelperTestTimeout);
        var tempDirectory = CreateInteropTempDirectory("xray-vless-tls-hellogolang-clienthello");
        var capturePort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        using var listener = new TcpListener(IPAddress.Loopback, capturePort);
        listener.Start();
        XrayProcessHandle? xray = null;

        try
        {
            var clientHelloTask = CaptureTlsClientHelloAsync(listener, lifetimeCts.Token);

            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "socks-to-vless-tls-hellogolang-clienthello.json",
                CreateXraySocksToVlessClientConfig(
                    socksPort,
                    capturePort,
                    security: RuntimeInternetSecurityTypes.Tls,
                    serverName: InteropTlsServerName,
                    allowInsecure: true,
                    fingerprint: "hellogolang"),
                socksPort,
                lifetimeCts.Token);

            xray.AssertStillRunning();

            using var trigger = await InitiateSocks5ConnectAsync(socksPort, destinationPort: 80, lifetimeCts.Token);
            var capture = await clientHelloTask;

            Assert.NotNull(capture.Metadata);
            Assert.Equal(GetExpectedGolangCipherSuites(includeTls12CipherSuites: true), capture.Metadata!.CipherSuites);
            Assert.Equal(GetExpectedGolangExtensions(), capture.Metadata.Extensions);
            Assert.Equal(GetExpectedGolangSupportedGroups(), capture.Metadata.SupportedGroups);

            var keyShareExtension = capture.Document.Extensions.Single(static extension => extension.Type == 0x0033);
            var keyShares = ParseKeyShares(keyShareExtension.Payload);
            if (RuntimeX25519MlKem768.IsSupported)
            {
                Assert.Equal(
                    [RuntimeTlsNamedGroups.X25519MLKem768, RuntimeTlsNamedGroups.X25519],
                    keyShares.Select(static entry => entry.Group).ToArray());
                Assert.True(
                    keyShares[0].KeyExchange
                        .AsSpan(keyShares[0].KeyExchange.Length - RuntimeX25519.KeyLength)
                        .SequenceEqual(keyShares[1].KeyExchange));
            }
            else
            {
                Assert.Single(keyShares);
                Assert.Equal(RuntimeTlsNamedGroups.X25519, keyShares[0].Group);
            }

            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw new InvalidOperationException(
                "xray-core VLESS tls hellogolang clienthello capture failed." + Environment.NewLine +
                xray.GetDiagnostics(),
                ex);
        }
        finally
        {
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            listener.Stop();
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task Xray_core_vless_tls_default_outbound_emits_expected_clienthello_shape()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(GoHelperTestTimeout);
        var tempDirectory = CreateInteropTempDirectory("xray-vless-tls-default-clienthello");
        var capturePort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        using var listener = new TcpListener(IPAddress.Loopback, capturePort);
        listener.Start();
        XrayProcessHandle? xray = null;

        try
        {
            var clientHelloTask = CaptureTlsClientHelloAsync(listener, lifetimeCts.Token);

            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "socks-to-vless-tls-default-clienthello.json",
                CreateXraySocksToVlessClientConfig(
                    socksPort,
                    capturePort,
                    security: RuntimeInternetSecurityTypes.Tls,
                    serverName: InteropTlsServerName,
                    allowInsecure: true),
                socksPort,
                lifetimeCts.Token);

            xray.AssertStillRunning();

            using var trigger = await InitiateSocks5ConnectAsync(socksPort, destinationPort: 80, lifetimeCts.Token);
            var capture = await clientHelloTask;
            var identifiedFingerprint = IdentifyModernChromeFingerprint(capture);

            Assert.True(
                MatchesChromeFingerprintShape(capture, "hellochrome_auto", allowProtocolConstraints: true),
                "Expected xray-core default TLS fingerprint to match HelloChrome_Auto." + Environment.NewLine +
                DescribeCapturedClientHello(capture, identifiedFingerprint));

            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw new InvalidOperationException(
                "xray-core VLESS tls default clienthello capture failed." + Environment.NewLine +
                xray.GetDiagnostics(),
                ex);
        }
        finally
        {
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            listener.Stop();
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task Xray_core_vless_mkcp_outbound_can_connect_to_default_runtime_vless_mkcp_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("xray-vless-mkcp-client-to-dotnet");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var vlessPort = GetAvailableUdpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xray = null;

        try
        {
            await runtime.StartAsync(
                CreateDotnetVlessServerPlan(
                    revision: 1,
                    inboundPort: vlessPort,
                    transportProtocol: RuntimeInternetTransportProtocols.Mkcp),
                lifetimeCts.Token);

            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "socks-to-vless-mkcp.json",
                CreateXraySocksToVlessClientConfig(
                    socksPort,
                    vlessPort,
                    network: RuntimeInternetTransportProtocols.Mkcp),
                socksPort,
                lifetimeCts.Token);

            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-xray-vless-mkcp-client-to-dotnet", lifetimeCts.Token);

            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw CreateInteropFailure(
                "xray-core VLESS mkcp client -> Xray-dotnet VLESS mkcp server interop failed.",
                runtime,
                xray,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task Xray_core_vless_ws_outbound_can_connect_to_default_runtime_vless_ws_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("xray-vless-ws-client-to-dotnet");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var vlessPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xray = null;

        try
        {
            await runtime.StartAsync(
                CreateDotnetVlessServerPlan(
                    revision: 1,
                    inboundPort: vlessPort,
                    transportProtocol: RuntimeInternetTransportProtocols.Ws,
                    host: V2rayWebSocketHost,
                    path: V2rayWebSocketPath),
                lifetimeCts.Token);

            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "socks-to-vless-ws.json",
                CreateXraySocksToVlessClientConfig(
                    socksPort,
                    vlessPort,
                    network: "ws",
                    host: V2rayWebSocketHost,
                    path: V2rayWebSocketPath),
                socksPort,
                lifetimeCts.Token);

            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-xray-vless-ws-client-to-dotnet", lifetimeCts.Token);

            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw CreateInteropFailure(
                "xray-core VLESS ws client -> Xray-dotnet VLESS ws server interop failed.",
                runtime,
                xray,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task Xray_core_vless_httpupgrade_outbound_can_connect_to_default_runtime_vless_httpupgrade_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("xray-vless-httpupgrade-client-to-dotnet");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var vlessPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xray = null;

        try
        {
            await runtime.StartAsync(
                CreateDotnetVlessServerPlan(
                    revision: 1,
                    inboundPort: vlessPort,
                    transportProtocol: RuntimeInternetTransportProtocols.HttpUpgrade,
                    host: V2rayHttpUpgradeHost,
                    path: V2rayHttpUpgradePath),
                lifetimeCts.Token);

            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "socks-to-vless-httpupgrade.json",
                CreateXraySocksToVlessClientConfig(
                    socksPort,
                    vlessPort,
                    network: "httpupgrade",
                    host: V2rayHttpUpgradeHost,
                    path: V2rayHttpUpgradePath),
                socksPort,
                lifetimeCts.Token);

            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-xray-vless-httpupgrade-client-to-dotnet", lifetimeCts.Token);

            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw CreateInteropFailure(
                "xray-core VLESS httpupgrade client -> Xray-dotnet VLESS httpupgrade server interop failed.",
                runtime,
                xray,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task Xray_core_vless_grpc_outbound_can_connect_to_default_runtime_vless_grpc_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("xray-vless-grpc-client-to-dotnet");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var vlessPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xray = null;

        try
        {
            await runtime.StartAsync(
                CreateDotnetVlessServerPlan(
                    revision: 1,
                    inboundPort: vlessPort,
                    transportProtocol: RuntimeInternetTransportProtocols.Grpc,
                    grpcServiceName: VlessGrpcServiceName),
                lifetimeCts.Token);

            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "socks-to-vless-grpc.json",
                CreateXraySocksToVlessClientConfig(
                    socksPort,
                    vlessPort,
                    network: "grpc",
                    grpcServiceName: VlessGrpcServiceName),
                socksPort,
                lifetimeCts.Token);

            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-xray-vless-grpc-client-to-dotnet", lifetimeCts.Token);

            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw CreateInteropFailure(
                "xray-core VLESS grpc client -> Xray-dotnet VLESS grpc server interop failed.",
                runtime,
                xray,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task Xray_core_vless_splithttp_outbound_can_connect_to_default_runtime_vless_splithttp_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("xray-vless-splithttp-client-to-dotnet");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var vlessPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xray = null;

        try
        {
            await runtime.StartAsync(
                CreateDotnetVlessServerPlan(
                    revision: 1,
                    inboundPort: vlessPort,
                    transportProtocol: RuntimeInternetTransportProtocols.SplitHttp,
                    host: V2raySplitHttpHost,
                    path: V2raySplitHttpPath),
                lifetimeCts.Token);

            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "socks-to-vless-splithttp.json",
                CreateXraySocksToVlessClientConfig(
                    socksPort,
                    vlessPort,
                    network: "splithttp",
                    host: V2raySplitHttpHost,
                    path: V2raySplitHttpPath),
                socksPort,
                lifetimeCts.Token);

            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-xray-vless-splithttp-client-to-dotnet", lifetimeCts.Token);

            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw CreateInteropFailure(
                "xray-core VLESS splithttp client -> Xray-dotnet VLESS splithttp server interop failed.",
                runtime,
                xray,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task Xray_core_vless_reality_vision_outbound_can_connect_to_default_runtime_vless_reality_vision_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(GoHelperTestTimeout);
        var tempDirectory = CreateInteropTempDirectory("xray-vless-reality-vision-client-to-dotnet");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var vlessPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xray = null;

        try
        {
            await runtime.StartAsync(
                CreateDotnetVlessServerPlan(
                    revision: 1,
                    inboundPort: vlessPort,
                    transportSecurity: RuntimeInternetSecurityTypes.Reality,
                    reality: CreateInteropRealityServerOptions(),
                    userFlow: VlessFlowTypes.Vision),
                lifetimeCts.Token);

            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "socks-to-vless-reality-vision.json",
                CreateXraySocksToVlessClientConfig(
                    socksPort,
                    vlessPort,
                    security: RuntimeInternetSecurityTypes.Reality,
                    serverName: InteropRealityServerName,
                    flow: VlessFlowTypes.Vision,
                    realitySettings: CreateXrayRealityClientSettings()),
                socksPort,
                lifetimeCts.Token);

            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-xray-vless-reality-vision-client-to-dotnet", lifetimeCts.Token);

            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw CreateInteropFailure(
                "xray-core VLESS REALITY Vision client -> Xray-dotnet VLESS REALITY Vision server interop failed.",
                runtime,
                xray,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task DefaultRuntime_vmess_outbound_can_connect_to_xray_core_vmess_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(GoHelperTestTimeout);
        var tempDirectory = CreateInteropTempDirectory("dotnet-vmess-client-to-xray");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var xrayPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        XrayProcessHandle? xray = null;

        try
        {
            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "vmess-server.json",
                CreateXrayVmessServerConfig(xrayPort),
                xrayPort,
                lifetimeCts.Token);

            await runtime.StartAsync(
                CreateDotnetVmessClientPlan(
                    revision: 1,
                    localSocksPort: socksPort,
                    serverPort: xrayPort),
                lifetimeCts.Token);

            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-dotnet-vmess-client-to-xray", lifetimeCts.Token);

            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw CreateInteropFailure(
                "Xray-dotnet VMess client -> xray-core VMess server 互通失败。",
                runtime,
                xray,
                ex);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task DefaultRuntime_vmess_tls_outbound_can_connect_to_xray_core_vmess_tls_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(GoHelperTestTimeout);
        var tempDirectory = CreateInteropTempDirectory("dotnet-vmess-tls-client-to-xray");
        var certificateFile = Path.Combine(tempDirectory, "vmess-tls-cert.pem");
        var keyFile = Path.Combine(tempDirectory, "vmess-tls-key.pem");
        using var certificate = CreateInteropServerCertificate(InteropTlsServerName);
        await WriteXrayCertificateFilesAsync(certificate, certificateFile, keyFile, lifetimeCts.Token);
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var xrayPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xray = null;

        try
        {
            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "vmess-tls-server.json",
                CreateXrayVmessServerConfig(
                    xrayPort,
                    security: RuntimeInternetSecurityTypes.Tls,
                    certificateFile: certificateFile,
                    keyFile: keyFile),
                xrayPort,
                lifetimeCts.Token);

            await runtime.StartAsync(
                CreateDotnetVmessClientPlan(
                    revision: 1,
                    localSocksPort: socksPort,
                    serverPort: xrayPort,
                    transport: VmessOutboundTransports.Tls,
                    serverName: InteropTlsServerName,
                    skipCertificateValidation: true),
                lifetimeCts.Token);

            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-dotnet-vmess-tls-client-to-xray", lifetimeCts.Token);

            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw CreateInteropFailure(
                "Xray-dotnet VMess tls client -> xray-core VMess tls server interop failed.",
                runtime,
                xray,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task DefaultRuntime_vmess_mkcp_outbound_can_connect_to_xray_core_vmess_mkcp_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(GoHelperTestTimeout);
        var tempDirectory = CreateInteropTempDirectory("dotnet-vmess-mkcp-client-to-xray");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var xrayPort = GetAvailableUdpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xray = null;

        try
        {
            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "vmess-mkcp-server.json",
                CreateXrayVmessServerConfig(
                    xrayPort,
                    network: RuntimeInternetTransportProtocols.Mkcp),
                xrayPort,
                lifetimeCts.Token,
                listenNetwork: RuntimeInternetTransportProtocols.Mkcp);

            await runtime.StartAsync(
                CreateDotnetVmessClientPlan(
                    revision: 1,
                    localSocksPort: socksPort,
                    serverPort: xrayPort,
                    transport: RuntimeInternetTransportProtocols.Mkcp),
                lifetimeCts.Token);

            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-dotnet-vmess-mkcp-client-to-xray", lifetimeCts.Token);

            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw CreateInteropFailure(
                "Xray-dotnet VMess mkcp client -> xray-core VMess mkcp server interop failed.",
                runtime,
                xray,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task DefaultRuntime_vmess_ws_outbound_can_connect_to_xray_core_vmess_ws_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(GoHelperTestTimeout);
        var tempDirectory = CreateInteropTempDirectory("dotnet-vmess-ws-client-to-xray");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var xrayPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xray = null;

        try
        {
            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "vmess-ws-server.json",
                CreateXrayVmessServerConfig(
                    xrayPort,
                    network: "ws",
                    host: V2rayWebSocketHost,
                    path: V2rayWebSocketPath),
                xrayPort,
                lifetimeCts.Token);

            await runtime.StartAsync(
                CreateDotnetVmessClientPlan(
                    revision: 1,
                    localSocksPort: socksPort,
                    serverPort: xrayPort,
                    transport: VmessOutboundTransports.Ws,
                    host: V2rayWebSocketHost,
                    path: V2rayWebSocketPath),
                lifetimeCts.Token);

            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-dotnet-vmess-ws-client-to-xray", lifetimeCts.Token);

            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw CreateInteropFailure(
                "Xray-dotnet VMess ws client -> xray-core VMess ws server interop failed.",
                runtime,
                xray,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task DefaultRuntime_vmess_httpupgrade_outbound_can_connect_to_xray_core_vmess_httpupgrade_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(GoHelperTestTimeout);
        var tempDirectory = CreateInteropTempDirectory("dotnet-vmess-httpupgrade-client-to-xray");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var xrayPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xray = null;

        try
        {
            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "vmess-httpupgrade-server.json",
                CreateXrayVmessServerConfig(
                    xrayPort,
                    network: "httpupgrade",
                    host: V2rayHttpUpgradeHost,
                    path: V2rayHttpUpgradePath),
                xrayPort,
                lifetimeCts.Token);

            await runtime.StartAsync(
                CreateDotnetVmessClientPlan(
                    revision: 1,
                    localSocksPort: socksPort,
                    serverPort: xrayPort,
                    transport: VmessOutboundTransports.HttpUpgrade,
                    host: V2rayHttpUpgradeHost,
                    path: V2rayHttpUpgradePath),
                lifetimeCts.Token);

            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-dotnet-vmess-httpupgrade-client-to-xray", lifetimeCts.Token);

            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw CreateInteropFailure(
                "Xray-dotnet VMess httpupgrade client -> xray-core VMess httpupgrade server interop failed.",
                runtime,
                xray,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task DefaultRuntime_vmess_grpc_outbound_can_connect_to_xray_core_vmess_grpc_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(GoHelperTestTimeout);
        var tempDirectory = CreateInteropTempDirectory("dotnet-vmess-grpc-client-to-xray");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var xrayPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xray = null;

        try
        {
            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "vmess-grpc-server.json",
                CreateXrayVmessServerConfig(
                    xrayPort,
                    network: "grpc",
                    grpcServiceName: VmessGrpcServiceName),
                xrayPort,
                lifetimeCts.Token);

            await runtime.StartAsync(
                CreateDotnetVmessClientPlan(
                    revision: 1,
                    localSocksPort: socksPort,
                    serverPort: xrayPort,
                    transport: VmessOutboundTransports.Grpc,
                    grpcServiceName: VmessGrpcServiceName),
                lifetimeCts.Token);

            xray.AssertStillRunning();

            await AssertEchoViaSocks5WithRetryAsync(
                socksPort,
                echoPort,
                "hello-dotnet-vmess-grpc-client-to-xray",
                lifetimeCts.Token);

            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw CreateInteropFailure(
                "Xray-dotnet VMess grpc client -> xray-core VMess grpc server interop failed.",
                runtime,
                xray,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task DefaultRuntime_vmess_splithttp_outbound_can_connect_to_xray_core_vmess_splithttp_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(GoHelperTestTimeout);
        var tempDirectory = CreateInteropTempDirectory("dotnet-vmess-splithttp-client-to-xray");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var xrayPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xray = null;

        try
        {
            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "vmess-splithttp-server.json",
                CreateXrayVmessServerConfig(
                    xrayPort,
                    network: "splithttp",
                    host: V2raySplitHttpHost,
                    path: V2raySplitHttpPath),
                xrayPort,
                lifetimeCts.Token);

            await runtime.StartAsync(
                CreateDotnetVmessClientPlan(
                    revision: 1,
                    localSocksPort: socksPort,
                    serverPort: xrayPort,
                    transport: VmessOutboundTransports.SplitHttp,
                    host: V2raySplitHttpHost,
                    path: V2raySplitHttpPath),
                lifetimeCts.Token);

            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-dotnet-vmess-splithttp-client-to-xray", lifetimeCts.Token);

            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw CreateInteropFailure(
                "Xray-dotnet VMess splithttp client -> xray-core VMess splithttp server interop failed.",
                runtime,
                xray,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task Vmess_outbound_handler_can_connect_to_xray_core_vmess_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(GoHelperTestTimeout);
        var tempDirectory = CreateInteropTempDirectory("vmess-handler-to-xray");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var xrayPort = GetAvailableTcpPort();
        XrayProcessHandle? xray = null;
        VmessOutboundHandler? handler = null;

        try
        {
            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "vmess-server.json",
                CreateXrayVmessServerConfig(xrayPort),
                xrayPort,
                lifetimeCts.Token);

            var dispatcher = CreateDirectVmessDispatcher(
                new VmessOutboundSettings
                {
                    Tag = "vmess-out",
                    ServerHost = IPAddress.Loopback.ToString(),
                    ServerPort = xrayPort,
                    Transport = VmessOutboundTransports.Tcp,
                    TransportSecurity = RuntimeInternetSecurityTypes.None,
                    UserUuid = UserUuid,
                    Security = VmessOutboundSecurityTypes.Aes128Gcm
                },
                out handler);

            await using var outbound = await dispatcher.DispatchTcpAsync(
                new DispatchContext
                {
                    InboundProtocol = InboundProtocols.Vmess,
                    InboundTag = "edge",
                    UserId = UserId,
                    ConnectTimeoutSeconds = 5
                },
                new DispatchDestination
                {
                    Host = "127.0.0.1",
                    Port = echoPort,
                    Network = DispatchNetwork.Tcp
                },
                lifetimeCts.Token);

            xray.AssertStillRunning();
            await AssertEchoAsync(outbound, "hello-vmess-handler-to-xray", lifetimeCts.Token);
            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw new InvalidOperationException(
                $"VmessOutboundHandler -> xray-core VMess inbound 互通失败。{Environment.NewLine}{xray.GetDiagnostics()}",
                ex);
        }
        finally
        {
            if (handler is not null)
            {
                await handler.DisposeAsync();
            }

            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task Xray_core_vmess_outbound_can_connect_to_default_runtime_vmess_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(GoHelperTestTimeout);
        var tempDirectory = CreateInteropTempDirectory("xray-vmess-client-to-dotnet");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var vmessPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        XrayProcessHandle? xray = null;

        try
        {
            await runtime.StartAsync(
                CreateDotnetVmessServerPlan(
                    revision: 1,
                    inboundPort: vmessPort),
                lifetimeCts.Token);

            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "socks-to-vmess.json",
                CreateXraySocksToVmessClientConfig(
                    socksPort,
                    vmessPort),
                socksPort,
                lifetimeCts.Token);

            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-xray-vmess-client-to-dotnet", lifetimeCts.Token);

            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw CreateInteropFailure(
                "xray-core VMess client -> Xray-dotnet VMess server 互通失败。",
                runtime,
                xray,
                ex);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task Xray_core_vmess_tls_outbound_can_connect_to_default_runtime_vmess_tls_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(GoHelperTestTimeout);
        var tempDirectory = CreateInteropTempDirectory("xray-vmess-tls-client-to-dotnet");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var vmessPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        using var certificate = CreateInteropServerCertificate(InteropTlsServerName);
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xray = null;

        try
        {
            await runtime.StartAsync(
                CreateDotnetVmessServerPlan(
                    revision: 1,
                    inboundPort: vmessPort,
                    transportSecurity: RuntimeInternetSecurityTypes.Tls,
                    tls: new RuntimeTlsOptions
                    {
                        Certificate = certificate
                    }),
                lifetimeCts.Token);

            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "socks-to-vmess-tls.json",
                CreateXraySocksToVmessClientConfig(
                    socksPort,
                    vmessPort,
                    security: RuntimeInternetSecurityTypes.Tls,
                    serverName: InteropTlsServerName,
                    allowInsecure: true),
                socksPort,
                lifetimeCts.Token);

            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-xray-vmess-tls-client-to-dotnet", lifetimeCts.Token);

            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw CreateInteropFailure(
                "xray-core VMess tls client -> Xray-dotnet VMess tls server interop failed.",
                runtime,
                xray,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task Xray_core_vmess_mkcp_outbound_can_connect_to_default_runtime_vmess_mkcp_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("xray-vmess-mkcp-client-to-dotnet");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var vmessPort = GetAvailableUdpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xray = null;

        try
        {
            await runtime.StartAsync(
                CreateDotnetVmessServerPlan(
                    revision: 1,
                    inboundPort: vmessPort,
                    transportProtocol: RuntimeInternetTransportProtocols.Mkcp),
                lifetimeCts.Token);

            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "socks-to-vmess-mkcp.json",
                CreateXraySocksToVmessClientConfig(
                    socksPort,
                    vmessPort,
                    network: RuntimeInternetTransportProtocols.Mkcp),
                socksPort,
                lifetimeCts.Token);

            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-xray-vmess-mkcp-client-to-dotnet", lifetimeCts.Token);

            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw CreateInteropFailure(
                "xray-core VMess mkcp client -> Xray-dotnet VMess mkcp server interop failed.",
                runtime,
                xray,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task Xray_core_vmess_ws_outbound_can_connect_to_default_runtime_vmess_ws_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(GoHelperTestTimeout);
        var tempDirectory = CreateInteropTempDirectory("xray-vmess-ws-client-to-dotnet");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var vmessPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xray = null;

        try
        {
            await runtime.StartAsync(
                CreateDotnetVmessServerPlan(
                    revision: 1,
                    inboundPort: vmessPort,
                    transportProtocol: RuntimeInternetTransportProtocols.Ws,
                    host: V2rayWebSocketHost,
                    path: V2rayWebSocketPath),
                lifetimeCts.Token);

            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "socks-to-vmess-ws.json",
                CreateXraySocksToVmessClientConfig(
                    socksPort,
                    vmessPort,
                    network: "ws",
                    host: V2rayWebSocketHost,
                    path: V2rayWebSocketPath),
                socksPort,
                lifetimeCts.Token);

            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-xray-vmess-ws-client-to-dotnet", lifetimeCts.Token);

            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw CreateInteropFailure(
                "xray-core VMess ws client -> Xray-dotnet VMess ws server interop failed.",
                runtime,
                xray,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task Xray_core_vmess_httpupgrade_outbound_can_connect_to_default_runtime_vmess_httpupgrade_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(GoHelperTestTimeout);
        var tempDirectory = CreateInteropTempDirectory("xray-vmess-httpupgrade-client-to-dotnet");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var vmessPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xray = null;

        try
        {
            await runtime.StartAsync(
                CreateDotnetVmessServerPlan(
                    revision: 1,
                    inboundPort: vmessPort,
                    transportProtocol: RuntimeInternetTransportProtocols.HttpUpgrade,
                    host: V2rayHttpUpgradeHost,
                    path: V2rayHttpUpgradePath),
                lifetimeCts.Token);

            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "socks-to-vmess-httpupgrade.json",
                CreateXraySocksToVmessClientConfig(
                    socksPort,
                    vmessPort,
                    network: "httpupgrade",
                    host: V2rayHttpUpgradeHost,
                    path: V2rayHttpUpgradePath),
                socksPort,
                lifetimeCts.Token);

            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-xray-vmess-httpupgrade-client-to-dotnet", lifetimeCts.Token);

            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw CreateInteropFailure(
                "xray-core VMess httpupgrade client -> Xray-dotnet VMess httpupgrade server interop failed.",
                runtime,
                xray,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task Xray_core_vmess_grpc_outbound_can_connect_to_default_runtime_vmess_grpc_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("xray-vmess-grpc-client-to-dotnet");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var vmessPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xray = null;

        try
        {
            await runtime.StartAsync(
                CreateDotnetVmessServerPlan(
                    revision: 1,
                    inboundPort: vmessPort,
                    transportProtocol: RuntimeInternetTransportProtocols.Grpc,
                    grpcServiceName: VmessGrpcServiceName),
                lifetimeCts.Token);

            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "socks-to-vmess-grpc.json",
                CreateXraySocksToVmessClientConfig(
                    socksPort,
                    vmessPort,
                    network: "grpc",
                    grpcServiceName: VmessGrpcServiceName),
                socksPort,
                lifetimeCts.Token);

            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-xray-vmess-grpc-client-to-dotnet", lifetimeCts.Token);

            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw CreateInteropFailure(
                "xray-core VMess grpc client -> Xray-dotnet VMess grpc server interop failed.",
                runtime,
                xray,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task Xray_core_vmess_splithttp_outbound_can_connect_to_default_runtime_vmess_splithttp_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("xray-vmess-splithttp-client-to-dotnet");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var vmessPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xray = null;

        try
        {
            await runtime.StartAsync(
                CreateDotnetVmessServerPlan(
                    revision: 1,
                    inboundPort: vmessPort,
                    transportProtocol: RuntimeInternetTransportProtocols.SplitHttp,
                    host: V2raySplitHttpHost,
                    path: V2raySplitHttpPath),
                lifetimeCts.Token);

            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "socks-to-vmess-splithttp.json",
                CreateXraySocksToVmessClientConfig(
                    socksPort,
                    vmessPort,
                    network: "splithttp",
                    host: V2raySplitHttpHost,
                    path: V2raySplitHttpPath),
                socksPort,
                lifetimeCts.Token);

            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-xray-vmess-splithttp-client-to-dotnet", lifetimeCts.Token);

            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw CreateInteropFailure(
                "xray-core VMess splithttp client -> Xray-dotnet VMess splithttp server interop failed.",
                runtime,
                xray,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task DefaultRuntime_vless_outbound_can_connect_to_xrayr_vless_inbound()
    {
        if (!TryGetXrayRExecutablePath(out var xrayrExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("dotnet-vless-client-to-xrayr");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var vlessPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        XrayProcessHandle? xrayr = null;
        await using var panel = await StartSspanelMockPanelAsync(
            nodeId: 31,
            CreateSspanelV2rayNodeInfoResponse(vlessPort, enableVless: true),
            [CreateSspanelV2rayUserResponse()],
            lifetimeCts.Token);

        try
        {
            xrayr = await StartXrayRAsync(
                xrayrExecutable,
                tempDirectory,
                "xrayr-vless-server.yml",
                CreateXrayRV2raySspanelConfig(panel.ApiHost, nodeId: 31),
                vlessPort,
                lifetimeCts.Token);

            await runtime.StartAsync(
                CreateDotnetVlessClientPlan(
                    revision: 1,
                    localSocksPort: socksPort,
                    serverPort: vlessPort),
                lifetimeCts.Token);

            xrayr.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-dotnet-vless-client-to-xrayr", lifetimeCts.Token);

            xrayr.AssertStillRunning();
        }
        catch (Exception ex) when (xrayr is not null)
        {
            throw CreateInteropFailure(
                "Xray-dotnet VLESS client -> XrayR VLESS server interop failed.",
                runtime,
                xrayr,
                ex);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xrayr is not null)
            {
                await xrayr.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task Xray_core_vless_outbound_can_connect_to_xrayr_vless_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable) ||
            !TryGetXrayRExecutablePath(out var xrayrExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("xray-vless-client-to-xrayr");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var vlessPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        XrayProcessHandle? xray = null;
        XrayProcessHandle? xrayr = null;
        await using var panel = await StartSspanelMockPanelAsync(
            nodeId: 32,
            CreateSspanelV2rayNodeInfoResponse(vlessPort, enableVless: true),
            [CreateSspanelV2rayUserResponse()],
            lifetimeCts.Token);

        try
        {
            xrayr = await StartXrayRAsync(
                xrayrExecutable,
                tempDirectory,
                "xrayr-vless-server.yml",
                CreateXrayRV2raySspanelConfig(panel.ApiHost, nodeId: 32),
                vlessPort,
                lifetimeCts.Token);

            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "socks-to-xrayr-vless.json",
                CreateXraySocksToVlessClientConfig(
                    socksPort,
                    vlessPort),
                socksPort,
                lifetimeCts.Token);

            xrayr.AssertStillRunning();
            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-xray-vless-client-to-xrayr", lifetimeCts.Token);

            xrayr.AssertStillRunning();
            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xrayr is not null || xray is not null)
        {
            var diagnostics = new StringBuilder();
            diagnostics.AppendLine("xray-core client -> XrayR VLESS server interop failed.");
            if (xrayr is not null)
            {
                diagnostics.AppendLine("xrayr:");
                diagnostics.AppendLine(xrayr.GetDiagnostics());
            }

            if (xray is not null)
            {
                diagnostics.AppendLine("xray-core:");
                diagnostics.AppendLine(xray.GetDiagnostics());
            }

            throw new InvalidOperationException(diagnostics.ToString().TrimEnd(), ex);
        }
        finally
        {
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            if (xrayr is not null)
            {
                await xrayr.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task DefaultRuntime_vless_tls_outbound_can_connect_to_xrayr_vless_tls_inbound()
    {
        if (!TryGetXrayRExecutablePath(out var xrayrExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("dotnet-vless-tls-client-to-xrayr");
        var certificateFile = Path.Combine(tempDirectory, "xrayr-vless-tls-cert.pem");
        var keyFile = Path.Combine(tempDirectory, "xrayr-vless-tls-key.pem");
        using var certificate = CreateInteropServerCertificate(InteropTlsServerName);
        await WriteXrayCertificateFilesAsync(certificate, certificateFile, keyFile, lifetimeCts.Token);
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var vlessPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xrayr = null;
        await using var panel = await StartSspanelMockPanelAsync(
            nodeId: 71,
            CreateSspanelV2rayNodeInfoResponse(
                vlessPort,
                enableVless: true,
                security: RuntimeInternetSecurityTypes.Tls),
            [CreateSspanelV2rayUserResponse()],
            lifetimeCts.Token);

        try
        {
            xrayr = await StartXrayRAsync(
                xrayrExecutable,
                tempDirectory,
                "xrayr-vless-tls-server.yml",
                CreateXrayRV2raySspanelConfig(
                    panel.ApiHost,
                    nodeId: 71,
                    certMode: "file",
                    certFile: certificateFile,
                    keyFile: keyFile),
                vlessPort,
                lifetimeCts.Token);

            await runtime.StartAsync(
                CreateDotnetVlessClientPlan(
                    revision: 1,
                    localSocksPort: socksPort,
                    serverPort: vlessPort,
                    transport: VlessOutboundTransports.Tls,
                    serverName: InteropTlsServerName,
                    skipCertificateValidation: true),
                lifetimeCts.Token);

            xrayr.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-dotnet-vless-tls-client-to-xrayr", lifetimeCts.Token);

            xrayr.AssertStillRunning();
        }
        catch (Exception ex) when (xrayr is not null)
        {
            throw CreateInteropFailure(
                "Xray-dotnet VLESS tls client -> XrayR VLESS tls server interop failed.",
                runtime,
                xrayr,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xrayr is not null)
            {
                await xrayr.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task Xray_core_vless_tls_outbound_can_connect_to_xrayr_vless_tls_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable) ||
            !TryGetXrayRExecutablePath(out var xrayrExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("xray-vless-tls-client-to-xrayr");
        var certificateFile = Path.Combine(tempDirectory, "xrayr-vless-tls-cert.pem");
        var keyFile = Path.Combine(tempDirectory, "xrayr-vless-tls-key.pem");
        using var certificate = CreateInteropServerCertificate(InteropTlsServerName);
        await WriteXrayCertificateFilesAsync(certificate, certificateFile, keyFile, lifetimeCts.Token);
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var vlessPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        XrayProcessHandle? xray = null;
        XrayProcessHandle? xrayr = null;
        await using var panel = await StartSspanelMockPanelAsync(
            nodeId: 72,
            CreateSspanelV2rayNodeInfoResponse(
                vlessPort,
                enableVless: true,
                security: RuntimeInternetSecurityTypes.Tls),
            [CreateSspanelV2rayUserResponse()],
            lifetimeCts.Token);

        try
        {
            xrayr = await StartXrayRAsync(
                xrayrExecutable,
                tempDirectory,
                "xrayr-vless-tls-server.yml",
                CreateXrayRV2raySspanelConfig(
                    panel.ApiHost,
                    nodeId: 72,
                    certMode: "file",
                    certFile: certificateFile,
                    keyFile: keyFile),
                vlessPort,
                lifetimeCts.Token);

            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "socks-to-xrayr-vless-tls.json",
                CreateXraySocksToVlessClientConfig(
                    socksPort,
                    vlessPort,
                    security: RuntimeInternetSecurityTypes.Tls,
                    serverName: InteropTlsServerName,
                    allowInsecure: true),
                socksPort,
                lifetimeCts.Token);

            xrayr.AssertStillRunning();
            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-xray-vless-tls-client-to-xrayr", lifetimeCts.Token);

            xrayr.AssertStillRunning();
            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xrayr is not null || xray is not null)
        {
            var diagnostics = new StringBuilder();
            diagnostics.AppendLine("xray-core tls client -> XrayR VLESS tls server interop failed.");
            if (xrayr is not null)
            {
                diagnostics.AppendLine("xrayr:");
                diagnostics.AppendLine(xrayr.GetDiagnostics());
            }

            if (xray is not null)
            {
                diagnostics.AppendLine("xray-core:");
                diagnostics.AppendLine(xray.GetDiagnostics());
            }

            throw new InvalidOperationException(diagnostics.ToString().TrimEnd(), ex);
        }
        finally
        {
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            if (xrayr is not null)
            {
                await xrayr.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task DefaultRuntime_vless_mkcp_outbound_can_connect_to_xrayr_vless_mkcp_inbound()
    {
        if (!TryGetXrayRExecutablePath(out var xrayrExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("dotnet-vless-mkcp-client-to-xrayr");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var vlessPort = GetAvailableUdpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xrayr = null;
        await using var panel = await StartSspanelMockPanelAsync(
            nodeId: 61,
            CreateSspanelV2rayNodeInfoResponse(
                vlessPort,
                enableVless: true,
                network: RuntimeInternetTransportProtocols.Mkcp),
            [CreateSspanelV2rayUserResponse()],
            lifetimeCts.Token);

        try
        {
            xrayr = await StartXrayRAsync(
                xrayrExecutable,
                tempDirectory,
                "xrayr-vless-mkcp-server.yml",
                CreateXrayRV2raySspanelConfig(panel.ApiHost, nodeId: 61),
                vlessPort,
                lifetimeCts.Token,
                listenNetwork: RuntimeInternetTransportProtocols.Mkcp);

            await runtime.StartAsync(
                CreateDotnetVlessClientPlan(
                    revision: 1,
                    localSocksPort: socksPort,
                    serverPort: vlessPort,
                    transport: RuntimeInternetTransportProtocols.Mkcp),
                lifetimeCts.Token);

            xrayr.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-dotnet-vless-mkcp-client-to-xrayr", lifetimeCts.Token);

            xrayr.AssertStillRunning();
        }
        catch (Exception ex) when (xrayr is not null)
        {
            throw CreateInteropFailure(
                "Xray-dotnet VLESS mkcp client -> XrayR VLESS mkcp server interop failed.",
                runtime,
                xrayr,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xrayr is not null)
            {
                await xrayr.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task Xray_core_vless_mkcp_outbound_can_connect_to_xrayr_vless_mkcp_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable) ||
            !TryGetXrayRExecutablePath(out var xrayrExecutable))
        {
            return;
        }

        if (!SupportsLegacyMkcpInteropWithXrayR(xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("xray-vless-mkcp-client-to-xrayr");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var vlessPort = GetAvailableUdpPort();
        var socksPort = GetAvailableTcpPort();
        XrayProcessHandle? xray = null;
        XrayProcessHandle? xrayr = null;
        await using var panel = await StartSspanelMockPanelAsync(
            nodeId: 62,
            CreateSspanelV2rayNodeInfoResponse(
                vlessPort,
                enableVless: true,
                network: RuntimeInternetTransportProtocols.Mkcp),
            [CreateSspanelV2rayUserResponse()],
            lifetimeCts.Token);

        try
        {
            xrayr = await StartXrayRAsync(
                xrayrExecutable,
                tempDirectory,
                "xrayr-vless-mkcp-server.yml",
                CreateXrayRV2raySspanelConfig(panel.ApiHost, nodeId: 62),
                vlessPort,
                lifetimeCts.Token,
                listenNetwork: RuntimeInternetTransportProtocols.Mkcp);

            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "socks-to-xrayr-vless-mkcp.json",
                CreateXraySocksToVlessClientConfig(
                    socksPort,
                    vlessPort,
                    network: RuntimeInternetTransportProtocols.Mkcp),
                socksPort,
                lifetimeCts.Token);

            xrayr.AssertStillRunning();
            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-xray-vless-mkcp-client-to-xrayr", lifetimeCts.Token);

            xrayr.AssertStillRunning();
            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xrayr is not null || xray is not null)
        {
            var diagnostics = new StringBuilder();
            diagnostics.AppendLine("xray-core mkcp client -> XrayR VLESS mkcp server interop failed.");
            if (xrayr is not null)
            {
                diagnostics.AppendLine("xrayr:");
                diagnostics.AppendLine(xrayr.GetDiagnostics());
            }

            if (xray is not null)
            {
                diagnostics.AppendLine("xray-core:");
                diagnostics.AppendLine(xray.GetDiagnostics());
            }

            throw new InvalidOperationException(diagnostics.ToString().TrimEnd(), ex);
        }
        finally
        {
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            if (xrayr is not null)
            {
                await xrayr.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task DefaultRuntime_vmess_outbound_can_connect_to_xrayr_vmess_inbound()
    {
        if (!TryGetXrayRExecutablePath(out var xrayrExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("dotnet-vmess-client-to-xrayr");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var vmessPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        XrayProcessHandle? xrayr = null;
        await using var panel = await StartSspanelMockPanelAsync(
            nodeId: 33,
            CreateSspanelV2rayNodeInfoResponse(vmessPort),
            [CreateSspanelV2rayUserResponse()],
            lifetimeCts.Token);

        try
        {
            xrayr = await StartXrayRAsync(
                xrayrExecutable,
                tempDirectory,
                "xrayr-vmess-server.yml",
                CreateXrayRV2raySspanelConfig(panel.ApiHost, nodeId: 33),
                vmessPort,
                lifetimeCts.Token);

            await runtime.StartAsync(
                CreateDotnetVmessClientPlan(
                    revision: 1,
                    localSocksPort: socksPort,
                    serverPort: vmessPort),
                lifetimeCts.Token);

            xrayr.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-dotnet-vmess-client-to-xrayr", lifetimeCts.Token);

            xrayr.AssertStillRunning();
        }
        catch (Exception ex) when (xrayr is not null)
        {
            throw CreateInteropFailure(
                "Xray-dotnet VMess client -> XrayR VMess server interop failed.",
                runtime,
                xrayr,
                ex);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xrayr is not null)
            {
                await xrayr.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task Xray_core_vmess_outbound_can_connect_to_xrayr_vmess_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable) ||
            !TryGetXrayRExecutablePath(out var xrayrExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("xray-vmess-client-to-xrayr");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var vmessPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        XrayProcessHandle? xray = null;
        XrayProcessHandle? xrayr = null;
        await using var panel = await StartSspanelMockPanelAsync(
            nodeId: 34,
            CreateSspanelV2rayNodeInfoResponse(vmessPort),
            [CreateSspanelV2rayUserResponse()],
            lifetimeCts.Token);

        try
        {
            xrayr = await StartXrayRAsync(
                xrayrExecutable,
                tempDirectory,
                "xrayr-vmess-server.yml",
                CreateXrayRV2raySspanelConfig(panel.ApiHost, nodeId: 34),
                vmessPort,
                lifetimeCts.Token);

            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "socks-to-xrayr-vmess.json",
                CreateXraySocksToVmessClientConfig(
                    socksPort,
                    vmessPort),
                socksPort,
                lifetimeCts.Token);

            xrayr.AssertStillRunning();
            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-xray-vmess-client-to-xrayr", lifetimeCts.Token);

            xrayr.AssertStillRunning();
            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xrayr is not null || xray is not null)
        {
            var diagnostics = new StringBuilder();
            diagnostics.AppendLine("xray-core client -> XrayR VMess server interop failed.");
            if (xrayr is not null)
            {
                diagnostics.AppendLine("xrayr:");
                diagnostics.AppendLine(xrayr.GetDiagnostics());
            }

            if (xray is not null)
            {
                diagnostics.AppendLine("xray-core:");
                diagnostics.AppendLine(xray.GetDiagnostics());
            }

            throw new InvalidOperationException(diagnostics.ToString().TrimEnd(), ex);
        }
        finally
        {
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            if (xrayr is not null)
            {
                await xrayr.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task DefaultRuntime_vmess_tls_outbound_can_connect_to_xrayr_vmess_tls_inbound()
    {
        if (!TryGetXrayRExecutablePath(out var xrayrExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("dotnet-vmess-tls-client-to-xrayr");
        var certificateFile = Path.Combine(tempDirectory, "xrayr-vmess-tls-cert.pem");
        var keyFile = Path.Combine(tempDirectory, "xrayr-vmess-tls-key.pem");
        using var certificate = CreateInteropServerCertificate(InteropTlsServerName);
        await WriteXrayCertificateFilesAsync(certificate, certificateFile, keyFile, lifetimeCts.Token);
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var vmessPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xrayr = null;
        await using var panel = await StartSspanelMockPanelAsync(
            nodeId: 73,
            CreateSspanelV2rayNodeInfoResponse(
                vmessPort,
                security: RuntimeInternetSecurityTypes.Tls),
            [CreateSspanelV2rayUserResponse()],
            lifetimeCts.Token);

        try
        {
            xrayr = await StartXrayRAsync(
                xrayrExecutable,
                tempDirectory,
                "xrayr-vmess-tls-server.yml",
                CreateXrayRV2raySspanelConfig(
                    panel.ApiHost,
                    nodeId: 73,
                    certMode: "file",
                    certFile: certificateFile,
                    keyFile: keyFile),
                vmessPort,
                lifetimeCts.Token);

            await runtime.StartAsync(
                CreateDotnetVmessClientPlan(
                    revision: 1,
                    localSocksPort: socksPort,
                    serverPort: vmessPort,
                    transport: VmessOutboundTransports.Tls,
                    serverName: InteropTlsServerName,
                    skipCertificateValidation: true),
                lifetimeCts.Token);

            xrayr.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-dotnet-vmess-tls-client-to-xrayr", lifetimeCts.Token);

            xrayr.AssertStillRunning();
        }
        catch (Exception ex) when (xrayr is not null)
        {
            throw CreateInteropFailure(
                "Xray-dotnet VMess tls client -> XrayR VMess tls server interop failed.",
                runtime,
                xrayr,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xrayr is not null)
            {
                await xrayr.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task Xray_core_vmess_tls_outbound_can_connect_to_xrayr_vmess_tls_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable) ||
            !TryGetXrayRExecutablePath(out var xrayrExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("xray-vmess-tls-client-to-xrayr");
        var certificateFile = Path.Combine(tempDirectory, "xrayr-vmess-tls-cert.pem");
        var keyFile = Path.Combine(tempDirectory, "xrayr-vmess-tls-key.pem");
        using var certificate = CreateInteropServerCertificate(InteropTlsServerName);
        await WriteXrayCertificateFilesAsync(certificate, certificateFile, keyFile, lifetimeCts.Token);
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var vmessPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        XrayProcessHandle? xray = null;
        XrayProcessHandle? xrayr = null;
        await using var panel = await StartSspanelMockPanelAsync(
            nodeId: 74,
            CreateSspanelV2rayNodeInfoResponse(
                vmessPort,
                security: RuntimeInternetSecurityTypes.Tls),
            [CreateSspanelV2rayUserResponse()],
            lifetimeCts.Token);

        try
        {
            xrayr = await StartXrayRAsync(
                xrayrExecutable,
                tempDirectory,
                "xrayr-vmess-tls-server.yml",
                CreateXrayRV2raySspanelConfig(
                    panel.ApiHost,
                    nodeId: 74,
                    certMode: "file",
                    certFile: certificateFile,
                    keyFile: keyFile),
                vmessPort,
                lifetimeCts.Token);

            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "socks-to-xrayr-vmess-tls.json",
                CreateXraySocksToVmessClientConfig(
                    socksPort,
                    vmessPort,
                    security: RuntimeInternetSecurityTypes.Tls,
                    serverName: InteropTlsServerName,
                    allowInsecure: true),
                socksPort,
                lifetimeCts.Token);

            xrayr.AssertStillRunning();
            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-xray-vmess-tls-client-to-xrayr", lifetimeCts.Token);

            xrayr.AssertStillRunning();
            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xrayr is not null || xray is not null)
        {
            var diagnostics = new StringBuilder();
            diagnostics.AppendLine("xray-core tls client -> XrayR VMess tls server interop failed.");
            if (xrayr is not null)
            {
                diagnostics.AppendLine("xrayr:");
                diagnostics.AppendLine(xrayr.GetDiagnostics());
            }

            if (xray is not null)
            {
                diagnostics.AppendLine("xray-core:");
                diagnostics.AppendLine(xray.GetDiagnostics());
            }

            throw new InvalidOperationException(diagnostics.ToString().TrimEnd(), ex);
        }
        finally
        {
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            if (xrayr is not null)
            {
                await xrayr.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task DefaultRuntime_vmess_mkcp_outbound_can_connect_to_xrayr_vmess_mkcp_inbound()
    {
        if (!TryGetXrayRExecutablePath(out var xrayrExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("dotnet-vmess-mkcp-client-to-xrayr");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var vmessPort = GetAvailableUdpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xrayr = null;
        await using var panel = await StartSspanelMockPanelAsync(
            nodeId: 63,
            CreateSspanelV2rayNodeInfoResponse(
                vmessPort,
                network: RuntimeInternetTransportProtocols.Mkcp),
            [CreateSspanelV2rayUserResponse()],
            lifetimeCts.Token);

        try
        {
            xrayr = await StartXrayRAsync(
                xrayrExecutable,
                tempDirectory,
                "xrayr-vmess-mkcp-server.yml",
                CreateXrayRV2raySspanelConfig(panel.ApiHost, nodeId: 63),
                vmessPort,
                lifetimeCts.Token,
                listenNetwork: RuntimeInternetTransportProtocols.Mkcp);

            await runtime.StartAsync(
                CreateDotnetVmessClientPlan(
                    revision: 1,
                    localSocksPort: socksPort,
                    serverPort: vmessPort,
                    transport: RuntimeInternetTransportProtocols.Mkcp),
                lifetimeCts.Token);

            xrayr.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-dotnet-vmess-mkcp-client-to-xrayr", lifetimeCts.Token);

            xrayr.AssertStillRunning();
        }
        catch (Exception ex) when (xrayr is not null)
        {
            throw CreateInteropFailure(
                "Xray-dotnet VMess mkcp client -> XrayR VMess mkcp server interop failed.",
                runtime,
                xrayr,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xrayr is not null)
            {
                await xrayr.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task Xray_core_vmess_mkcp_outbound_can_connect_to_xrayr_vmess_mkcp_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable) ||
            !TryGetXrayRExecutablePath(out var xrayrExecutable))
        {
            return;
        }

        if (!SupportsLegacyMkcpInteropWithXrayR(xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("xray-vmess-mkcp-client-to-xrayr");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var vmessPort = GetAvailableUdpPort();
        var socksPort = GetAvailableTcpPort();
        XrayProcessHandle? xray = null;
        XrayProcessHandle? xrayr = null;
        await using var panel = await StartSspanelMockPanelAsync(
            nodeId: 64,
            CreateSspanelV2rayNodeInfoResponse(
                vmessPort,
                network: RuntimeInternetTransportProtocols.Mkcp),
            [CreateSspanelV2rayUserResponse()],
            lifetimeCts.Token);

        try
        {
            xrayr = await StartXrayRAsync(
                xrayrExecutable,
                tempDirectory,
                "xrayr-vmess-mkcp-server.yml",
                CreateXrayRV2raySspanelConfig(panel.ApiHost, nodeId: 64),
                vmessPort,
                lifetimeCts.Token,
                listenNetwork: RuntimeInternetTransportProtocols.Mkcp);

            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "socks-to-xrayr-vmess-mkcp.json",
                CreateXraySocksToVmessClientConfig(
                    socksPort,
                    vmessPort,
                    network: RuntimeInternetTransportProtocols.Mkcp),
                socksPort,
                lifetimeCts.Token);

            xrayr.AssertStillRunning();
            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-xray-vmess-mkcp-client-to-xrayr", lifetimeCts.Token);

            xrayr.AssertStillRunning();
            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xrayr is not null || xray is not null)
        {
            var diagnostics = new StringBuilder();
            diagnostics.AppendLine("xray-core mkcp client -> XrayR VMess mkcp server interop failed.");
            if (xrayr is not null)
            {
                diagnostics.AppendLine("xrayr:");
                diagnostics.AppendLine(xrayr.GetDiagnostics());
            }

            if (xray is not null)
            {
                diagnostics.AppendLine("xray-core:");
                diagnostics.AppendLine(xray.GetDiagnostics());
            }

            throw new InvalidOperationException(diagnostics.ToString().TrimEnd(), ex);
        }
        finally
        {
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            if (xrayr is not null)
            {
                await xrayr.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task DefaultRuntime_trojan_outbound_can_connect_to_xray_core_trojan_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("dotnet-trojan-client-to-xray");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var xrayPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        XrayProcessHandle? xray = null;

        try
        {
            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "trojan-server.json",
                CreateXrayTrojanServerConfig(xrayPort),
                xrayPort,
                lifetimeCts.Token);

            await runtime.StartAsync(
                CreateDotnetTrojanClientPlan(
                    revision: 1,
                    localSocksPort: socksPort,
                    serverPort: xrayPort),
                lifetimeCts.Token);

            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-dotnet-trojan-client-to-xray", lifetimeCts.Token);

            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw CreateInteropFailure(
                "Xray-dotnet Trojan client -> xray-core Trojan server interop failed.",
                runtime,
                xray,
                ex);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task DefaultRuntime_trojan_tls_outbound_can_connect_to_xray_core_trojan_tls_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(GoHelperTestTimeout);
        var tempDirectory = CreateInteropTempDirectory("dotnet-trojan-tls-client-to-xray");
        var certificateFile = Path.Combine(tempDirectory, "trojan-tls-cert.pem");
        var keyFile = Path.Combine(tempDirectory, "trojan-tls-key.pem");
        using var certificate = CreateInteropServerCertificate(InteropTlsServerName);
        await WriteXrayCertificateFilesAsync(certificate, certificateFile, keyFile, lifetimeCts.Token);
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var xrayPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xray = null;

        try
        {
            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "trojan-tls-server.json",
                CreateXrayTrojanServerConfig(
                    xrayPort,
                    security: RuntimeInternetSecurityTypes.Tls,
                    certificateFile: certificateFile,
                    keyFile: keyFile),
                xrayPort,
                lifetimeCts.Token);

            await runtime.StartAsync(
                CreateDotnetTrojanClientPlan(
                    revision: 1,
                    localSocksPort: socksPort,
                    serverPort: xrayPort,
                    transport: TrojanOutboundTransports.Tls,
                    serverName: InteropTlsServerName,
                    skipCertificateValidation: true),
                lifetimeCts.Token);

            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-dotnet-trojan-tls-client-to-xray", lifetimeCts.Token);

            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw CreateInteropFailure(
                "Xray-dotnet Trojan tls client -> xray-core Trojan tls server interop failed.",
                runtime,
                xray,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task DefaultRuntime_trojan_mkcp_outbound_can_connect_to_xray_core_trojan_mkcp_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(GoHelperTestTimeout);
        var tempDirectory = CreateInteropTempDirectory("dotnet-trojan-mkcp-client-to-xray");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var xrayPort = GetAvailableUdpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xray = null;

        try
        {
            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "trojan-mkcp-server.json",
                CreateXrayTrojanServerConfig(
                    xrayPort,
                    network: RuntimeInternetTransportProtocols.Mkcp),
                xrayPort,
                lifetimeCts.Token,
                listenNetwork: RuntimeInternetTransportProtocols.Mkcp);

            await runtime.StartAsync(
                CreateDotnetTrojanClientPlan(
                    revision: 1,
                    localSocksPort: socksPort,
                    serverPort: xrayPort,
                    transport: RuntimeInternetTransportProtocols.Mkcp),
                lifetimeCts.Token);

            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-dotnet-trojan-mkcp-client-to-xray", lifetimeCts.Token);

            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw CreateInteropFailure(
                "Xray-dotnet Trojan mkcp client -> xray-core Trojan mkcp server interop failed.",
                runtime,
                xray,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task DefaultRuntime_trojan_ws_outbound_can_connect_to_xray_core_trojan_ws_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("dotnet-trojan-ws-client-to-xray");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var xrayPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xray = null;

        try
        {
            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "trojan-ws-server.json",
                CreateXrayTrojanServerConfig(
                    xrayPort,
                    network: "ws",
                    host: TrojanWebSocketHost,
                    path: TrojanWebSocketPath),
                xrayPort,
                lifetimeCts.Token);

            await runtime.StartAsync(
                CreateDotnetTrojanClientPlan(
                    revision: 1,
                    localSocksPort: socksPort,
                    serverPort: xrayPort,
                    transport: TrojanOutboundTransports.Ws,
                    host: TrojanWebSocketHost,
                    path: TrojanWebSocketPath),
                lifetimeCts.Token);

            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-dotnet-trojan-ws-client-to-xray", lifetimeCts.Token);

            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw CreateInteropFailure(
                "Xray-dotnet Trojan ws client -> xray-core Trojan ws server interop failed.",
                runtime,
                xray,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task DefaultRuntime_trojan_grpc_outbound_can_connect_to_xray_core_trojan_grpc_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("dotnet-trojan-grpc-client-to-xray");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var xrayPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xray = null;

        try
        {
            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "trojan-grpc-server.json",
                CreateXrayTrojanServerConfig(
                    xrayPort,
                    network: "grpc",
                    grpcServiceName: TrojanGrpcServiceName),
                xrayPort,
                lifetimeCts.Token);

            await runtime.StartAsync(
                CreateDotnetTrojanClientPlan(
                    revision: 1,
                    localSocksPort: socksPort,
                    serverPort: xrayPort,
                    transport: TrojanOutboundTransports.Grpc,
                    grpcServiceName: TrojanGrpcServiceName),
                lifetimeCts.Token);

            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-dotnet-trojan-grpc-client-to-xray", lifetimeCts.Token);

            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw CreateInteropFailure(
                "Xray-dotnet Trojan grpc client -> xray-core Trojan grpc server interop failed.",
                runtime,
                xray,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task DefaultRuntime_trojan_httpupgrade_outbound_can_connect_to_xray_core_trojan_httpupgrade_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(GoHelperTestTimeout);
        var tempDirectory = CreateInteropTempDirectory("dotnet-trojan-httpupgrade-client-to-xray");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var xrayPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xray = null;

        try
        {
            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "trojan-httpupgrade-server.json",
                CreateXrayTrojanServerConfig(
                    xrayPort,
                    network: "httpupgrade",
                    host: TrojanHttpUpgradeHost,
                    path: TrojanHttpUpgradePath),
                xrayPort,
                lifetimeCts.Token);

            await runtime.StartAsync(
                CreateDotnetTrojanClientPlan(
                    revision: 1,
                    localSocksPort: socksPort,
                    serverPort: xrayPort,
                    transport: TrojanOutboundTransports.HttpUpgrade,
                    host: TrojanHttpUpgradeHost,
                    path: TrojanHttpUpgradePath),
                lifetimeCts.Token);

            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-dotnet-trojan-httpupgrade-client-to-xray", lifetimeCts.Token);

            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw CreateInteropFailure(
                "Xray-dotnet Trojan httpupgrade client -> xray-core Trojan httpupgrade server interop failed.",
                runtime,
                xray,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task DefaultRuntime_trojan_splithttp_outbound_can_connect_to_xray_core_trojan_splithttp_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(GoHelperTestTimeout);
        var tempDirectory = CreateInteropTempDirectory("dotnet-trojan-splithttp-client-to-xray");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var xrayPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xray = null;

        try
        {
            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "trojan-splithttp-server.json",
                CreateXrayTrojanServerConfig(
                    xrayPort,
                    network: "splithttp",
                    host: TrojanSplitHttpHost,
                    path: TrojanSplitHttpPath),
                xrayPort,
                lifetimeCts.Token);

            await runtime.StartAsync(
                CreateDotnetTrojanClientPlan(
                    revision: 1,
                    localSocksPort: socksPort,
                    serverPort: xrayPort,
                    transport: TrojanOutboundTransports.SplitHttp,
                    host: TrojanSplitHttpHost,
                    path: TrojanSplitHttpPath),
                lifetimeCts.Token);

            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-dotnet-trojan-splithttp-client-to-xray", lifetimeCts.Token);

            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw CreateInteropFailure(
                "Xray-dotnet Trojan splithttp client -> xray-core Trojan splithttp server interop failed.",
                runtime,
                xray,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task Trojan_outbound_handler_can_connect_to_xray_core_trojan_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("trojan-handler-to-xray");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var xrayPort = GetAvailableTcpPort();
        XrayProcessHandle? xray = null;
        TrojanOutboundHandler? handler = null;

        try
        {
            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "trojan-server.json",
                CreateXrayTrojanServerConfig(xrayPort),
                xrayPort,
                lifetimeCts.Token);

            var dispatcher = CreateDirectTrojanDispatcher(
                new TrojanOutboundSettings
                {
                    Tag = "trojan-out",
                    ServerHost = IPAddress.Loopback.ToString(),
                    ServerPort = xrayPort,
                    Transport = TrojanOutboundTransports.Tcp,
                    TransportSecurity = RuntimeInternetSecurityTypes.None,
                    Password = TrojanSharedPassword,
                    ConnectTimeoutSeconds = 5,
                    HandshakeTimeoutSeconds = 5
                },
                out handler);

            await using var outbound = await dispatcher.DispatchTcpAsync(
                new DispatchContext
                {
                    InboundProtocol = InboundProtocols.Trojan,
                    InboundTag = "edge",
                    UserId = UserId,
                    ConnectTimeoutSeconds = 5
                },
                new DispatchDestination
                {
                    Host = "127.0.0.1",
                    Port = echoPort,
                    Network = DispatchNetwork.Tcp
                },
                lifetimeCts.Token);

            xray.AssertStillRunning();
            await AssertEchoAsync(outbound, "hello-trojan-handler-to-xray", lifetimeCts.Token);
            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw new InvalidOperationException(
                $"TrojanOutboundHandler -> xray-core Trojan inbound interop failed.{Environment.NewLine}{xray.GetDiagnostics()}",
                ex);
        }
        finally
        {
            if (handler is not null)
            {
                await handler.DisposeAsync();
            }

            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task Xray_core_trojan_outbound_can_connect_to_default_runtime_trojan_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("xray-trojan-client-to-dotnet");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var trojanPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        XrayProcessHandle? xray = null;

        try
        {
            await runtime.StartAsync(
                CreateDotnetTrojanServerPlan(
                    revision: 1,
                    inboundPort: trojanPort),
                lifetimeCts.Token);

            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "socks-to-trojan.json",
                CreateXraySocksToTrojanClientConfig(
                    socksPort,
                    trojanPort),
                socksPort,
                lifetimeCts.Token);

            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-xray-trojan-client-to-dotnet", lifetimeCts.Token);

            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw CreateInteropFailure(
                "xray-core Trojan client -> Xray-dotnet Trojan server interop failed.",
                runtime,
                xray,
                ex);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task Xray_core_trojan_tls_outbound_can_connect_to_default_runtime_trojan_tls_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(GoHelperTestTimeout);
        var tempDirectory = CreateInteropTempDirectory("xray-trojan-tls-client-to-dotnet");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var trojanPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        using var certificate = CreateInteropServerCertificate(InteropTlsServerName);
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xray = null;

        try
        {
            await runtime.StartAsync(
                CreateDotnetTrojanServerPlan(
                    revision: 1,
                    inboundPort: trojanPort,
                    transportSecurity: RuntimeInternetSecurityTypes.Tls,
                    tls: new RuntimeTlsOptions
                    {
                        Certificate = certificate
                    }),
                lifetimeCts.Token);

            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "socks-to-trojan-tls.json",
                CreateXraySocksToTrojanClientConfig(
                    socksPort,
                    trojanPort,
                    security: RuntimeInternetSecurityTypes.Tls,
                    serverName: InteropTlsServerName,
                    allowInsecure: true),
                socksPort,
                lifetimeCts.Token);

            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-xray-trojan-tls-client-to-dotnet", lifetimeCts.Token);

            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw CreateInteropFailure(
                "xray-core Trojan tls client -> Xray-dotnet Trojan tls server interop failed.",
                runtime,
                xray,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task Xray_core_trojan_mkcp_outbound_can_connect_to_default_runtime_trojan_mkcp_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("xray-trojan-mkcp-client-to-dotnet");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var trojanPort = GetAvailableUdpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xray = null;

        try
        {
            await runtime.StartAsync(
                CreateDotnetTrojanServerPlan(
                    revision: 1,
                    inboundPort: trojanPort,
                    transportProtocol: RuntimeInternetTransportProtocols.Mkcp),
                lifetimeCts.Token);

            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "socks-to-trojan-mkcp.json",
                CreateXraySocksToTrojanClientConfig(
                    socksPort,
                    trojanPort,
                    network: RuntimeInternetTransportProtocols.Mkcp),
                socksPort,
                lifetimeCts.Token);

            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-xray-trojan-mkcp-client-to-dotnet", lifetimeCts.Token);

            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw CreateInteropFailure(
                "xray-core Trojan mkcp client -> Xray-dotnet Trojan mkcp server interop failed.",
                runtime,
                xray,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task Xray_core_trojan_ws_outbound_can_connect_to_default_runtime_trojan_ws_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("xray-trojan-ws-client-to-dotnet");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var trojanPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xray = null;

        try
        {
            await runtime.StartAsync(
                CreateDotnetTrojanServerPlan(
                    revision: 1,
                    inboundPort: trojanPort,
                    transportProtocol: RuntimeInternetTransportProtocols.Ws,
                    host: TrojanWebSocketHost,
                    path: TrojanWebSocketPath),
                lifetimeCts.Token);

            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "socks-to-trojan-ws.json",
                CreateXraySocksToTrojanClientConfig(
                    socksPort,
                    trojanPort,
                    network: "ws",
                    host: TrojanWebSocketHost,
                    path: TrojanWebSocketPath),
                socksPort,
                lifetimeCts.Token);

            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-xray-trojan-ws-client-to-dotnet", lifetimeCts.Token);

            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw CreateInteropFailure(
                "xray-core Trojan ws client -> Xray-dotnet Trojan ws server interop failed.",
                runtime,
                xray,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task Xray_core_trojan_grpc_outbound_can_connect_to_default_runtime_trojan_grpc_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("xray-trojan-grpc-client-to-dotnet");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var trojanPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xray = null;

        try
        {
            await runtime.StartAsync(
                CreateDotnetTrojanServerPlan(
                    revision: 1,
                    inboundPort: trojanPort,
                    transportProtocol: RuntimeInternetTransportProtocols.Grpc,
                    grpcServiceName: TrojanGrpcServiceName),
                lifetimeCts.Token);

            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "socks-to-trojan-grpc.json",
                CreateXraySocksToTrojanClientConfig(
                    socksPort,
                    trojanPort,
                    network: "grpc",
                    grpcServiceName: TrojanGrpcServiceName),
                socksPort,
                lifetimeCts.Token);

            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-xray-trojan-grpc-client-to-dotnet", lifetimeCts.Token);

            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw CreateInteropFailure(
                "xray-core Trojan grpc client -> Xray-dotnet Trojan grpc server interop failed.",
                runtime,
                xray,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task DefaultRuntime_vless_grpc_outbound_can_connect_to_xrayr_vless_grpc_inbound()
    {
        if (!TryGetXrayRExecutablePath(out var xrayrExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("dotnet-vless-grpc-client-to-xrayr");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var vlessPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xrayr = null;
        await using var panel = await StartSspanelMockPanelAsync(
            nodeId: 35,
            CreateSspanelV2rayNodeInfoResponse(
                vlessPort,
                enableVless: true,
                network: "grpc",
                grpcServiceName: VlessGrpcServiceName),
            [CreateSspanelV2rayUserResponse()],
            lifetimeCts.Token);

        try
        {
            xrayr = await StartXrayRAsync(
                xrayrExecutable,
                tempDirectory,
                "xrayr-vless-grpc-server.yml",
                CreateXrayRV2raySspanelConfig(panel.ApiHost, nodeId: 35),
                vlessPort,
                lifetimeCts.Token);

            await runtime.StartAsync(
                CreateDotnetVlessClientPlan(
                    revision: 1,
                    localSocksPort: socksPort,
                    serverPort: vlessPort,
                    transport: VlessOutboundTransports.Grpc,
                    grpcServiceName: VlessGrpcServiceName),
                lifetimeCts.Token);

            xrayr.AssertStillRunning();

            await AssertEchoViaSocks5WithRetryAsync(
                socksPort,
                echoPort,
                "hello-dotnet-vless-grpc-client-to-xrayr",
                lifetimeCts.Token);

            xrayr.AssertStillRunning();
        }
        catch (Exception ex) when (xrayr is not null)
        {
            throw CreateInteropFailure(
                "Xray-dotnet VLESS grpc client -> XrayR VLESS grpc server interop failed.",
                runtime,
                xrayr,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xrayr is not null)
            {
                await xrayr.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task Xray_core_vless_grpc_outbound_can_connect_to_xrayr_vless_grpc_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable) ||
            !TryGetXrayRExecutablePath(out var xrayrExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("xray-vless-grpc-client-to-xrayr");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var vlessPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        XrayProcessHandle? xray = null;
        XrayProcessHandle? xrayr = null;
        await using var panel = await StartSspanelMockPanelAsync(
            nodeId: 36,
            CreateSspanelV2rayNodeInfoResponse(
                vlessPort,
                enableVless: true,
                network: "grpc",
                grpcServiceName: VlessGrpcServiceName),
            [CreateSspanelV2rayUserResponse()],
            lifetimeCts.Token);

        try
        {
            xrayr = await StartXrayRAsync(
                xrayrExecutable,
                tempDirectory,
                "xrayr-vless-grpc-server.yml",
                CreateXrayRV2raySspanelConfig(panel.ApiHost, nodeId: 36),
                vlessPort,
                lifetimeCts.Token);

            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "socks-to-xrayr-vless-grpc.json",
                CreateXraySocksToVlessClientConfig(
                    socksPort,
                    vlessPort,
                    network: "grpc",
                    grpcServiceName: VlessGrpcServiceName),
                socksPort,
                lifetimeCts.Token);

            xrayr.AssertStillRunning();
            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-xray-vless-grpc-client-to-xrayr", lifetimeCts.Token);

            xrayr.AssertStillRunning();
            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xrayr is not null || xray is not null)
        {
            var diagnostics = new StringBuilder();
            diagnostics.AppendLine("xray-core grpc client -> XrayR VLESS grpc server interop failed.");
            if (xrayr is not null)
            {
                diagnostics.AppendLine("xrayr:");
                diagnostics.AppendLine(xrayr.GetDiagnostics());
            }

            if (xray is not null)
            {
                diagnostics.AppendLine("xray-core:");
                diagnostics.AppendLine(xray.GetDiagnostics());
            }

            throw new InvalidOperationException(diagnostics.ToString().TrimEnd(), ex);
        }
        finally
        {
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            if (xrayr is not null)
            {
                await xrayr.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task DefaultRuntime_vmess_grpc_outbound_can_connect_to_xrayr_vmess_grpc_inbound()
    {
        if (!TryGetXrayRExecutablePath(out var xrayrExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("dotnet-vmess-grpc-client-to-xrayr");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var vmessPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        XrayProcessHandle? xrayr = null;
        await using var panel = await StartSspanelMockPanelAsync(
            nodeId: 37,
            CreateSspanelV2rayNodeInfoResponse(
                vmessPort,
                network: "grpc",
                grpcServiceName: VmessGrpcServiceName),
            [CreateSspanelV2rayUserResponse()],
            lifetimeCts.Token);

        try
        {
            xrayr = await StartXrayRAsync(
                xrayrExecutable,
                tempDirectory,
                "xrayr-vmess-grpc-server.yml",
                CreateXrayRV2raySspanelConfig(panel.ApiHost, nodeId: 37),
                vmessPort,
                lifetimeCts.Token);

            await runtime.StartAsync(
                CreateDotnetVmessClientPlan(
                    revision: 1,
                    localSocksPort: socksPort,
                    serverPort: vmessPort,
                    transport: VmessOutboundTransports.Grpc,
                    grpcServiceName: VmessGrpcServiceName),
                lifetimeCts.Token);

            xrayr.AssertStillRunning();

            await AssertEchoViaSocks5WithRetryAsync(
                socksPort,
                echoPort,
                "hello-dotnet-vmess-grpc-client-to-xrayr",
                lifetimeCts.Token);

            xrayr.AssertStillRunning();
        }
        catch (Exception ex) when (xrayr is not null)
        {
            throw CreateInteropFailure(
                "Xray-dotnet VMess grpc client -> XrayR VMess grpc server interop failed.",
                runtime,
                xrayr,
                ex);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xrayr is not null)
            {
                await xrayr.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task Xray_core_vmess_grpc_outbound_can_connect_to_xrayr_vmess_grpc_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable) ||
            !TryGetXrayRExecutablePath(out var xrayrExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("xray-vmess-grpc-client-to-xrayr");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var vmessPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        XrayProcessHandle? xray = null;
        XrayProcessHandle? xrayr = null;
        await using var panel = await StartSspanelMockPanelAsync(
            nodeId: 38,
            CreateSspanelV2rayNodeInfoResponse(
                vmessPort,
                network: "grpc",
                grpcServiceName: VmessGrpcServiceName),
            [CreateSspanelV2rayUserResponse()],
            lifetimeCts.Token);

        try
        {
            xrayr = await StartXrayRAsync(
                xrayrExecutable,
                tempDirectory,
                "xrayr-vmess-grpc-server.yml",
                CreateXrayRV2raySspanelConfig(panel.ApiHost, nodeId: 38),
                vmessPort,
                lifetimeCts.Token);

            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "socks-to-xrayr-vmess-grpc.json",
                CreateXraySocksToVmessClientConfig(
                    socksPort,
                    vmessPort,
                    network: "grpc",
                    grpcServiceName: VmessGrpcServiceName),
                socksPort,
                lifetimeCts.Token);

            xrayr.AssertStillRunning();
            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-xray-vmess-grpc-client-to-xrayr", lifetimeCts.Token);

            xrayr.AssertStillRunning();
            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xrayr is not null || xray is not null)
        {
            var diagnostics = new StringBuilder();
            diagnostics.AppendLine("xray-core grpc client -> XrayR VMess grpc server interop failed.");
            if (xrayr is not null)
            {
                diagnostics.AppendLine("xrayr:");
                diagnostics.AppendLine(xrayr.GetDiagnostics());
            }

            if (xray is not null)
            {
                diagnostics.AppendLine("xray-core:");
                diagnostics.AppendLine(xray.GetDiagnostics());
            }

            throw new InvalidOperationException(diagnostics.ToString().TrimEnd(), ex);
        }
        finally
        {
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            if (xrayr is not null)
            {
                await xrayr.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task DefaultRuntime_vless_ws_outbound_can_connect_to_xrayr_vless_ws_inbound()
    {
        if (!TryGetXrayRExecutablePath(out var xrayrExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("dotnet-vless-ws-client-to-xrayr");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var vlessPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xrayr = null;
        await using var panel = await StartSspanelMockPanelAsync(
            nodeId: 45,
            CreateSspanelV2rayNodeInfoResponse(
                vlessPort,
                enableVless: true,
                network: "ws",
                host: V2rayWebSocketHost,
                path: V2rayWebSocketPath),
            [CreateSspanelV2rayUserResponse()],
            lifetimeCts.Token);

        try
        {
            xrayr = await StartXrayRAsync(
                xrayrExecutable,
                tempDirectory,
                "xrayr-vless-ws-server.yml",
                CreateXrayRV2raySspanelConfig(panel.ApiHost, nodeId: 45),
                vlessPort,
                lifetimeCts.Token);

            await runtime.StartAsync(
                CreateDotnetVlessClientPlan(
                    revision: 1,
                    localSocksPort: socksPort,
                    serverPort: vlessPort,
                    transport: VlessOutboundTransports.Ws,
                    host: V2rayWebSocketHost,
                    path: V2rayWebSocketPath),
                lifetimeCts.Token);

            xrayr.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-dotnet-vless-ws-client-to-xrayr", lifetimeCts.Token);

            xrayr.AssertStillRunning();
        }
        catch (Exception ex) when (xrayr is not null)
        {
            throw CreateInteropFailure(
                "Xray-dotnet VLESS ws client -> XrayR VLESS ws server interop failed.",
                runtime,
                xrayr,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xrayr is not null)
            {
                await xrayr.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task Xray_core_vless_ws_outbound_can_connect_to_xrayr_vless_ws_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable) ||
            !TryGetXrayRExecutablePath(out var xrayrExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("xray-vless-ws-client-to-xrayr");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var vlessPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        XrayProcessHandle? xray = null;
        XrayProcessHandle? xrayr = null;
        await using var panel = await StartSspanelMockPanelAsync(
            nodeId: 46,
            CreateSspanelV2rayNodeInfoResponse(
                vlessPort,
                enableVless: true,
                network: "ws",
                host: V2rayWebSocketHost,
                path: V2rayWebSocketPath),
            [CreateSspanelV2rayUserResponse()],
            lifetimeCts.Token);

        try
        {
            xrayr = await StartXrayRAsync(
                xrayrExecutable,
                tempDirectory,
                "xrayr-vless-ws-server.yml",
                CreateXrayRV2raySspanelConfig(panel.ApiHost, nodeId: 46),
                vlessPort,
                lifetimeCts.Token);

            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "socks-to-xrayr-vless-ws.json",
                CreateXraySocksToVlessClientConfig(
                    socksPort,
                    vlessPort,
                    network: "ws",
                    host: V2rayWebSocketHost,
                    path: V2rayWebSocketPath),
                socksPort,
                lifetimeCts.Token);

            xrayr.AssertStillRunning();
            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-xray-vless-ws-client-to-xrayr", lifetimeCts.Token);

            xrayr.AssertStillRunning();
            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xrayr is not null || xray is not null)
        {
            var diagnostics = new StringBuilder();
            diagnostics.AppendLine("xray-core ws client -> XrayR VLESS ws server interop failed.");
            if (xrayr is not null)
            {
                diagnostics.AppendLine("xrayr:");
                diagnostics.AppendLine(xrayr.GetDiagnostics());
            }

            if (xray is not null)
            {
                diagnostics.AppendLine("xray-core:");
                diagnostics.AppendLine(xray.GetDiagnostics());
            }

            throw new InvalidOperationException(diagnostics.ToString().TrimEnd(), ex);
        }
        finally
        {
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            if (xrayr is not null)
            {
                await xrayr.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task DefaultRuntime_vmess_ws_outbound_can_connect_to_xrayr_vmess_ws_inbound()
    {
        if (!TryGetXrayRExecutablePath(out var xrayrExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("dotnet-vmess-ws-client-to-xrayr");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var vmessPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xrayr = null;
        await using var panel = await StartSspanelMockPanelAsync(
            nodeId: 47,
            CreateSspanelV2rayNodeInfoResponse(
                vmessPort,
                network: "ws",
                host: V2rayWebSocketHost,
                path: V2rayWebSocketPath),
            [CreateSspanelV2rayUserResponse()],
            lifetimeCts.Token);

        try
        {
            xrayr = await StartXrayRAsync(
                xrayrExecutable,
                tempDirectory,
                "xrayr-vmess-ws-server.yml",
                CreateXrayRV2raySspanelConfig(panel.ApiHost, nodeId: 47),
                vmessPort,
                lifetimeCts.Token);

            await runtime.StartAsync(
                CreateDotnetVmessClientPlan(
                    revision: 1,
                    localSocksPort: socksPort,
                    serverPort: vmessPort,
                    transport: VmessOutboundTransports.Ws,
                    host: V2rayWebSocketHost,
                    path: V2rayWebSocketPath),
                lifetimeCts.Token);

            xrayr.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-dotnet-vmess-ws-client-to-xrayr", lifetimeCts.Token);

            xrayr.AssertStillRunning();
        }
        catch (Exception ex) when (xrayr is not null)
        {
            throw CreateInteropFailure(
                "Xray-dotnet VMess ws client -> XrayR VMess ws server interop failed.",
                runtime,
                xrayr,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xrayr is not null)
            {
                await xrayr.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task Xray_core_vmess_ws_outbound_can_connect_to_xrayr_vmess_ws_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable) ||
            !TryGetXrayRExecutablePath(out var xrayrExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("xray-vmess-ws-client-to-xrayr");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var vmessPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        XrayProcessHandle? xray = null;
        XrayProcessHandle? xrayr = null;
        await using var panel = await StartSspanelMockPanelAsync(
            nodeId: 48,
            CreateSspanelV2rayNodeInfoResponse(
                vmessPort,
                network: "ws",
                host: V2rayWebSocketHost,
                path: V2rayWebSocketPath),
            [CreateSspanelV2rayUserResponse()],
            lifetimeCts.Token);

        try
        {
            xrayr = await StartXrayRAsync(
                xrayrExecutable,
                tempDirectory,
                "xrayr-vmess-ws-server.yml",
                CreateXrayRV2raySspanelConfig(panel.ApiHost, nodeId: 48),
                vmessPort,
                lifetimeCts.Token);

            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "socks-to-xrayr-vmess-ws.json",
                CreateXraySocksToVmessClientConfig(
                    socksPort,
                    vmessPort,
                    network: "ws",
                    host: V2rayWebSocketHost,
                    path: V2rayWebSocketPath),
                socksPort,
                lifetimeCts.Token);

            xrayr.AssertStillRunning();
            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-xray-vmess-ws-client-to-xrayr", lifetimeCts.Token);

            xrayr.AssertStillRunning();
            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xrayr is not null || xray is not null)
        {
            var diagnostics = new StringBuilder();
            diagnostics.AppendLine("xray-core ws client -> XrayR VMess ws server interop failed.");
            if (xrayr is not null)
            {
                diagnostics.AppendLine("xrayr:");
                diagnostics.AppendLine(xrayr.GetDiagnostics());
            }

            if (xray is not null)
            {
                diagnostics.AppendLine("xray-core:");
                diagnostics.AppendLine(xray.GetDiagnostics());
            }

            throw new InvalidOperationException(diagnostics.ToString().TrimEnd(), ex);
        }
        finally
        {
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            if (xrayr is not null)
            {
                await xrayr.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task DefaultRuntime_vless_httpupgrade_outbound_can_connect_to_xrayr_vless_httpupgrade_inbound()
    {
        if (!TryGetXrayRExecutablePath(out var xrayrExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("dotnet-vless-httpupgrade-client-to-xrayr");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var vlessPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xrayr = null;
        await using var panel = await StartSspanelMockPanelAsync(
            nodeId: 49,
            CreateSspanelV2rayNodeInfoResponse(
                vlessPort,
                enableVless: true,
                network: "httpupgrade",
                host: V2rayHttpUpgradeHost,
                path: V2rayHttpUpgradePath),
            [CreateSspanelV2rayUserResponse()],
            lifetimeCts.Token);

        try
        {
            xrayr = await StartXrayRAsync(
                xrayrExecutable,
                tempDirectory,
                "xrayr-vless-httpupgrade-server.yml",
                CreateXrayRV2raySspanelConfig(panel.ApiHost, nodeId: 49),
                vlessPort,
                lifetimeCts.Token);

            await runtime.StartAsync(
                CreateDotnetVlessClientPlan(
                    revision: 1,
                    localSocksPort: socksPort,
                    serverPort: vlessPort,
                    transport: VlessOutboundTransports.HttpUpgrade,
                    host: V2rayHttpUpgradeHost,
                    path: V2rayHttpUpgradePath),
                lifetimeCts.Token);

            xrayr.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-dotnet-vless-httpupgrade-client-to-xrayr", lifetimeCts.Token);

            xrayr.AssertStillRunning();
        }
        catch (Exception ex) when (xrayr is not null)
        {
            throw CreateInteropFailure(
                "Xray-dotnet VLESS httpupgrade client -> XrayR VLESS httpupgrade server interop failed.",
                runtime,
                xrayr,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xrayr is not null)
            {
                await xrayr.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task Xray_core_vless_httpupgrade_outbound_can_connect_to_xrayr_vless_httpupgrade_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable) ||
            !TryGetXrayRExecutablePath(out var xrayrExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("xray-vless-httpupgrade-client-to-xrayr");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var vlessPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        XrayProcessHandle? xray = null;
        XrayProcessHandle? xrayr = null;
        await using var panel = await StartSspanelMockPanelAsync(
            nodeId: 50,
            CreateSspanelV2rayNodeInfoResponse(
                vlessPort,
                enableVless: true,
                network: "httpupgrade",
                host: V2rayHttpUpgradeHost,
                path: V2rayHttpUpgradePath),
            [CreateSspanelV2rayUserResponse()],
            lifetimeCts.Token);

        try
        {
            xrayr = await StartXrayRAsync(
                xrayrExecutable,
                tempDirectory,
                "xrayr-vless-httpupgrade-server.yml",
                CreateXrayRV2raySspanelConfig(panel.ApiHost, nodeId: 50),
                vlessPort,
                lifetimeCts.Token);

            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "socks-to-xrayr-vless-httpupgrade.json",
                CreateXraySocksToVlessClientConfig(
                    socksPort,
                    vlessPort,
                    network: "httpupgrade",
                    host: V2rayHttpUpgradeHost,
                    path: V2rayHttpUpgradePath),
                socksPort,
                lifetimeCts.Token);

            xrayr.AssertStillRunning();
            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-xray-vless-httpupgrade-client-to-xrayr", lifetimeCts.Token);

            xrayr.AssertStillRunning();
            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xrayr is not null || xray is not null)
        {
            var diagnostics = new StringBuilder();
            diagnostics.AppendLine("xray-core httpupgrade client -> XrayR VLESS httpupgrade server interop failed.");
            if (xrayr is not null)
            {
                diagnostics.AppendLine("xrayr:");
                diagnostics.AppendLine(xrayr.GetDiagnostics());
            }

            if (xray is not null)
            {
                diagnostics.AppendLine("xray-core:");
                diagnostics.AppendLine(xray.GetDiagnostics());
            }

            throw new InvalidOperationException(diagnostics.ToString().TrimEnd(), ex);
        }
        finally
        {
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            if (xrayr is not null)
            {
                await xrayr.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task DefaultRuntime_vmess_httpupgrade_outbound_can_connect_to_xrayr_vmess_httpupgrade_inbound()
    {
        if (!TryGetXrayRExecutablePath(out var xrayrExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("dotnet-vmess-httpupgrade-client-to-xrayr");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var vmessPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xrayr = null;
        await using var panel = await StartSspanelMockPanelAsync(
            nodeId: 51,
            CreateSspanelV2rayNodeInfoResponse(
                vmessPort,
                network: "httpupgrade",
                host: V2rayHttpUpgradeHost,
                path: V2rayHttpUpgradePath),
            [CreateSspanelV2rayUserResponse()],
            lifetimeCts.Token);

        try
        {
            xrayr = await StartXrayRAsync(
                xrayrExecutable,
                tempDirectory,
                "xrayr-vmess-httpupgrade-server.yml",
                CreateXrayRV2raySspanelConfig(panel.ApiHost, nodeId: 51),
                vmessPort,
                lifetimeCts.Token);

            await runtime.StartAsync(
                CreateDotnetVmessClientPlan(
                    revision: 1,
                    localSocksPort: socksPort,
                    serverPort: vmessPort,
                    transport: VmessOutboundTransports.HttpUpgrade,
                    host: V2rayHttpUpgradeHost,
                    path: V2rayHttpUpgradePath),
                lifetimeCts.Token);

            xrayr.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-dotnet-vmess-httpupgrade-client-to-xrayr", lifetimeCts.Token);

            xrayr.AssertStillRunning();
        }
        catch (Exception ex) when (xrayr is not null)
        {
            throw CreateInteropFailure(
                "Xray-dotnet VMess httpupgrade client -> XrayR VMess httpupgrade server interop failed.",
                runtime,
                xrayr,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xrayr is not null)
            {
                await xrayr.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task Xray_core_vmess_httpupgrade_outbound_can_connect_to_xrayr_vmess_httpupgrade_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable) ||
            !TryGetXrayRExecutablePath(out var xrayrExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("xray-vmess-httpupgrade-client-to-xrayr");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var vmessPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        XrayProcessHandle? xray = null;
        XrayProcessHandle? xrayr = null;
        await using var panel = await StartSspanelMockPanelAsync(
            nodeId: 52,
            CreateSspanelV2rayNodeInfoResponse(
                vmessPort,
                network: "httpupgrade",
                host: V2rayHttpUpgradeHost,
                path: V2rayHttpUpgradePath),
            [CreateSspanelV2rayUserResponse()],
            lifetimeCts.Token);

        try
        {
            xrayr = await StartXrayRAsync(
                xrayrExecutable,
                tempDirectory,
                "xrayr-vmess-httpupgrade-server.yml",
                CreateXrayRV2raySspanelConfig(panel.ApiHost, nodeId: 52),
                vmessPort,
                lifetimeCts.Token);

            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "socks-to-xrayr-vmess-httpupgrade.json",
                CreateXraySocksToVmessClientConfig(
                    socksPort,
                    vmessPort,
                    network: "httpupgrade",
                    host: V2rayHttpUpgradeHost,
                    path: V2rayHttpUpgradePath),
                socksPort,
                lifetimeCts.Token);

            xrayr.AssertStillRunning();
            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-xray-vmess-httpupgrade-client-to-xrayr", lifetimeCts.Token);

            xrayr.AssertStillRunning();
            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xrayr is not null || xray is not null)
        {
            var diagnostics = new StringBuilder();
            diagnostics.AppendLine("xray-core httpupgrade client -> XrayR VMess httpupgrade server interop failed.");
            if (xrayr is not null)
            {
                diagnostics.AppendLine("xrayr:");
                diagnostics.AppendLine(xrayr.GetDiagnostics());
            }

            if (xray is not null)
            {
                diagnostics.AppendLine("xray-core:");
                diagnostics.AppendLine(xray.GetDiagnostics());
            }

            throw new InvalidOperationException(diagnostics.ToString().TrimEnd(), ex);
        }
        finally
        {
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            if (xrayr is not null)
            {
                await xrayr.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task DefaultRuntime_vless_splithttp_outbound_can_connect_to_xrayr_vless_splithttp_inbound()
    {
        if (!TryGetXrayRExecutablePath(out var xrayrExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("dotnet-vless-splithttp-client-to-xrayr");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var vlessPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xrayr = null;
        await using var panel = await StartSspanelMockPanelAsync(
            nodeId: 53,
            CreateSspanelV2rayNodeInfoResponse(
                vlessPort,
                enableVless: true,
                network: "splithttp",
                host: V2raySplitHttpHost,
                path: V2raySplitHttpPath),
            [CreateSspanelV2rayUserResponse()],
            lifetimeCts.Token);

        try
        {
            xrayr = await StartXrayRAsync(
                xrayrExecutable,
                tempDirectory,
                "xrayr-vless-splithttp-server.yml",
                CreateXrayRV2raySspanelConfig(panel.ApiHost, nodeId: 53),
                vlessPort,
                lifetimeCts.Token);

            await runtime.StartAsync(
                CreateDotnetVlessClientPlan(
                    revision: 1,
                    localSocksPort: socksPort,
                    serverPort: vlessPort,
                    transport: VlessOutboundTransports.SplitHttp,
                    host: V2raySplitHttpHost,
                    path: V2raySplitHttpPath),
                lifetimeCts.Token);

            xrayr.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-dotnet-vless-splithttp-client-to-xrayr", lifetimeCts.Token);

            xrayr.AssertStillRunning();
        }
        catch (Exception ex) when (xrayr is not null)
        {
            throw CreateInteropFailure(
                "Xray-dotnet VLESS splithttp client -> XrayR VLESS splithttp server interop failed.",
                runtime,
                xrayr,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xrayr is not null)
            {
                await xrayr.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task Xray_core_vless_splithttp_outbound_can_connect_to_xrayr_vless_splithttp_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable) ||
            !TryGetXrayRExecutablePath(out var xrayrExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("xray-vless-splithttp-client-to-xrayr");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var vlessPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        XrayProcessHandle? xray = null;
        XrayProcessHandle? xrayr = null;
        await using var panel = await StartSspanelMockPanelAsync(
            nodeId: 54,
            CreateSspanelV2rayNodeInfoResponse(
                vlessPort,
                enableVless: true,
                network: "splithttp",
                host: V2raySplitHttpHost,
                path: V2raySplitHttpPath),
            [CreateSspanelV2rayUserResponse()],
            lifetimeCts.Token);

        try
        {
            xrayr = await StartXrayRAsync(
                xrayrExecutable,
                tempDirectory,
                "xrayr-vless-splithttp-server.yml",
                CreateXrayRV2raySspanelConfig(panel.ApiHost, nodeId: 54),
                vlessPort,
                lifetimeCts.Token);

            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "socks-to-xrayr-vless-splithttp.json",
                CreateXraySocksToVlessClientConfig(
                    socksPort,
                    vlessPort,
                    network: "splithttp",
                    host: V2raySplitHttpHost,
                    path: V2raySplitHttpPath),
                socksPort,
                lifetimeCts.Token);

            xrayr.AssertStillRunning();
            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-xray-vless-splithttp-client-to-xrayr", lifetimeCts.Token);

            xrayr.AssertStillRunning();
            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xrayr is not null || xray is not null)
        {
            var diagnostics = new StringBuilder();
            diagnostics.AppendLine("xray-core splithttp client -> XrayR VLESS splithttp server interop failed.");
            if (xrayr is not null)
            {
                diagnostics.AppendLine("xrayr:");
                diagnostics.AppendLine(xrayr.GetDiagnostics());
            }

            if (xray is not null)
            {
                diagnostics.AppendLine("xray-core:");
                diagnostics.AppendLine(xray.GetDiagnostics());
            }

            throw new InvalidOperationException(diagnostics.ToString().TrimEnd(), ex);
        }
        finally
        {
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            if (xrayr is not null)
            {
                await xrayr.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task DefaultRuntime_vmess_splithttp_outbound_can_connect_to_xrayr_vmess_splithttp_inbound()
    {
        if (!TryGetXrayRExecutablePath(out var xrayrExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("dotnet-vmess-splithttp-client-to-xrayr");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var vmessPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xrayr = null;
        await using var panel = await StartSspanelMockPanelAsync(
            nodeId: 55,
            CreateSspanelV2rayNodeInfoResponse(
                vmessPort,
                network: "splithttp",
                host: V2raySplitHttpHost,
                path: V2raySplitHttpPath),
            [CreateSspanelV2rayUserResponse()],
            lifetimeCts.Token);

        try
        {
            xrayr = await StartXrayRAsync(
                xrayrExecutable,
                tempDirectory,
                "xrayr-vmess-splithttp-server.yml",
                CreateXrayRV2raySspanelConfig(panel.ApiHost, nodeId: 55),
                vmessPort,
                lifetimeCts.Token);

            await runtime.StartAsync(
                CreateDotnetVmessClientPlan(
                    revision: 1,
                    localSocksPort: socksPort,
                    serverPort: vmessPort,
                    transport: VmessOutboundTransports.SplitHttp,
                    host: V2raySplitHttpHost,
                    path: V2raySplitHttpPath),
                lifetimeCts.Token);

            xrayr.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-dotnet-vmess-splithttp-client-to-xrayr", lifetimeCts.Token);

            xrayr.AssertStillRunning();
        }
        catch (Exception ex) when (xrayr is not null)
        {
            throw CreateInteropFailure(
                "Xray-dotnet VMess splithttp client -> XrayR VMess splithttp server interop failed.",
                runtime,
                xrayr,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xrayr is not null)
            {
                await xrayr.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task Xray_core_vmess_splithttp_outbound_can_connect_to_xrayr_vmess_splithttp_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable) ||
            !TryGetXrayRExecutablePath(out var xrayrExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("xray-vmess-splithttp-client-to-xrayr");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var vmessPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        XrayProcessHandle? xray = null;
        XrayProcessHandle? xrayr = null;
        await using var panel = await StartSspanelMockPanelAsync(
            nodeId: 56,
            CreateSspanelV2rayNodeInfoResponse(
                vmessPort,
                network: "splithttp",
                host: V2raySplitHttpHost,
                path: V2raySplitHttpPath),
            [CreateSspanelV2rayUserResponse()],
            lifetimeCts.Token);

        try
        {
            xrayr = await StartXrayRAsync(
                xrayrExecutable,
                tempDirectory,
                "xrayr-vmess-splithttp-server.yml",
                CreateXrayRV2raySspanelConfig(panel.ApiHost, nodeId: 56),
                vmessPort,
                lifetimeCts.Token);

            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "socks-to-xrayr-vmess-splithttp.json",
                CreateXraySocksToVmessClientConfig(
                    socksPort,
                    vmessPort,
                    network: "splithttp",
                    host: V2raySplitHttpHost,
                    path: V2raySplitHttpPath),
                socksPort,
                lifetimeCts.Token);

            xrayr.AssertStillRunning();
            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-xray-vmess-splithttp-client-to-xrayr", lifetimeCts.Token);

            xrayr.AssertStillRunning();
            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xrayr is not null || xray is not null)
        {
            var diagnostics = new StringBuilder();
            diagnostics.AppendLine("xray-core splithttp client -> XrayR VMess splithttp server interop failed.");
            if (xrayr is not null)
            {
                diagnostics.AppendLine("xrayr:");
                diagnostics.AppendLine(xrayr.GetDiagnostics());
            }

            if (xray is not null)
            {
                diagnostics.AppendLine("xray-core:");
                diagnostics.AppendLine(xray.GetDiagnostics());
            }

            throw new InvalidOperationException(diagnostics.ToString().TrimEnd(), ex);
        }
        finally
        {
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            if (xrayr is not null)
            {
                await xrayr.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task DefaultRuntime_trojan_outbound_can_connect_to_xrayr_trojan_inbound()
    {
        if (!TryGetXrayRExecutablePath(out var xrayrExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("dotnet-trojan-client-to-xrayr");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var trojanPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        XrayProcessHandle? xrayr = null;
        await using var panel = await StartSspanelMockPanelAsync(
            nodeId: 41,
            CreateSspanelTrojanNodeInfoResponse(trojanPort),
            [CreateSspanelTrojanUserResponse()],
            lifetimeCts.Token);

        try
        {
            xrayr = await StartXrayRAsync(
                xrayrExecutable,
                tempDirectory,
                "xrayr-trojan-server.yml",
                CreateXrayRTrojanSspanelConfig(panel.ApiHost, nodeId: 41),
                trojanPort,
                lifetimeCts.Token);

            await runtime.StartAsync(
                CreateDotnetTrojanClientPlan(
                    revision: 1,
                    localSocksPort: socksPort,
                    serverPort: trojanPort),
                lifetimeCts.Token);

            xrayr.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-dotnet-trojan-client-to-xrayr", lifetimeCts.Token);

            xrayr.AssertStillRunning();
        }
        catch (Exception ex) when (xrayr is not null)
        {
            throw CreateInteropFailure(
                "Xray-dotnet Trojan client -> XrayR Trojan server interop failed.",
                runtime,
                xrayr,
                ex);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xrayr is not null)
            {
                await xrayr.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task Xray_core_trojan_outbound_can_connect_to_xrayr_trojan_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable) ||
            !TryGetXrayRExecutablePath(out var xrayrExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("xray-trojan-client-to-xrayr");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var trojanPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        XrayProcessHandle? xray = null;
        XrayProcessHandle? xrayr = null;
        await using var panel = await StartSspanelMockPanelAsync(
            nodeId: 41,
            CreateSspanelTrojanNodeInfoResponse(trojanPort),
            [CreateSspanelTrojanUserResponse()],
            lifetimeCts.Token);

        try
        {
            xrayr = await StartXrayRAsync(
                xrayrExecutable,
                tempDirectory,
                "xrayr-trojan-server.yml",
                CreateXrayRTrojanSspanelConfig(panel.ApiHost, nodeId: 41),
                trojanPort,
                lifetimeCts.Token);

            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "socks-to-xrayr-trojan.json",
                CreateXraySocksToTrojanClientConfig(
                    socksPort,
                    trojanPort),
                socksPort,
                lifetimeCts.Token);

            xrayr.AssertStillRunning();
            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-xray-trojan-client-to-xrayr", lifetimeCts.Token);

            xrayr.AssertStillRunning();
            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xrayr is not null || xray is not null)
        {
            var diagnostics = new StringBuilder();
            diagnostics.AppendLine("xray-core client -> XrayR Trojan server interop failed.");
            if (xrayr is not null)
            {
                diagnostics.AppendLine("xrayr:");
                diagnostics.AppendLine(xrayr.GetDiagnostics());
            }

            if (xray is not null)
            {
                diagnostics.AppendLine("xray-core:");
                diagnostics.AppendLine(xray.GetDiagnostics());
            }

            throw new InvalidOperationException(diagnostics.ToString().TrimEnd(), ex);
        }
        finally
        {
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            if (xrayr is not null)
            {
                await xrayr.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task DefaultRuntime_trojan_mkcp_outbound_can_connect_to_xrayr_trojan_mkcp_inbound()
    {
        if (!TryGetXrayRExecutablePath(out var xrayrExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("dotnet-trojan-mkcp-client-to-xrayr");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var trojanPort = GetAvailableUdpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xrayr = null;
        await using var panel = await StartSspanelMockPanelAsync(
            nodeId: 65,
            CreateSspanelTrojanNodeInfoResponse(
                trojanPort,
                network: RuntimeInternetTransportProtocols.Mkcp),
            [CreateSspanelTrojanUserResponse()],
            lifetimeCts.Token);

        try
        {
            xrayr = await StartXrayRAsync(
                xrayrExecutable,
                tempDirectory,
                "xrayr-trojan-mkcp-server.yml",
                CreateXrayRTrojanSspanelConfig(panel.ApiHost, nodeId: 65),
                trojanPort,
                lifetimeCts.Token,
                listenNetwork: RuntimeInternetTransportProtocols.Mkcp);

            await runtime.StartAsync(
                CreateDotnetTrojanClientPlan(
                    revision: 1,
                    localSocksPort: socksPort,
                    serverPort: trojanPort,
                    transport: RuntimeInternetTransportProtocols.Mkcp),
                lifetimeCts.Token);

            xrayr.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-dotnet-trojan-mkcp-client-to-xrayr", lifetimeCts.Token);

            xrayr.AssertStillRunning();
        }
        catch (Exception ex) when (xrayr is not null)
        {
            throw CreateInteropFailure(
                "Xray-dotnet Trojan mkcp client -> XrayR Trojan mkcp server interop failed.",
                runtime,
                xrayr,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xrayr is not null)
            {
                await xrayr.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task Xray_core_trojan_mkcp_outbound_can_connect_to_xrayr_trojan_mkcp_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable) ||
            !TryGetXrayRExecutablePath(out var xrayrExecutable))
        {
            return;
        }

        if (!SupportsLegacyMkcpInteropWithXrayR(xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("xray-trojan-mkcp-client-to-xrayr");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var trojanPort = GetAvailableUdpPort();
        var socksPort = GetAvailableTcpPort();
        XrayProcessHandle? xray = null;
        XrayProcessHandle? xrayr = null;
        await using var panel = await StartSspanelMockPanelAsync(
            nodeId: 66,
            CreateSspanelTrojanNodeInfoResponse(
                trojanPort,
                network: RuntimeInternetTransportProtocols.Mkcp),
            [CreateSspanelTrojanUserResponse()],
            lifetimeCts.Token);

        try
        {
            xrayr = await StartXrayRAsync(
                xrayrExecutable,
                tempDirectory,
                "xrayr-trojan-mkcp-server.yml",
                CreateXrayRTrojanSspanelConfig(panel.ApiHost, nodeId: 66),
                trojanPort,
                lifetimeCts.Token,
                listenNetwork: RuntimeInternetTransportProtocols.Mkcp);

            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "socks-to-xrayr-trojan-mkcp.json",
                CreateXraySocksToTrojanClientConfig(
                    socksPort,
                    trojanPort,
                    network: RuntimeInternetTransportProtocols.Mkcp),
                socksPort,
                lifetimeCts.Token);

            xrayr.AssertStillRunning();
            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-xray-trojan-mkcp-client-to-xrayr", lifetimeCts.Token);

            xrayr.AssertStillRunning();
            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xrayr is not null || xray is not null)
        {
            var diagnostics = new StringBuilder();
            diagnostics.AppendLine("xray-core mkcp client -> XrayR Trojan mkcp server interop failed.");
            if (xrayr is not null)
            {
                diagnostics.AppendLine("xrayr:");
                diagnostics.AppendLine(xrayr.GetDiagnostics());
            }

            if (xray is not null)
            {
                diagnostics.AppendLine("xray-core:");
                diagnostics.AppendLine(xray.GetDiagnostics());
            }

            throw new InvalidOperationException(diagnostics.ToString().TrimEnd(), ex);
        }
        finally
        {
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            if (xrayr is not null)
            {
                await xrayr.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task DefaultRuntime_trojan_ws_outbound_can_connect_to_xrayr_trojan_ws_inbound()
    {
        if (!TryGetXrayRExecutablePath(out var xrayrExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("dotnet-trojan-ws-client-to-xrayr");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var trojanPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xrayr = null;
        await using var panel = await StartSspanelMockPanelAsync(
            nodeId: 59,
            CreateSspanelTrojanNodeInfoResponse(
                trojanPort,
                network: "ws",
                host: TrojanWebSocketHost,
                path: TrojanWebSocketPath),
            [CreateSspanelTrojanUserResponse()],
            lifetimeCts.Token);

        try
        {
            xrayr = await StartXrayRAsync(
                xrayrExecutable,
                tempDirectory,
                "xrayr-trojan-ws-server.yml",
                CreateXrayRTrojanSspanelConfig(panel.ApiHost, nodeId: 59),
                trojanPort,
                lifetimeCts.Token);

            await runtime.StartAsync(
                CreateDotnetTrojanClientPlan(
                    revision: 1,
                    localSocksPort: socksPort,
                    serverPort: trojanPort,
                    transport: TrojanOutboundTransports.Ws,
                    host: TrojanWebSocketHost,
                    path: TrojanWebSocketPath),
                lifetimeCts.Token);

            xrayr.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-dotnet-trojan-ws-client-to-xrayr", lifetimeCts.Token);

            xrayr.AssertStillRunning();
        }
        catch (Exception ex) when (xrayr is not null)
        {
            throw CreateInteropFailure(
                "Xray-dotnet Trojan ws client -> XrayR Trojan ws server interop failed.",
                runtime,
                xrayr,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xrayr is not null)
            {
                await xrayr.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task DefaultRuntime_trojan_grpc_outbound_can_connect_to_xrayr_trojan_grpc_inbound()
    {
        if (!TryGetXrayRExecutablePath(out var xrayrExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("dotnet-trojan-grpc-client-to-xrayr");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var trojanPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        XrayProcessHandle? xrayr = null;
        await using var panel = await StartSspanelMockPanelAsync(
            nodeId: 41,
            CreateSspanelTrojanNodeInfoResponse(
                trojanPort,
                network: RuntimeInternetTransportProtocols.Grpc,
                grpcServiceName: TrojanGrpcServiceName),
            [CreateSspanelTrojanUserResponse()],
            lifetimeCts.Token);

        try
        {
            xrayr = await StartXrayRAsync(
                xrayrExecutable,
                tempDirectory,
                "xrayr-trojan-grpc-server.yml",
                CreateXrayRTrojanSspanelConfig(panel.ApiHost, nodeId: 41),
                trojanPort,
                lifetimeCts.Token);

            await runtime.StartAsync(
                CreateDotnetTrojanClientPlan(
                    revision: 1,
                    localSocksPort: socksPort,
                    serverPort: trojanPort,
                    transport: TrojanOutboundTransports.Grpc,
                    grpcServiceName: TrojanGrpcServiceName),
                lifetimeCts.Token);

            xrayr.AssertStillRunning();

            await AssertEchoViaSocks5WithRetryAsync(
                socksPort,
                echoPort,
                "hello-dotnet-trojan-grpc-client-to-xrayr",
                lifetimeCts.Token);

            xrayr.AssertStillRunning();
        }
        catch (Exception ex) when (xrayr is not null)
        {
            throw CreateInteropFailure(
                "Xray-dotnet Trojan grpc client -> XrayR Trojan grpc server interop failed.",
                runtime,
                xrayr,
                ex);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xrayr is not null)
            {
                await xrayr.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task Xray_core_trojan_grpc_outbound_can_connect_to_xrayr_trojan_grpc_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable) ||
            !TryGetXrayRExecutablePath(out var xrayrExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("xray-trojan-grpc-client-to-xrayr");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var trojanPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        XrayProcessHandle? xray = null;
        XrayProcessHandle? xrayr = null;
        await using var panel = await StartSspanelMockPanelAsync(
            nodeId: 41,
            CreateSspanelTrojanNodeInfoResponse(
                trojanPort,
                network: RuntimeInternetTransportProtocols.Grpc,
                grpcServiceName: TrojanGrpcServiceName),
            [CreateSspanelTrojanUserResponse()],
            lifetimeCts.Token);

        try
        {
            xrayr = await StartXrayRAsync(
                xrayrExecutable,
                tempDirectory,
                "xrayr-trojan-grpc-server.yml",
                CreateXrayRTrojanSspanelConfig(panel.ApiHost, nodeId: 41),
                trojanPort,
                lifetimeCts.Token);

            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "socks-to-xrayr-trojan-grpc.json",
                CreateXraySocksToTrojanClientConfig(
                    socksPort,
                    trojanPort,
                    network: "grpc",
                    grpcServiceName: TrojanGrpcServiceName),
                socksPort,
                lifetimeCts.Token);

            xrayr.AssertStillRunning();
            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-xray-trojan-grpc-client-to-xrayr", lifetimeCts.Token);

            xrayr.AssertStillRunning();
            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xrayr is not null || xray is not null)
        {
            var diagnostics = new StringBuilder();
            diagnostics.AppendLine("xray-core client -> XrayR Trojan grpc server interop failed.");
            if (xrayr is not null)
            {
                diagnostics.AppendLine("xrayr:");
                diagnostics.AppendLine(xrayr.GetDiagnostics());
            }

            if (xray is not null)
            {
                diagnostics.AppendLine("xray-core:");
                diagnostics.AppendLine(xray.GetDiagnostics());
            }

            throw new InvalidOperationException(diagnostics.ToString().TrimEnd(), ex);
        }
        finally
        {
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            if (xrayr is not null)
            {
                await xrayr.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task Xray_core_trojan_ws_outbound_can_connect_to_xrayr_trojan_ws_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable) ||
            !TryGetXrayRExecutablePath(out var xrayrExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("xray-trojan-ws-client-to-xrayr");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var trojanPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        XrayProcessHandle? xray = null;
        XrayProcessHandle? xrayr = null;
        await using var panel = await StartSspanelMockPanelAsync(
            nodeId: 60,
            CreateSspanelTrojanNodeInfoResponse(
                trojanPort,
                network: "ws",
                host: TrojanWebSocketHost,
                path: TrojanWebSocketPath),
            [CreateSspanelTrojanUserResponse()],
            lifetimeCts.Token);

        try
        {
            xrayr = await StartXrayRAsync(
                xrayrExecutable,
                tempDirectory,
                "xrayr-trojan-ws-server.yml",
                CreateXrayRTrojanSspanelConfig(panel.ApiHost, nodeId: 60),
                trojanPort,
                lifetimeCts.Token);

            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "socks-to-xrayr-trojan-ws.json",
                CreateXraySocksToTrojanClientConfig(
                    socksPort,
                    trojanPort,
                    network: "ws",
                    host: TrojanWebSocketHost,
                    path: TrojanWebSocketPath),
                socksPort,
                lifetimeCts.Token);

            xrayr.AssertStillRunning();
            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-xray-trojan-ws-client-to-xrayr", lifetimeCts.Token);

            xrayr.AssertStillRunning();
            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xrayr is not null || xray is not null)
        {
            var diagnostics = new StringBuilder();
            diagnostics.AppendLine("xray-core ws client -> XrayR Trojan ws server interop failed.");
            if (xrayr is not null)
            {
                diagnostics.AppendLine("xrayr:");
                diagnostics.AppendLine(xrayr.GetDiagnostics());
            }

            if (xray is not null)
            {
                diagnostics.AppendLine("xray-core:");
                diagnostics.AppendLine(xray.GetDiagnostics());
            }

            throw new InvalidOperationException(diagnostics.ToString().TrimEnd(), ex);
        }
        finally
        {
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            if (xrayr is not null)
            {
                await xrayr.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task DefaultRuntime_trojan_httpupgrade_outbound_can_connect_to_xrayr_trojan_httpupgrade_inbound()
    {
        if (!TryGetXrayRExecutablePath(out var xrayrExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("dotnet-trojan-httpupgrade-client-to-xrayr");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var trojanPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        XrayProcessHandle? xrayr = null;
        await using var panel = await StartSspanelMockPanelAsync(
            nodeId: 41,
            CreateSspanelTrojanNodeInfoResponse(
                trojanPort,
                network: RuntimeInternetTransportProtocols.HttpUpgrade,
                host: TrojanHttpUpgradeHost,
                path: TrojanHttpUpgradePath),
            [CreateSspanelTrojanUserResponse()],
            lifetimeCts.Token);

        try
        {
            xrayr = await StartXrayRAsync(
                xrayrExecutable,
                tempDirectory,
                "xrayr-trojan-httpupgrade-server.yml",
                CreateXrayRTrojanSspanelConfig(panel.ApiHost, nodeId: 41),
                trojanPort,
                lifetimeCts.Token);

            await runtime.StartAsync(
                CreateDotnetTrojanClientPlan(
                    revision: 1,
                    localSocksPort: socksPort,
                    serverPort: trojanPort,
                    transport: TrojanOutboundTransports.HttpUpgrade,
                    host: TrojanHttpUpgradeHost,
                    path: TrojanHttpUpgradePath),
                lifetimeCts.Token);

            xrayr.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-dotnet-trojan-httpupgrade-client-to-xrayr", lifetimeCts.Token);

            xrayr.AssertStillRunning();
        }
        catch (Exception ex) when (xrayr is not null)
        {
            throw CreateInteropFailure(
                "Xray-dotnet Trojan httpupgrade client -> XrayR Trojan httpupgrade server interop failed.",
                runtime,
                xrayr,
                ex);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xrayr is not null)
            {
                await xrayr.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task Xray_core_trojan_httpupgrade_outbound_can_connect_to_xrayr_trojan_httpupgrade_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable) ||
            !TryGetXrayRExecutablePath(out var xrayrExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("xray-trojan-httpupgrade-client-to-xrayr");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var trojanPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        XrayProcessHandle? xray = null;
        XrayProcessHandle? xrayr = null;
        await using var panel = await StartSspanelMockPanelAsync(
            nodeId: 41,
            CreateSspanelTrojanNodeInfoResponse(
                trojanPort,
                network: RuntimeInternetTransportProtocols.HttpUpgrade,
                host: TrojanHttpUpgradeHost,
                path: TrojanHttpUpgradePath),
            [CreateSspanelTrojanUserResponse()],
            lifetimeCts.Token);

        try
        {
            xrayr = await StartXrayRAsync(
                xrayrExecutable,
                tempDirectory,
                "xrayr-trojan-httpupgrade-server.yml",
                CreateXrayRTrojanSspanelConfig(panel.ApiHost, nodeId: 41),
                trojanPort,
                lifetimeCts.Token);

            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "socks-to-xrayr-trojan-httpupgrade.json",
                CreateXraySocksToTrojanClientConfig(
                    socksPort,
                    trojanPort,
                    network: "httpupgrade",
                    host: TrojanHttpUpgradeHost,
                    path: TrojanHttpUpgradePath),
                socksPort,
                lifetimeCts.Token);

            xrayr.AssertStillRunning();
            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-xray-trojan-httpupgrade-client-to-xrayr", lifetimeCts.Token);

            xrayr.AssertStillRunning();
            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xrayr is not null || xray is not null)
        {
            var diagnostics = new StringBuilder();
            diagnostics.AppendLine("xray-core client -> XrayR Trojan httpupgrade server interop failed.");
            if (xrayr is not null)
            {
                diagnostics.AppendLine("xrayr:");
                diagnostics.AppendLine(xrayr.GetDiagnostics());
            }

            if (xray is not null)
            {
                diagnostics.AppendLine("xray-core:");
                diagnostics.AppendLine(xray.GetDiagnostics());
            }

            throw new InvalidOperationException(diagnostics.ToString().TrimEnd(), ex);
        }
        finally
        {
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            if (xrayr is not null)
            {
                await xrayr.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task DefaultRuntime_trojan_splithttp_outbound_can_connect_to_xrayr_trojan_splithttp_inbound()
    {
        if (!TryGetXrayRExecutablePath(out var xrayrExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("dotnet-trojan-splithttp-client-to-xrayr");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var trojanPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xrayr = null;
        await using var panel = await StartSspanelMockPanelAsync(
            nodeId: 57,
            CreateSspanelTrojanNodeInfoResponse(
                trojanPort,
                network: "splithttp",
                host: TrojanSplitHttpHost,
                path: TrojanSplitHttpPath),
            [CreateSspanelTrojanUserResponse()],
            lifetimeCts.Token);

        try
        {
            xrayr = await StartXrayRAsync(
                xrayrExecutable,
                tempDirectory,
                "xrayr-trojan-splithttp-server.yml",
                CreateXrayRTrojanSspanelConfig(panel.ApiHost, nodeId: 57),
                trojanPort,
                lifetimeCts.Token);

            await runtime.StartAsync(
                CreateDotnetTrojanClientPlan(
                    revision: 1,
                    localSocksPort: socksPort,
                    serverPort: trojanPort,
                    transport: TrojanOutboundTransports.SplitHttp,
                    host: TrojanSplitHttpHost,
                    path: TrojanSplitHttpPath),
                lifetimeCts.Token);

            xrayr.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-dotnet-trojan-splithttp-client-to-xrayr", lifetimeCts.Token);

            xrayr.AssertStillRunning();
        }
        catch (Exception ex) when (xrayr is not null)
        {
            throw CreateInteropFailure(
                "Xray-dotnet Trojan splithttp client -> XrayR Trojan splithttp server interop failed.",
                runtime,
                xrayr,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xrayr is not null)
            {
                await xrayr.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task Xray_core_trojan_splithttp_outbound_can_connect_to_xrayr_trojan_splithttp_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable) ||
            !TryGetXrayRExecutablePath(out var xrayrExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("xray-trojan-splithttp-client-to-xrayr");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var trojanPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        XrayProcessHandle? xray = null;
        XrayProcessHandle? xrayr = null;
        await using var panel = await StartSspanelMockPanelAsync(
            nodeId: 58,
            CreateSspanelTrojanNodeInfoResponse(
                trojanPort,
                network: "splithttp",
                host: TrojanSplitHttpHost,
                path: TrojanSplitHttpPath),
            [CreateSspanelTrojanUserResponse()],
            lifetimeCts.Token);

        try
        {
            xrayr = await StartXrayRAsync(
                xrayrExecutable,
                tempDirectory,
                "xrayr-trojan-splithttp-server.yml",
                CreateXrayRTrojanSspanelConfig(panel.ApiHost, nodeId: 58),
                trojanPort,
                lifetimeCts.Token);

            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "socks-to-xrayr-trojan-splithttp.json",
                CreateXraySocksToTrojanClientConfig(
                    socksPort,
                    trojanPort,
                    network: "splithttp",
                    host: TrojanSplitHttpHost,
                    path: TrojanSplitHttpPath),
                socksPort,
                lifetimeCts.Token);

            xrayr.AssertStillRunning();
            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-xray-trojan-splithttp-client-to-xrayr", lifetimeCts.Token);

            xrayr.AssertStillRunning();
            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xrayr is not null || xray is not null)
        {
            var diagnostics = new StringBuilder();
            diagnostics.AppendLine("xray-core splithttp client -> XrayR Trojan splithttp server interop failed.");
            if (xrayr is not null)
            {
                diagnostics.AppendLine("xrayr:");
                diagnostics.AppendLine(xrayr.GetDiagnostics());
            }

            if (xray is not null)
            {
                diagnostics.AppendLine("xray-core:");
                diagnostics.AppendLine(xray.GetDiagnostics());
            }

            throw new InvalidOperationException(diagnostics.ToString().TrimEnd(), ex);
        }
        finally
        {
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            if (xrayr is not null)
            {
                await xrayr.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task Xray_core_trojan_httpupgrade_outbound_can_connect_to_default_runtime_trojan_httpupgrade_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("xray-trojan-httpupgrade-client-to-dotnet");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var trojanPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        XrayProcessHandle? xray = null;

        try
        {
            await runtime.StartAsync(
                CreateDotnetTrojanServerPlan(
                    revision: 1,
                    inboundPort: trojanPort,
                    transportProtocol: RuntimeInternetTransportProtocols.HttpUpgrade,
                    host: TrojanHttpUpgradeHost,
                    path: TrojanHttpUpgradePath),
                lifetimeCts.Token);

            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "socks-to-trojan-httpupgrade.json",
                CreateXraySocksToTrojanClientConfig(
                    socksPort,
                    trojanPort,
                    network: "httpupgrade",
                    host: TrojanHttpUpgradeHost,
                    path: TrojanHttpUpgradePath),
                socksPort,
                lifetimeCts.Token);

            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-xray-trojan-httpupgrade-client-to-dotnet", lifetimeCts.Token);

            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw CreateInteropFailure(
                "xray-core Trojan httpupgrade client -> Xray-dotnet Trojan httpupgrade server interop failed.",
                runtime,
                xray,
                ex);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task Xray_core_trojan_splithttp_outbound_can_connect_to_default_runtime_trojan_splithttp_inbound()
    {
        if (!TryGetXrayExecutablePath(out var xrayExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var tempDirectory = CreateInteropTempDirectory("xray-trojan-splithttp-client-to-dotnet");
        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var trojanPort = GetAvailableTcpPort();
        var socksPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        XrayProcessHandle? xray = null;

        try
        {
            await runtime.StartAsync(
                CreateDotnetTrojanServerPlan(
                    revision: 1,
                    inboundPort: trojanPort,
                    transportProtocol: RuntimeInternetTransportProtocols.SplitHttp,
                    host: TrojanSplitHttpHost,
                    path: TrojanSplitHttpPath),
                lifetimeCts.Token);

            xray = await StartXrayAsync(
                xrayExecutable,
                tempDirectory,
                "socks-to-trojan-splithttp.json",
                CreateXraySocksToTrojanClientConfig(
                    socksPort,
                    trojanPort,
                    network: "splithttp",
                    host: TrojanSplitHttpHost,
                    path: TrojanSplitHttpPath),
                socksPort,
                lifetimeCts.Token);

            xray.AssertStillRunning();

            using var client = await ConnectViaSocks5Async(socksPort, echoPort, lifetimeCts.Token);
            await using var stream = client.GetStream();
            await AssertEchoAsync(stream, "hello-xray-trojan-splithttp-client-to-dotnet", lifetimeCts.Token);

            xray.AssertStillRunning();
        }
        catch (Exception ex) when (xray is not null)
        {
            throw CreateInteropFailure(
                "xray-core Trojan splithttp client -> Xray-dotnet Trojan splithttp server interop failed.",
                runtime,
                xray,
                ex,
                runtimeEvents);
        }
        finally
        {
            await StopRuntimeAsync(runtime);
            if (xray is not null)
            {
                await xray.DisposeAsync();
            }

            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
            TryDeleteDirectory(tempDirectory);
        }
    }

    [Fact]
    public async Task Grpc_go_trojan_client_with_split_header_and_payload_can_connect_to_default_runtime_trojan_grpc_inbound()
    {
        if (!TryGetGoExecutablePath(out var goExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var workspaceRoot = FindWorkspaceRoot();
        var helperPath = Path.Combine(
            workspaceRoot,
            "xray-core",
            ".codex-probes",
            "trojan-grpc-split-client",
            "main.go");
        Assert.True(File.Exists(helperPath), $"Missing grpc-go Trojan split-client helper: {helperPath}");

        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var trojanPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        Process? process = null;

        try
        {
            await runtime.StartAsync(
                CreateDotnetTrojanServerPlan(
                    revision: 1,
                    inboundPort: trojanPort,
                    transportProtocol: RuntimeInternetTransportProtocols.Grpc,
                    grpcServiceName: TrojanGrpcServiceName),
                lifetimeCts.Token);

            process = new Process
            {
                StartInfo = CreateGoHelperStartInfo(
                    goExecutable,
                    workspaceRoot,
                    helperPath,
                    trojanPort.ToString(),
                    echoPort.ToString())
            };

            Assert.True(process.Start(), "Failed to start grpc-go Trojan split-client helper.");
            var (stdout, stderr) = await WaitForProcessExitWithDiagnosticsAsync(
                process,
                "grpc-go Trojan split-client helper",
                runtime,
                runtimeEvents,
                lifetimeCts.Token);

            Assert.True(
                process.ExitCode == 0,
                $"grpc-go trojan split-client exit code: {process.ExitCode}{Environment.NewLine}stdout:{Environment.NewLine}{stdout}{Environment.NewLine}stderr:{Environment.NewLine}{stderr}");
            Assert.Contains("ok", stdout, StringComparison.Ordinal);
            Assert.True(string.IsNullOrWhiteSpace(stderr), $"grpc-go trojan split-client stderr: {stderr}");
        }
        finally
        {
            if (process is not null)
            {
                TryTerminateProcess(process);
                process.Dispose();
            }

            await StopRuntimeAsync(runtime);
            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
        }
    }

    [Fact]
    public async Task Grpc_go_trojan_client_with_xray_like_header_only_and_concurrent_response_can_connect_to_default_runtime_trojan_grpc_inbound()
    {
        if (!TryGetGoExecutablePath(out var goExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var workspaceRoot = FindWorkspaceRoot();
        var helperPath = Path.Combine(
            workspaceRoot,
            "xray-core",
            ".codex-probes",
            "trojan-grpc-xray-like-client",
            "main.go");
        Assert.True(File.Exists(helperPath), $"Missing grpc-go Trojan xray-like helper: {helperPath}");

        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var trojanPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        Process? process = null;

        try
        {
            await runtime.StartAsync(
                CreateDotnetTrojanServerPlan(
                    revision: 1,
                    inboundPort: trojanPort,
                    transportProtocol: RuntimeInternetTransportProtocols.Grpc,
                    grpcServiceName: TrojanGrpcServiceName),
                lifetimeCts.Token);

            process = new Process
            {
                StartInfo = CreateGoHelperStartInfo(
                    goExecutable,
                    workspaceRoot,
                    helperPath,
                    trojanPort.ToString(),
                    echoPort.ToString())
            };

            Assert.True(process.Start(), "Failed to start grpc-go Trojan xray-like helper.");
            var (stdout, stderr) = await WaitForProcessExitWithDiagnosticsAsync(
                process,
                "grpc-go Trojan xray-like helper",
                runtime,
                runtimeEvents,
                lifetimeCts.Token);

            Assert.True(
                process.ExitCode == 0,
                $"grpc-go trojan xray-like helper exit code: {process.ExitCode}{Environment.NewLine}stdout:{Environment.NewLine}{stdout}{Environment.NewLine}stderr:{Environment.NewLine}{stderr}");
            Assert.Contains("ok", stdout, StringComparison.Ordinal);
            Assert.True(string.IsNullOrWhiteSpace(stderr), $"grpc-go trojan xray-like helper stderr: {stderr}");
        }
        finally
        {
            if (process is not null)
            {
                TryTerminateProcess(process);
                process.Dispose();
            }

            await StopRuntimeAsync(runtime);
            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
        }
    }

    [Fact]
    public async Task Xray_trojan_client_process_path_can_connect_to_default_runtime_trojan_grpc_inbound()
    {
        if (!TryGetGoExecutablePath(out var goExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var workspaceRoot = FindWorkspaceRoot();
        var helperPath = Path.Combine(
            workspaceRoot,
            "xray-core",
            ".codex-probes",
            "trojan-grpc-process-client",
            "main.go");
        Assert.True(File.Exists(helperPath), $"Missing Trojan process-path helper: {helperPath}");

        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var trojanPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        Process? process = null;

        try
        {
            await runtime.StartAsync(
                CreateDotnetTrojanServerPlan(
                    revision: 1,
                    inboundPort: trojanPort,
                    transportProtocol: RuntimeInternetTransportProtocols.Grpc,
                    grpcServiceName: TrojanGrpcServiceName),
                lifetimeCts.Token);

            process = new Process
            {
                StartInfo = CreateGoHelperStartInfo(
                    goExecutable,
                    workspaceRoot,
                    helperPath,
                    trojanPort.ToString(),
                    echoPort.ToString())
            };

            Assert.True(process.Start(), "Failed to start Trojan process-path helper.");
            var (stdout, stderr) = await WaitForProcessExitWithDiagnosticsAsync(
                process,
                "Trojan process-path helper",
                runtime,
                runtimeEvents,
                lifetimeCts.Token);

            Assert.True(
                process.ExitCode == 0,
                $"Trojan process-path helper exit code: {process.ExitCode}{Environment.NewLine}stdout:{Environment.NewLine}{stdout}{Environment.NewLine}stderr:{Environment.NewLine}{stderr}");
            Assert.Contains("ok", stdout, StringComparison.Ordinal);
            Assert.True(string.IsNullOrWhiteSpace(stderr), $"Trojan process-path helper stderr: {stderr}");
        }
        finally
        {
            if (process is not null)
            {
                TryTerminateProcess(process);
                process.Dispose();
            }

            await StopRuntimeAsync(runtime);
            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
        }
    }

    [Fact]
    public async Task Xray_trojan_client_process_with_tcp_link_can_connect_to_default_runtime_trojan_grpc_inbound()
    {
        if (!TryGetGoExecutablePath(out var goExecutable))
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var workspaceRoot = FindWorkspaceRoot();
        var helperPath = Path.Combine(
            workspaceRoot,
            "xray-core",
            ".codex-probes",
            "trojan-grpc-process-tcp-link-client",
            "main.go");
        Assert.True(File.Exists(helperPath), $"Missing Trojan process TCP-link helper: {helperPath}");

        var (echoListener, echoTask, echoPort) = StartEchoServer(lifetimeCts.Token);
        var trojanPort = GetAvailableTcpPort();
        await using var runtime = new DefaultRuntime();
        await using var runtimeEvents = new RuntimeEventCollector(runtime);
        Process? process = null;

        try
        {
            await runtime.StartAsync(
                CreateDotnetTrojanServerPlan(
                    revision: 1,
                    inboundPort: trojanPort,
                    transportProtocol: RuntimeInternetTransportProtocols.Grpc,
                    grpcServiceName: TrojanGrpcServiceName),
                lifetimeCts.Token);

            process = new Process
            {
                StartInfo = CreateGoHelperStartInfo(
                    goExecutable,
                    workspaceRoot,
                    helperPath,
                    trojanPort.ToString(),
                    echoPort.ToString())
            };

            Assert.True(process.Start(), "Failed to start Trojan process TCP-link helper.");
            var (stdout, stderr) = await WaitForProcessExitWithDiagnosticsAsync(
                process,
                "Trojan process TCP-link helper",
                runtime,
                runtimeEvents,
                lifetimeCts.Token);

            Assert.True(
                process.ExitCode == 0,
                $"Trojan process TCP-link helper exit code: {process.ExitCode}{Environment.NewLine}stdout:{Environment.NewLine}{stdout}{Environment.NewLine}stderr:{Environment.NewLine}{stderr}");
            Assert.Contains("ok", stdout, StringComparison.Ordinal);
            Assert.True(string.IsNullOrWhiteSpace(stderr), $"Trojan process TCP-link helper stderr: {stderr}");
        }
        finally
        {
            if (process is not null)
            {
                TryTerminateProcess(process);
                process.Dispose();
            }

            await StopRuntimeAsync(runtime);
            lifetimeCts.Cancel();
            echoListener.Stop();
            await AwaitCompletionAsync(echoTask);
        }
    }

    private static RuntimePlan CreateDotnetVlessClientPlan(
        int revision,
        int localSocksPort,
        int serverPort,
        string transport = VlessOutboundTransports.Tcp,
        string transportSecurity = "",
        string host = "",
        string path = "",
        string grpcServiceName = "",
        string serverName = "",
        string fingerprint = "",
        bool skipCertificateValidation = false,
        RuntimeRealityOptions? realityOptions = null,
        string flow = "")
    {
        var settings = new RuntimeVlessOutboundOptions
        {
            Tag = "vless-out",
            ServerHost = IPAddress.Loopback.ToString(),
            ServerPort = serverPort,
            Transport = transport,
            TransportSecurity = string.IsNullOrWhiteSpace(transportSecurity)
                ? ResolveOutboundTransportSecurity(transport)
                : RuntimeInternetSecurityTypes.Normalize(transportSecurity),
            ServerName = serverName,
            Fingerprint = fingerprint,
            RealityOptions = realityOptions ?? RuntimeRealityOptions.Empty,
            WebSocketPath = path,
            WebSocketHeaders = CreateOptionalHostHeader(host),
            SplitHttpHost = host,
            SplitHttpPath = path,
            GrpcServiceName = grpcServiceName,
            UserUuid = UserUuid,
            Flow = flow,
            SkipCertificateValidation = skipCertificateValidation,
            ConnectTimeoutSeconds = 5,
            HandshakeTimeoutSeconds = 5
        };

        return new RuntimePlan
        {
            Revision = revision,
            Plan = new NodeRuntimePlan
            {
                Inbounds = InboundRuntimePlanCollection.Empty,
                Outbound = new OutboundRuntimePlan
                {
                    Outbounds =
                    [
                        new OutboundRuntime
                        {
                            Tag = "vless-out",
                            Protocol = OutboundProtocols.Vless
                        }
                    ],
                    DefaultOutboundTag = "vless-out"
                }
            },
            TransportLimits = new RuntimeTransportLimits(),
            Dns = DnsRuntimeSettings.Default,
            ProxyInbounds = new ProxyInboundRuntimePlan
            {
                SocksListeners =
                [
                    new ProxyInboundListenerDefinition
                    {
                        Tag = "socks-local",
                        Binding = new ListenerBinding("127.0.0.1", localSocksPort),
                        HandshakeTimeoutSeconds = 10
                    }
                ]
            },
            OutboundSettings = RuntimeOutboundSettingsCatalog.Create(
                new IRuntimeOutboundOptions[]
                {
                    settings
                }),
            ActiveUsers = Array.Empty<IRuntimeUserDefinition>()
        };
    }

    private static RuntimePlan CreateDotnetVmessClientPlan(
        int revision,
        int localSocksPort,
        int serverPort,
        string transport = VmessOutboundTransports.Tcp,
        string host = "",
        string path = "",
        string grpcServiceName = "",
        string serverName = "",
        string fingerprint = "",
        bool skipCertificateValidation = false)
    {
        var settings = new RuntimeVmessOutboundOptions
        {
            Tag = "vmess-out",
            ServerHost = IPAddress.Loopback.ToString(),
            ServerPort = serverPort,
            Transport = transport,
            TransportSecurity = ResolveOutboundTransportSecurity(transport),
            ServerName = serverName,
            Fingerprint = fingerprint,
            WebSocketPath = path,
            WebSocketHeaders = CreateOptionalHostHeader(host),
            SplitHttpHost = host,
            SplitHttpPath = path,
            GrpcServiceName = grpcServiceName,
            UserUuid = UserUuid,
            Security = VmessOutboundSecurityTypes.Aes128Gcm,
            SkipCertificateValidation = skipCertificateValidation,
            ConnectTimeoutSeconds = 5,
            HandshakeTimeoutSeconds = 5
        };

        return new RuntimePlan
        {
            Revision = revision,
            Plan = new NodeRuntimePlan
            {
                Inbounds = InboundRuntimePlanCollection.Empty,
                Outbound = new OutboundRuntimePlan
                {
                    Outbounds =
                    [
                        new OutboundRuntime
                        {
                            Tag = "vmess-out",
                            Protocol = OutboundProtocols.Vmess
                        }
                    ],
                    DefaultOutboundTag = "vmess-out"
                }
            },
            TransportLimits = new RuntimeTransportLimits(),
            Dns = DnsRuntimeSettings.Default,
            ProxyInbounds = new ProxyInboundRuntimePlan
            {
                SocksListeners =
                [
                    new ProxyInboundListenerDefinition
                    {
                        Tag = "socks-local",
                        Binding = new ListenerBinding("127.0.0.1", localSocksPort),
                        HandshakeTimeoutSeconds = 10
                    }
                ]
            },
            OutboundSettings = RuntimeOutboundSettingsCatalog.Create(
                new IRuntimeOutboundOptions[]
                {
                    settings
                }),
            ActiveUsers = Array.Empty<IRuntimeUserDefinition>()
        };
    }

    private static RuntimePlan CreateDotnetVlessServerPlan(
        int revision,
        int inboundPort,
        string transportProtocol = RuntimeInternetTransportProtocols.Tcp,
        string transportSecurity = RuntimeInternetSecurityTypes.None,
        string host = "",
        string path = "",
        string grpcServiceName = "",
        RuntimeTlsOptions? tls = null,
        RuntimeRealityServerOptions? reality = null,
        string userFlow = "")
    {
        var user = new TestVlessUserDefinition
        {
            UserId = UserId,
            Uuid = UserUuid,
            Flow = userFlow,
            BytesPerSecond = 0
        };
        var inbound = new TestVlessInboundDefinition
        {
            Tag = "vless-plain",
            Enabled = true,
            Protocol = InboundProtocols.Vless,
            Transport = string.Empty,
            TransportProtocol = transportProtocol,
            TransportSecurity = transportSecurity,
            ListenAddress = "127.0.0.1",
            Port = inboundPort,
            HandshakeTimeoutSeconds = 10,
            Host = host,
            Path = path,
            GrpcServiceName = grpcServiceName,
            Users = new IVlessUserDefinition[]
            {
                user
            }
        };

        var built = VlessInboundRuntimePlanner.TryBuild(
            new IVlessInboundDefinition[]
            {
                inbound
            },
            out var inboundPlan,
            out var error);

        Assert.True(built, error);

        return new RuntimePlan
        {
            Revision = revision,
            Tls = tls,
            Reality = reality,
            Plan = new NodeRuntimePlan
            {
                Inbounds = InboundRuntimePlanCollection.Create(
                    new IInboundProtocolRuntimePlan[]
                    {
                        inboundPlan
                    }),
                Outbound = new OutboundRuntimePlan
                {
                    Outbounds =
                    [
                        new OutboundRuntime
                        {
                            Tag = "direct",
                            Protocol = OutboundProtocols.Freedom
                        }
                    ],
                    DefaultOutboundTag = "direct"
                }
            },
            TransportLimits = new RuntimeTransportLimits(),
            Dns = DnsRuntimeSettings.Default,
            ProxyInbounds = ProxyInboundRuntimePlan.Empty,
            OutboundSettings = RuntimeOutboundSettingsCatalog.Empty,
            ActiveUsers = new IRuntimeUserDefinition[]
            {
                user
            }
        };
    }

    private static RuntimePlan CreateDotnetVmessServerPlan(
        int revision,
        int inboundPort,
        string transportProtocol = RuntimeInternetTransportProtocols.Tcp,
        string transportSecurity = RuntimeInternetSecurityTypes.None,
        string host = "",
        string path = "",
        string grpcServiceName = "",
        RuntimeTlsOptions? tls = null,
        RuntimeRealityServerOptions? reality = null)
    {
        var user = new TestVmessUserDefinition
        {
            UserId = UserId,
            Uuid = UserUuid,
            BytesPerSecond = 0
        };
        var inbound = new TestVmessInboundDefinition
        {
            Tag = "vmess-plain",
            Enabled = true,
            Protocol = InboundProtocols.Vmess,
            Transport = string.Empty,
            TransportProtocol = transportProtocol,
            TransportSecurity = transportSecurity,
            ListenAddress = "127.0.0.1",
            Port = inboundPort,
            HandshakeTimeoutSeconds = 10,
            Host = host,
            Path = path,
            GrpcServiceName = grpcServiceName,
            Users = new IVmessUserDefinition[]
            {
                user
            }
        };

        var built = VmessInboundRuntimePlanner.TryBuild(
            new IVmessInboundDefinition[]
            {
                inbound
            },
            out var inboundPlan,
            out var error);

        Assert.True(built, error);

        return new RuntimePlan
        {
            Revision = revision,
            Tls = tls,
            Reality = reality,
            Plan = new NodeRuntimePlan
            {
                Inbounds = InboundRuntimePlanCollection.Create(
                    new IInboundProtocolRuntimePlan[]
                    {
                        inboundPlan
                    }),
                Outbound = new OutboundRuntimePlan
                {
                    Outbounds =
                    [
                        new OutboundRuntime
                        {
                            Tag = "direct",
                            Protocol = OutboundProtocols.Freedom
                        }
                    ],
                    DefaultOutboundTag = "direct"
                }
            },
            TransportLimits = new RuntimeTransportLimits(),
            Dns = DnsRuntimeSettings.Default,
            ProxyInbounds = ProxyInboundRuntimePlan.Empty,
            OutboundSettings = RuntimeOutboundSettingsCatalog.Empty,
            ActiveUsers = new IRuntimeUserDefinition[]
            {
                user
            }
        };
    }

    private static RuntimePlan CreateDotnetTrojanClientPlan(
        int revision,
        int localSocksPort,
        int serverPort,
        string transport = TrojanOutboundTransports.Tcp,
        string host = "",
        string path = "",
        string grpcServiceName = "",
        string serverName = "",
        string fingerprint = "",
        bool skipCertificateValidation = false)
    {
        var settings = new RuntimeTrojanOutboundOptions
        {
            Tag = "trojan-out",
            ServerHost = IPAddress.Loopback.ToString(),
            ServerPort = serverPort,
            Transport = transport,
            TransportSecurity = ResolveOutboundTransportSecurity(transport),
            ServerName = serverName,
            Fingerprint = fingerprint,
            WebSocketPath = path,
            WebSocketHeaders = CreateOptionalHostHeader(host),
            SplitHttpHost = host,
            SplitHttpPath = path,
            GrpcServiceName = grpcServiceName,
            Password = TrojanSharedPassword,
            SkipCertificateValidation = skipCertificateValidation,
            ConnectTimeoutSeconds = 5,
            HandshakeTimeoutSeconds = 5
        };

        return new RuntimePlan
        {
            Revision = revision,
            Plan = new NodeRuntimePlan
            {
                Inbounds = InboundRuntimePlanCollection.Empty,
                Outbound = new OutboundRuntimePlan
                {
                    Outbounds =
                    [
                        new OutboundRuntime
                        {
                            Tag = "trojan-out",
                            Protocol = OutboundProtocols.Trojan
                        }
                    ],
                    DefaultOutboundTag = "trojan-out"
                }
            },
            TransportLimits = new RuntimeTransportLimits(),
            Dns = DnsRuntimeSettings.Default,
            ProxyInbounds = new ProxyInboundRuntimePlan
            {
                SocksListeners =
                [
                    new ProxyInboundListenerDefinition
                    {
                        Tag = "socks-local",
                        Binding = new ListenerBinding("127.0.0.1", localSocksPort),
                        HandshakeTimeoutSeconds = 10
                    }
                ]
            },
            OutboundSettings = RuntimeOutboundSettingsCatalog.Create(
                new IRuntimeOutboundOptions[]
                {
                    settings
                }),
            ActiveUsers = Array.Empty<IRuntimeUserDefinition>()
        };
    }

    private static RuntimePlan CreateDotnetTrojanServerPlan(
        int revision,
        int inboundPort,
        string transportProtocol = RuntimeInternetTransportProtocols.Tcp,
        string transportSecurity = RuntimeInternetSecurityTypes.None,
        string host = "",
        string path = "",
        string grpcServiceName = "",
        RuntimeTlsOptions? tls = null,
        RuntimeRealityServerOptions? reality = null)
    {
        var user = new TestTrojanUserDefinition
        {
            UserId = UserId,
            Password = TrojanSharedPassword,
            BytesPerSecond = 0
        };
        var inbound = new TestTrojanInboundDefinition
        {
            Tag = "trojan-plain",
            Enabled = true,
            Protocol = InboundProtocols.Trojan,
            Transport = string.Empty,
            TransportProtocol = transportProtocol,
            TransportSecurity = transportSecurity,
            ListenAddress = "127.0.0.1",
            Port = inboundPort,
            HandshakeTimeoutSeconds = 10,
            Host = host,
            Path = path,
            GrpcServiceName = grpcServiceName,
            Users = new ITrojanUserDefinition[]
            {
                user
            }
        };

        var built = TrojanInboundRuntimePlanner.TryBuild(
            new ITrojanInboundDefinition[]
            {
                inbound
            },
            out var inboundPlan,
            out var error);

        Assert.True(built, error);

        return new RuntimePlan
        {
            Revision = revision,
            Tls = tls,
            Reality = reality,
            Plan = new NodeRuntimePlan
            {
                Inbounds = InboundRuntimePlanCollection.Create(
                    new IInboundProtocolRuntimePlan[]
                    {
                        inboundPlan
                    }),
                Outbound = new OutboundRuntimePlan
                {
                    Outbounds =
                    [
                        new OutboundRuntime
                        {
                            Tag = "direct",
                            Protocol = OutboundProtocols.Freedom
                        }
                    ],
                    DefaultOutboundTag = "direct"
                }
            },
            TransportLimits = new RuntimeTransportLimits(),
            Dns = DnsRuntimeSettings.Default,
            ProxyInbounds = ProxyInboundRuntimePlan.Empty,
            OutboundSettings = RuntimeOutboundSettingsCatalog.Empty,
            ActiveUsers = new IRuntimeUserDefinition[]
            {
                user
            }
        };
    }

    private static object CreateXrayVlessServerConfig(
        int vlessPort,
        string network = "tcp",
        string host = "",
        string path = "",
        string grpcServiceName = "",
        string security = "none",
        string certificateFile = "",
        string keyFile = "",
        string flow = "",
        object? realitySettings = null)
        => new
        {
            log = new
            {
                loglevel = "debug"
            },
            inbounds = new object[]
            {
                new
                {
                    tag = "vless-in",
                    listen = "127.0.0.1",
                    port = vlessPort,
                    protocol = "vless",
                    settings = new
                    {
                        clients = new object[]
                        {
                            new
                            {
                                id = UserUuid,
                                flow,
                                level = 0,
                                email = "interop@example.com"
                            }
                        },
                        decryption = "none"
                    },
                    streamSettings = CreateXrayStreamSettings(
                        network,
                        host,
                        path,
                        grpcServiceName,
                        security,
                        string.Empty,
                        allowInsecure: false,
                        certificateFile,
                        keyFile,
                        realitySettings: realitySettings)
                }
            },
            outbounds = new object[]
            {
                new
                {
                    tag = "direct",
                    protocol = "freedom"
                }
            }
        };

    private static object CreateXrayTrojanServerConfig(
        int trojanPort,
        string network = "tcp",
        string host = "",
        string path = "",
        string grpcServiceName = "",
        string security = "none",
        string certificateFile = "",
        string keyFile = "")
        => new
        {
            log = new
            {
                loglevel = "debug"
            },
            inbounds = new object[]
            {
                new
                {
                    tag = "trojan-in",
                    listen = "127.0.0.1",
                    port = trojanPort,
                    protocol = "trojan",
                    settings = new
                    {
                        clients = new object[]
                        {
                            new
                            {
                                password = TrojanSharedPassword,
                                level = 0,
                                email = "interop@example.com"
                            }
                        }
                    },
                    streamSettings = CreateXrayStreamSettings(
                        network,
                        host,
                        path,
                        grpcServiceName,
                        security,
                        string.Empty,
                        allowInsecure: false,
                        certificateFile,
                        keyFile)
                }
            },
            outbounds = new object[]
            {
                new
                {
                    tag = "direct",
                    protocol = "freedom"
                }
            }
        };

    private static object CreateXrayVmessServerConfig(
        int vmessPort,
        string network = "tcp",
        string host = "",
        string path = "",
        string grpcServiceName = "",
        string security = "none",
        string certificateFile = "",
        string keyFile = "")
        => new
        {
            log = new
            {
                loglevel = "debug"
            },
            inbounds = new object[]
            {
                new
                {
                    tag = "vmess-in",
                    listen = "127.0.0.1",
                    port = vmessPort,
                    protocol = "vmess",
                    settings = new
                    {
                        clients = new object[]
                        {
                            new
                            {
                                id = UserUuid,
                                alterId = 0,
                                level = 0,
                                email = "interop@example.com"
                            }
                        }
                    },
                    streamSettings = CreateXrayStreamSettings(
                        network,
                        host,
                        path,
                        grpcServiceName,
                        security,
                        string.Empty,
                        allowInsecure: false,
                        certificateFile,
                        keyFile)
                }
            },
            outbounds = new object[]
            {
                new
                {
                    tag = "direct",
                    protocol = "freedom"
                }
            }
        };

    private static object CreateXraySocksToVlessClientConfig(
        int socksPort,
        int vlessPort,
        string network = "tcp",
        string host = "",
        string path = "",
        string grpcServiceName = "",
        string security = "none",
        string serverName = "",
        bool allowInsecure = false,
        string fingerprint = "",
        string flow = "",
        object? realitySettings = null)
        => new
        {
            log = new
            {
                loglevel = "debug"
            },
            inbounds = new object[]
            {
                new
                {
                    tag = "socks-in",
                    listen = "127.0.0.1",
                    port = socksPort,
                    protocol = "socks",
                    settings = new
                    {
                        auth = "noauth",
                        udp = false
                    }
                }
            },
            outbounds = new object[]
            {
                new
                {
                    tag = "proxy",
                    protocol = "vless",
                    settings = new
                    {
                        vnext = new object[]
                        {
                            new
                            {
                                address = "127.0.0.1",
                                port = vlessPort,
                                users = new object[]
                                {
                                    new
                                    {
                                        id = UserUuid,
                                        flow,
                                        encryption = "none",
                                        level = 0
                                    }
                                }
                            }
                        }
                    },
                    streamSettings = CreateXrayStreamSettings(
                        network,
                        host,
                        path,
                        grpcServiceName,
                        security,
                        serverName,
                        allowInsecure,
                        fingerprint: fingerprint,
                        realitySettings: realitySettings)
                }
            }
        };

    private static object CreateXraySocksToVmessClientConfig(
        int socksPort,
        int vmessPort,
        string network = "tcp",
        string host = "",
        string path = "",
        string grpcServiceName = "",
        string security = "none",
        string serverName = "",
        bool allowInsecure = false,
        string fingerprint = "")
        => new
        {
            log = new
            {
                loglevel = "debug"
            },
            inbounds = new object[]
            {
                new
                {
                    tag = "socks-in",
                    listen = "127.0.0.1",
                    port = socksPort,
                    protocol = "socks",
                    settings = new
                    {
                        auth = "noauth",
                        udp = false
                    }
                }
            },
            outbounds = new object[]
            {
                new
                {
                    tag = "proxy",
                    protocol = "vmess",
                    settings = new
                    {
                        vnext = new object[]
                        {
                            new
                            {
                                address = "127.0.0.1",
                                port = vmessPort,
                                users = new object[]
                                {
                                    new
                                    {
                                        id = UserUuid,
                                        alterId = 0,
                                        security = "auto",
                                        level = 0
                                    }
                                }
                            }
                        }
                    },
                    streamSettings = CreateXrayStreamSettings(
                        network,
                        host,
                        path,
                        grpcServiceName,
                        security,
                        serverName,
                        allowInsecure,
                        fingerprint: fingerprint)
                }
            }
        };

    private static object CreateXraySocksToTrojanClientConfig(
        int socksPort,
        int trojanPort,
        string network = "tcp",
        string host = "",
        string path = "",
        string grpcServiceName = "",
        string security = "none",
        string serverName = "",
        bool allowInsecure = false,
        string fingerprint = "")
        => new
        {
            log = new
            {
                loglevel = "debug"
            },
            inbounds = new object[]
            {
                new
                {
                    tag = "socks-in",
                    listen = "127.0.0.1",
                    port = socksPort,
                    protocol = "socks",
                    settings = new
                    {
                        auth = "noauth",
                        udp = false
                    }
                }
            },
            outbounds = new object[]
            {
                new
                {
                    tag = "proxy",
                    protocol = "trojan",
                    settings = new
                    {
                        servers = new object[]
                        {
                            new
                            {
                                address = "127.0.0.1",
                                port = trojanPort,
                                password = TrojanSharedPassword,
                                level = 0,
                                email = "interop@example.com"
                            }
                        }
                    },
                    streamSettings = CreateXrayStreamSettings(
                        network,
                        host,
                        path,
                        grpcServiceName,
                        security,
                        serverName,
                        allowInsecure,
                        fingerprint: fingerprint)
                }
            }
        };

    private static Dictionary<string, object?> CreateXrayStreamSettings(
        string network,
        string host,
        string path,
        string grpcServiceName,
        string security = "none",
        string serverName = "",
        bool allowInsecure = false,
        string certificateFile = "",
        string keyFile = "",
        string fingerprint = "",
        object? realitySettings = null)
    {
        var settings = new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            ["network"] = network,
            ["security"] = security
        };

        if (string.Equals(network, "httpupgrade", StringComparison.OrdinalIgnoreCase))
        {
            settings["httpupgradeSettings"] = new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["host"] = host,
                ["path"] = path
            };
        }
        else if (string.Equals(network, "grpc", StringComparison.OrdinalIgnoreCase))
        {
            settings["grpcSettings"] = new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["serviceName"] = grpcServiceName
            };
        }
        else if (string.Equals(network, "ws", StringComparison.OrdinalIgnoreCase))
        {
            settings["wsSettings"] = new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["host"] = host,
                ["path"] = path
            };
        }
        else if (string.Equals(network, "splithttp", StringComparison.OrdinalIgnoreCase) ||
                 string.Equals(network, "xhttp", StringComparison.OrdinalIgnoreCase))
        {
            settings["splithttpSettings"] = new Dictionary<string, object?>(StringComparer.Ordinal)
            {
                ["host"] = host,
                ["path"] = path
            };
        }
        else if (string.Equals(network, RuntimeInternetTransportProtocols.Mkcp, StringComparison.OrdinalIgnoreCase) ||
                 string.Equals(network, "kcp", StringComparison.OrdinalIgnoreCase))
        {
            settings["kcpSettings"] = new Dictionary<string, object?>(StringComparer.Ordinal);
        }

        if (string.Equals(security, RuntimeInternetSecurityTypes.Tls, StringComparison.OrdinalIgnoreCase))
        {
            var tlsSettings = new Dictionary<string, object?>(StringComparer.Ordinal);
            if (!string.IsNullOrWhiteSpace(serverName))
            {
                tlsSettings["serverName"] = serverName;
            }

            if (allowInsecure)
            {
                tlsSettings["allowInsecure"] = true;
            }

            if (!string.IsNullOrWhiteSpace(fingerprint))
            {
                tlsSettings["fingerprint"] = fingerprint;
            }

            if (!string.IsNullOrWhiteSpace(certificateFile) &&
                !string.IsNullOrWhiteSpace(keyFile))
            {
                tlsSettings["certificates"] = new object[]
                {
                    new Dictionary<string, object?>(StringComparer.Ordinal)
                    {
                        ["certificateFile"] = certificateFile,
                        ["keyFile"] = keyFile
                    }
                };
            }

            settings["tlsSettings"] = tlsSettings;
        }
        else if (string.Equals(security, RuntimeInternetSecurityTypes.Reality, StringComparison.OrdinalIgnoreCase) &&
                 realitySettings is not null)
        {
            settings["realitySettings"] = realitySettings;
        }

        return settings;
    }

    private static RuntimeRealityServerOptions CreateInteropRealityServerOptions()
        => new()
        {
            Show = true,
            ServerNames = [InteropRealityServerName],
            PrivateKey = InteropRealityPrivateKey,
            ShortIds = [InteropRealityShortId]
        };

    private static RuntimeRealityOptions CreateInteropRealityClientOptions(string fingerprint = "chrome")
        => new()
        {
            Show = true,
            Fingerprint = fingerprint,
            PublicKey = InteropRealityPublicKey,
            ShortId = InteropRealityShortId,
            SpiderX = "/"
        };

    private static object CreateXrayRealityServerSettings()
        => new
        {
            show = true,
            dest = $"{InteropRealityServerName}:443",
            type = "tcp",
            serverNames = new[]
            {
                InteropRealityServerName
            },
            privateKey = InteropRealityPrivateKey,
            shortIds = new[]
            {
                InteropRealityShortId
            }
        };

    private static object CreateXrayRealityClientSettings(string fingerprint = "chrome")
        => new
        {
            show = true,
            fingerprint,
            serverName = InteropRealityServerName,
            publicKey = InteropRealityPublicKey,
            shortId = InteropRealityShortId,
            spiderX = "/"
        };

    private static IReadOnlyDictionary<string, string> CreateOptionalHostHeader(string host)
        => string.IsNullOrWhiteSpace(host)
            ? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["Host"] = host
            };

    private static string ResolveOutboundTransportSecurity(string transport)
        => TrojanOutboundTransports.Normalize(transport) switch
        {
            TrojanOutboundTransports.Tls or
            TrojanOutboundTransports.Wss or
            TrojanOutboundTransports.HttpUpgradeTls => RuntimeInternetSecurityTypes.Tls,
            _ => RuntimeInternetSecurityTypes.None
        };

    private static string CreateXrayRSspanelConfig(
        string apiHost,
        int nodeId,
        string nodeType,
        string certMode = "none",
        string certFile = "",
        string keyFile = "",
        bool rejectUnknownSni = false)
    {
        var builder = new StringBuilder();
        builder.AppendLine("Log:");
        builder.AppendLine("  Level: debug");
        builder.AppendLine("Nodes:");
        builder.AppendLine("  - PanelType: SSpanel");
        builder.AppendLine("    ApiConfig:");
        builder.AppendLine($"      ApiHost: {apiHost}");
        builder.AppendLine("      ApiKey: 123");
        builder.AppendLine($"      NodeID: {nodeId}");
        builder.AppendLine($"      NodeType: {nodeType}");
        builder.AppendLine("      Timeout: 5");
        builder.AppendLine("      DisableCustomConfig: false");
        builder.AppendLine("    ControllerConfig:");
        builder.AppendLine("      ListenIP: 127.0.0.1");
        builder.AppendLine("      UpdatePeriodic: 86400");
        builder.AppendLine("      DisableGetRule: true");
        builder.AppendLine("      CertConfig:");
        builder.AppendLine($"        CertMode: {certMode}");
        if (!string.IsNullOrWhiteSpace(certFile))
        {
            builder.AppendLine($"        CertFile: '{certFile.Replace('\\', '/')}'");
        }

        if (!string.IsNullOrWhiteSpace(keyFile))
        {
            builder.AppendLine($"        KeyFile: '{keyFile.Replace('\\', '/')}'");
        }

        if (rejectUnknownSni)
        {
            builder.AppendLine("        RejectUnknownSni: true");
        }

        return builder.ToString();
    }

    private static string CreateXrayRV2raySspanelConfig(
        string apiHost,
        int nodeId,
        string certMode = "none",
        string certFile = "",
        string keyFile = "",
        bool rejectUnknownSni = false)
        => CreateXrayRSspanelConfig(apiHost, nodeId, "V2ray", certMode, certFile, keyFile, rejectUnknownSni);

    private static string CreateXrayRTrojanSspanelConfig(
        string apiHost,
        int nodeId,
        string certMode = "none",
        string certFile = "",
        string keyFile = "",
        bool rejectUnknownSni = false)
        => CreateXrayRSspanelConfig(apiHost, nodeId, "Trojan", certMode, certFile, keyFile, rejectUnknownSni);

    private static object CreateSspanelV2rayNodeInfoResponse(
        int port,
        bool enableVless = false,
        string network = "tcp",
        string host = "",
        string path = "",
        string grpcServiceName = "",
        string flow = "",
        string security = "none")
        => new
        {
            node_group = 0,
            node_class = 0,
            node_speedlimit = 0,
            traffic_rate = 1,
            sort = 0,
            server = string.Empty,
            type = "V2ray",
            version = "2024.6",
            custom_config = new
            {
                offset_port_node = port.ToString(),
                host,
                network,
                path,
                servicename = grpcServiceName,
                enable_vless = enableVless ? "1" : "0",
                flow,
                security
            }
        };

    private static object CreateSspanelV2rayUserResponse(int userId = 1)
        => new
        {
            id = userId,
            passwd = string.Empty,
            port = 0,
            method = string.Empty,
            node_speedlimit = 0,
            node_iplimit = 0,
            uuid = UserUuid,
            alive_ip = 0
        };

    private static object CreateSspanelTrojanNodeInfoResponse(
        int port,
        string network = "tcp",
        string host = "",
        string path = "",
        string grpcServiceName = "")
        => new
        {
            node_group = 0,
            node_class = 0,
            node_speedlimit = 0,
            traffic_rate = 1,
            sort = 0,
            server = string.Empty,
            type = "Trojan",
            version = "2024.6",
            custom_config = new
            {
                offset_port_node = port.ToString(),
                host,
                network,
                path,
                servicename = grpcServiceName
            }
        };

    private static object CreateSspanelTrojanUserResponse(int userId = 1)
        => new
        {
            id = userId,
            passwd = TrojanSharedPassword,
            port = 0,
            method = string.Empty,
            node_speedlimit = 0,
            node_iplimit = 0,
            uuid = TrojanSharedPassword,
            alive_ip = 0
        };

    private static X509Certificate2 CreateInteropServerCertificate(string commonName)
        => TestCertificateFactory.CreateSelfSignedServerCertificate(
            commonName,
            [commonName]);

    private static async Task WriteXrayCertificateFilesAsync(
        X509Certificate2 certificate,
        string certificateFile,
        string keyFile,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentException.ThrowIfNullOrWhiteSpace(certificateFile);
        ArgumentException.ThrowIfNullOrWhiteSpace(keyFile);

        var directory = Path.GetDirectoryName(certificateFile);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        directory = Path.GetDirectoryName(keyFile);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        await File.WriteAllTextAsync(
            certificateFile,
            certificate.ExportCertificatePem(),
            cancellationToken);

        string privateKeyPem;
        using var rsa = certificate.GetRSAPrivateKey();
        if (rsa is not null)
        {
            privateKeyPem = rsa.ExportPkcs8PrivateKeyPem();
        }
        else
        {
            using var ecdsa = certificate.GetECDsaPrivateKey();
            if (ecdsa is null)
            {
                throw new InvalidOperationException("Certificate does not contain an exportable RSA or ECDSA private key.");
            }

            privateKeyPem = ecdsa.ExportPkcs8PrivateKeyPem();
        }

        await File.WriteAllTextAsync(keyFile, privateKeyPem, cancellationToken);
    }

    private static async Task<XrayProcessHandle> StartXrayAsync(
        string xrayExecutable,
        string tempDirectory,
        string configFileName,
        object config,
        int listenPort,
        CancellationToken cancellationToken,
        string listenNetwork = RuntimeInternetTransportProtocols.Tcp)
    {
        Directory.CreateDirectory(tempDirectory);

        var configPath = Path.Combine(tempDirectory, configFileName);
        await File.WriteAllTextAsync(
            configPath,
            JsonSerializer.Serialize(
                config,
                new JsonSerializerOptions
                {
                    WriteIndented = true
                }),
            cancellationToken);

        var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = xrayExecutable,
                WorkingDirectory = Path.GetDirectoryName(xrayExecutable)!,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            },
            EnableRaisingEvents = true
        };
        process.StartInfo.ArgumentList.Add("run");
        process.StartInfo.ArgumentList.Add("-c");
        process.StartInfo.ArgumentList.Add(configPath);

        var handle = new XrayProcessHandle(process, configPath, "xray-core");
        if (!process.Start())
        {
            process.Dispose();
            throw new InvalidOperationException("Failed to start xray-core process.");
        }

        handle.BeginCapture();

        try
        {
            if (string.Equals(listenNetwork, RuntimeInternetTransportProtocols.Mkcp, StringComparison.OrdinalIgnoreCase))
            {
                await WaitForProcessStableAsync(handle, "xray-core", cancellationToken);
            }
            else
            {
                await WaitForTcpPortAsync(listenPort, handle, "xray-core", cancellationToken);
            }
            handle.AssertStillRunning();
            return handle;
        }
        catch
        {
            await handle.DisposeAsync();
            throw;
        }
    }

    private static async Task<XrayProcessHandle> StartXrayRAsync(
        string xrayrExecutable,
        string tempDirectory,
        string configFileName,
        string config,
        int listenPort,
        CancellationToken cancellationToken,
        string listenNetwork = RuntimeInternetTransportProtocols.Tcp)
    {
        Directory.CreateDirectory(tempDirectory);

        var configPath = Path.Combine(tempDirectory, configFileName);
        await File.WriteAllTextAsync(configPath, config, cancellationToken);

        var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = xrayrExecutable,
                WorkingDirectory = Path.GetDirectoryName(xrayrExecutable)!,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            },
            EnableRaisingEvents = true
        };
        process.StartInfo.ArgumentList.Add("-c");
        process.StartInfo.ArgumentList.Add(configPath.Replace('\\', '/'));

        var handle = new XrayProcessHandle(process, configPath, "XrayR");
        if (!process.Start())
        {
            process.Dispose();
            throw new InvalidOperationException("Failed to start XrayR process.");
        }

        handle.BeginCapture();

        try
        {
            if (string.Equals(listenNetwork, RuntimeInternetTransportProtocols.Mkcp, StringComparison.OrdinalIgnoreCase))
            {
                await WaitForProcessStableAsync(handle, "XrayR", cancellationToken);
            }
            else
            {
                await WaitForTcpPortAsync(listenPort, handle, "XrayR", cancellationToken);
            }
            handle.AssertStillRunning();
            return handle;
        }
        catch
        {
            await handle.DisposeAsync();
            throw;
        }
    }

    private static async Task<MockSspanelPanelHandle> StartSspanelMockPanelAsync(
        int nodeId,
        object nodeInfoResponse,
        object[] users,
        CancellationToken cancellationToken)
    {
        var port = GetAvailableTcpPort();
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseUrls($"http://127.0.0.1:{port}");

        var app = builder.Build();
        var okResponse = new { ret = 1, data = new { } };
        app.MapGet($"/mod_mu/nodes/{nodeId}/info", () => new { ret = 1, data = nodeInfoResponse });
        app.MapGet("/mod_mu/users", () => new { ret = 1, data = users });
        app.MapGet("/mod_mu/func/detect_rules", () => new { ret = 1, data = Array.Empty<object>() });
        app.MapPost($"/mod_mu/nodes/{nodeId}/info", () => okResponse);
        app.MapPost("/mod_mu/users/aliveip", () => okResponse);
        app.MapPost("/mod_mu/users/traffic", () => okResponse);
        app.MapPost("/mod_mu/users/detectlog", () => okResponse);

        await app.StartAsync(cancellationToken);
        return new MockSspanelPanelHandle(app, $"http://127.0.0.1:{port}");
    }

    private static async Task WaitForTcpPortAsync(
        int port,
        XrayProcessHandle handle,
        string processName,
        CancellationToken cancellationToken)
    {
        using var waitCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        waitCts.CancelAfter(TimeSpan.FromSeconds(10));

        while (!waitCts.IsCancellationRequested)
        {
            handle.AssertStillRunning();

            using var client = new TcpClient();
            try
            {
                await client.ConnectAsync(IPAddress.Loopback, port, waitCts.Token);
                return;
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested && waitCts.IsCancellationRequested)
            {
                break;
            }
            catch (SocketException)
            {
            }

            try
            {
                await Task.Delay(100, waitCts.Token);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested && waitCts.IsCancellationRequested)
            {
                break;
            }
        }

        throw new TimeoutException(
            $"Timed out waiting for {processName} to listen on 127.0.0.1:{port}.{Environment.NewLine}{handle.GetDiagnostics()}");
    }

    private static async Task WaitForProcessStableAsync(
        XrayProcessHandle handle,
        string processName,
        CancellationToken cancellationToken)
    {
        using var waitCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        waitCts.CancelAfter(TimeSpan.FromSeconds(2));

        while (!waitCts.IsCancellationRequested)
        {
            handle.AssertStillRunning();

            try
            {
                await Task.Delay(100, waitCts.Token);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested && waitCts.IsCancellationRequested)
            {
                break;
            }
        }

        try
        {
            handle.AssertStillRunning();
        }
        catch (Exception ex)
        {
            throw new TimeoutException(
                $"Timed out waiting for {processName} to stay alive during startup.{Environment.NewLine}{handle.GetDiagnostics()}",
                ex);
        }
    }

    private static async Task<CapturedTlsClientHello> CaptureTlsClientHelloAsync(
        TcpListener listener,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = client.GetStream();
        var clientHello = await RuntimeTlsClientHelloReader.ReadAsync(stream, cancellationToken);
        Assert.True(RuntimeTlsClientHelloParser.TryParse(clientHello, out var metadata));
        Assert.True(
            RuntimeRealityClientHelloDocument.TryParse(clientHello, out var document, out var error),
            error);
        Assert.NotNull(document);
        return new CapturedTlsClientHello(clientHello, metadata, document!);
    }

    private static async Task<TcpClient> InitiateSocks5ConnectAsync(
        int proxyPort,
        int destinationPort,
        CancellationToken cancellationToken)
    {
        var client = new TcpClient();

        try
        {
            await client.ConnectAsync(IPAddress.Loopback, proxyPort, cancellationToken);
            var stream = client.GetStream();

            await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 }, cancellationToken);

            var greeting = new byte[2];
            await stream.ReadExactlyAsync(greeting.AsMemory(0, greeting.Length), cancellationToken);
            Assert.Equal(new byte[] { 0x05, 0x00 }, greeting);

            var request = new List<byte>
            {
                0x05,
                0x01,
                0x00,
                0x01
            };
            request.AddRange(IPAddress.Loopback.GetAddressBytes());
            request.Add((byte)(destinationPort >> 8));
            request.Add((byte)(destinationPort & 0xFF));
            await stream.WriteAsync(request.ToArray(), cancellationToken);
            await stream.FlushAsync(cancellationToken);

            return client;
        }
        catch
        {
            client.Dispose();
            throw;
        }
    }

    private static async Task<TcpClient> ConnectViaSocks5Async(
        int proxyPort,
        int destinationPort,
        CancellationToken cancellationToken)
    {
        var client = new TcpClient();

        try
        {
            await client.ConnectAsync(IPAddress.Loopback, proxyPort, cancellationToken);
            var stream = client.GetStream();

            await stream.WriteAsync(new byte[] { 0x05, 0x01, 0x00 }, cancellationToken);

            var greeting = new byte[2];
            await stream.ReadExactlyAsync(greeting.AsMemory(0, greeting.Length), cancellationToken);
            Assert.Equal(new byte[] { 0x05, 0x00 }, greeting);

            var request = new List<byte>
            {
                0x05,
                0x01,
                0x00,
                0x01
            };
            request.AddRange(IPAddress.Loopback.GetAddressBytes());
            request.Add((byte)(destinationPort >> 8));
            request.Add((byte)(destinationPort & 0xFF));
            await stream.WriteAsync(request.ToArray(), cancellationToken);

            var reply = new byte[10];
            await stream.ReadExactlyAsync(reply.AsMemory(0, reply.Length), cancellationToken);
            Assert.Equal(0x00, reply[1]);

            return client;
        }
        catch
        {
            client.Dispose();
            throw;
        }
    }

    private static async Task AssertEchoViaSocks5WithRetryAsync(
        int proxyPort,
        int destinationPort,
        string payload,
        CancellationToken cancellationToken)
    {
        Exception? lastException = null;

        for (var attempt = 0; attempt < 3; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                using var client = await ConnectViaSocks5Async(proxyPort, destinationPort, cancellationToken);
                await using var stream = client.GetStream();
                await AssertEchoAsync(stream, payload, cancellationToken);
                return;
            }
            catch (Exception ex) when (attempt < 2 && !cancellationToken.IsCancellationRequested)
            {
                lastException = ex;
                await Task.Delay(200, cancellationToken);
            }
        }

        if (lastException is not null)
        {
            ExceptionDispatchInfo.Capture(lastException).Throw();
        }

        throw new InvalidOperationException("SOCKS5 echo retry exited without completing.");
    }

    private static IReadOnlyList<int> GetExpectedGolangCipherSuites(bool includeTls12CipherSuites)
    {
        if (!includeTls12CipherSuites)
        {
            return PreferAesGcmCipherSuites()
                ? [0x1301, 0x1302, 0x1303]
                : [0x1303, 0x1301, 0x1302];
        }

        return PreferAesGcmCipherSuites()
            ? [0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC009, 0xC013, 0xC00A, 0xC014, 0x1301, 0x1302, 0x1303]
            : [0xCCA9, 0xCCA8, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xC009, 0xC013, 0xC00A, 0xC014, 0x1303, 0x1301, 0x1302];
    }

    private static IReadOnlyList<int> GetExpectedGolangExtensions()
        => [0x0000, 0x000B, 0xFF01, 0x0017, 0x0012, 0x0005, 0x000A, 0x000D, 0x002B, 0x0033];

    private static IReadOnlyList<int> GetExpectedGolangSupportedGroups()
        => RuntimeX25519MlKem768.IsSupported
            ? [RuntimeTlsNamedGroups.X25519MLKem768, RuntimeTlsNamedGroups.X25519, RuntimeTlsNamedGroups.Secp256r1, RuntimeTlsNamedGroups.Secp384r1, RuntimeTlsNamedGroups.Secp521r1]
            : [RuntimeTlsNamedGroups.X25519, RuntimeTlsNamedGroups.Secp256r1, RuntimeTlsNamedGroups.Secp384r1, RuntimeTlsNamedGroups.Secp521r1];

    private static string? IdentifyModernChromeFingerprint(CapturedTlsClientHello capture)
    {
        if (MatchesChromeFingerprintShape(capture, "hellochrome_auto", allowProtocolConstraints: true))
        {
            return "hellochrome_auto";
        }

        if (MatchesChromeFingerprintShape(capture, "hellochrome_131"))
        {
            return "hellochrome_131";
        }

        if (MatchesChromeFingerprintShape(capture, "hellochrome_120"))
        {
            return "hellochrome_120";
        }

        if (MatchesChromeFingerprintShape(capture, "hellochrome_106_shuffle"))
        {
            return "hellochrome_106_shuffle";
        }

        return null;
    }

    private static bool MatchesChromeFingerprintShape(
        CapturedTlsClientHello capture,
        string fingerprint,
        bool allowProtocolConstraints = false)
    {
        var metadata = capture.Metadata;
        if (metadata is null || !HasRandomSessionId(capture.Document))
        {
            return false;
        }

        var hello = capture.Document;
        var actualCipherSuites = metadata.CipherSuites;
        var actualSupportedGroups = metadata.SupportedGroups;
        var actualSupportedGroupsWithGrease = GetSupportedGroups(hello, includeGrease: true);
        var actualKeyShareGroups = GetKeyShareGroups(hello, includeGrease: false);
        var actualKeyShareGroupsWithGrease = GetKeyShareGroups(hello, includeGrease: true);
        var actualSupportedVersions = GetSupportedVersions(hello, includeGrease: false);
        var actualSupportedVersionsWithGrease = GetSupportedVersions(hello, includeGrease: true);
        var actualExtensionTypesWithoutGrease = GetExtensionTypes(hello, includeGrease: false);
        var actualSignatureAlgorithms = GetSignatureAlgorithms(hello);
        var expectedCipherSuites = Array.Empty<int>();
        var expectedSupportedGroups = Array.Empty<int>();
        var expectedKeyShareGroups = Array.Empty<int>();
        var expectedSupportedVersions = Array.Empty<int>();
        var expectedExtensionTypes = Array.Empty<int>();
        var expectedApplicationSettingsExtensionType = 0;
        var expectsEchGrease = false;
        var expectsPadding = false;
        var allowsOptionalPadding = false;
        var expectsKeyShare = true;
        var expectsGreasedSupportedVersions = true;
        var expectsGreasedSupportedGroups = true;
        var expectedHybridKeyShareGroup = 0;
        var expectedHybridKeyShareLength = 0;

        switch (fingerprint)
        {
            case "hellochrome_106_shuffle":
                expectedCipherSuites = [.. GetExpectedChromeMixedCipherSuites()];
                expectedSupportedGroups = [RuntimeTlsNamedGroups.X25519, RuntimeTlsNamedGroups.Secp256r1, RuntimeTlsNamedGroups.Secp384r1];
                expectedKeyShareGroups = [RuntimeTlsNamedGroups.X25519];
                expectedSupportedVersions = [0x0304, 0x0303];
                expectedExtensionTypes = BuildExpectedChromeExtensionTypeSet(
                    includeKeyShare: true,
                    includePskKeyExchangeModes: true,
                    includeSupportedVersions: true,
                    includeCompressCertificate: true,
                    applicationSettingsExtensionType: 17513,
                    includeEchGrease: false,
                    includePadding: true);
                expectsPadding = true;
                expectedApplicationSettingsExtensionType = 17513;
                break;

            case "hellochrome_120":
                expectedCipherSuites = [.. GetExpectedChromeMixedCipherSuites()];
                expectedSupportedGroups = [RuntimeTlsNamedGroups.X25519, RuntimeTlsNamedGroups.Secp256r1, RuntimeTlsNamedGroups.Secp384r1];
                expectedKeyShareGroups = [RuntimeTlsNamedGroups.X25519];
                expectedSupportedVersions = [0x0304, 0x0303];
                expectedExtensionTypes = BuildExpectedChromeExtensionTypeSet(
                    includeKeyShare: true,
                    includePskKeyExchangeModes: true,
                    includeSupportedVersions: true,
                    includeCompressCertificate: true,
                    applicationSettingsExtensionType: 17513,
                    includeEchGrease: true,
                    includePadding: false);
                expectsEchGrease = true;
                allowsOptionalPadding = true;
                expectedApplicationSettingsExtensionType = 17513;
                break;

            case "hellochrome_131":
                expectedCipherSuites = [.. GetExpectedChromeMixedCipherSuites()];
                expectedSupportedGroups = [RuntimeTlsNamedGroups.X25519MLKem768, RuntimeTlsNamedGroups.X25519, RuntimeTlsNamedGroups.Secp256r1, RuntimeTlsNamedGroups.Secp384r1];
                expectedKeyShareGroups = [RuntimeTlsNamedGroups.X25519MLKem768, RuntimeTlsNamedGroups.X25519];
                expectedSupportedVersions = [0x0304, 0x0303];
                expectedExtensionTypes = BuildExpectedChromeExtensionTypeSet(
                    includeKeyShare: true,
                    includePskKeyExchangeModes: true,
                    includeSupportedVersions: true,
                    includeCompressCertificate: true,
                    applicationSettingsExtensionType: 17513,
                    includeEchGrease: true,
                    includePadding: false);
                expectsEchGrease = true;
                expectedApplicationSettingsExtensionType = 17513;
                expectedHybridKeyShareGroup = RuntimeTlsNamedGroups.X25519MLKem768;
                expectedHybridKeyShareLength = RuntimeX25519MlKem768.ClientKeyShareLength;
                break;

            case "chrome":
            case "hellochrome_auto":
                if (!allowProtocolConstraints)
                {
                    expectedCipherSuites = [.. GetExpectedChromeMixedCipherSuites()];
                    expectedSupportedGroups = [RuntimeTlsNamedGroups.X25519MLKem768, RuntimeTlsNamedGroups.X25519, RuntimeTlsNamedGroups.Secp256r1, RuntimeTlsNamedGroups.Secp384r1];
                    expectedKeyShareGroups = [RuntimeTlsNamedGroups.X25519MLKem768, RuntimeTlsNamedGroups.X25519];
                    expectedSupportedVersions = [0x0304, 0x0303];
                    expectedExtensionTypes = BuildExpectedChromeExtensionTypeSet(
                        includeKeyShare: true,
                        includePskKeyExchangeModes: true,
                        includeSupportedVersions: true,
                        includeCompressCertificate: true,
                        applicationSettingsExtensionType: 17613,
                        includeEchGrease: true,
                        includePadding: false);
                    expectsEchGrease = true;
                    expectedApplicationSettingsExtensionType = 17613;
                    expectedHybridKeyShareGroup = RuntimeTlsNamedGroups.X25519MLKem768;
                    expectedHybridKeyShareLength = RuntimeX25519MlKem768.ClientKeyShareLength;
                    break;
                }

                if (actualSupportedVersions.SequenceEqual(new[] { 0x0304 }))
                {
                    expectedCipherSuites = [.. GetExpectedChromeTls13OnlyCipherSuites()];
                    expectedSupportedGroups = [RuntimeTlsNamedGroups.X25519MLKem768, RuntimeTlsNamedGroups.X25519, RuntimeTlsNamedGroups.Secp256r1, RuntimeTlsNamedGroups.Secp384r1];
                    expectedKeyShareGroups = [RuntimeTlsNamedGroups.X25519MLKem768, RuntimeTlsNamedGroups.X25519];
                    expectedSupportedVersions = [0x0304];
                    expectedExtensionTypes = BuildExpectedChromeExtensionTypeSet(
                        includeKeyShare: true,
                        includePskKeyExchangeModes: true,
                        includeSupportedVersions: true,
                        includeCompressCertificate: true,
                        applicationSettingsExtensionType: 17613,
                        includeEchGrease: true,
                        includePadding: false);
                    expectsEchGrease = true;
                    expectedApplicationSettingsExtensionType = 17613;
                    expectedHybridKeyShareGroup = RuntimeTlsNamedGroups.X25519MLKem768;
                    expectedHybridKeyShareLength = RuntimeX25519MlKem768.ClientKeyShareLength;
                    break;
                }

                if (actualSupportedVersions.SequenceEqual(new[] { 0x0304, 0x0303 }))
                {
                    expectedCipherSuites = [.. GetExpectedChromeMixedCipherSuites()];
                    expectedSupportedGroups = [RuntimeTlsNamedGroups.X25519MLKem768, RuntimeTlsNamedGroups.X25519, RuntimeTlsNamedGroups.Secp256r1, RuntimeTlsNamedGroups.Secp384r1];
                    expectedKeyShareGroups = [RuntimeTlsNamedGroups.X25519MLKem768, RuntimeTlsNamedGroups.X25519];
                    expectedSupportedVersions = [0x0304, 0x0303];
                    expectedExtensionTypes = BuildExpectedChromeExtensionTypeSet(
                        includeKeyShare: true,
                        includePskKeyExchangeModes: true,
                        includeSupportedVersions: true,
                        includeCompressCertificate: true,
                        applicationSettingsExtensionType: 17613,
                        includeEchGrease: true,
                        includePadding: false);
                    expectsEchGrease = true;
                    expectedApplicationSettingsExtensionType = 17613;
                    expectedHybridKeyShareGroup = RuntimeTlsNamedGroups.X25519MLKem768;
                    expectedHybridKeyShareLength = RuntimeX25519MlKem768.ClientKeyShareLength;
                    break;
                }

                if (actualSupportedVersions.SequenceEqual(new[] { 0x0303 }))
                {
                    expectedCipherSuites = [.. GetExpectedChromeLegacyCipherSuitesWithoutTls13()];
                    expectedSupportedGroups = [RuntimeTlsNamedGroups.X25519, RuntimeTlsNamedGroups.Secp256r1, RuntimeTlsNamedGroups.Secp384r1];
                    expectedKeyShareGroups = Array.Empty<int>();
                    expectedSupportedVersions = [0x0303];
                    expectedExtensionTypes = BuildExpectedChromeExtensionTypeSet(
                        includeKeyShare: false,
                        includePskKeyExchangeModes: false,
                        includeSupportedVersions: true,
                        includeCompressCertificate: false,
                        applicationSettingsExtensionType: null,
                        includeEchGrease: false,
                        includePadding: false);
                    expectsKeyShare = false;
                    break;
                }

                return false;

            default:
                throw new NotSupportedException($"Unsupported Chrome fingerprint '{fingerprint}'.");
        }

        if (!actualCipherSuites.SequenceEqual(expectedCipherSuites) ||
            !actualSupportedGroups.SequenceEqual(expectedSupportedGroups) ||
            !actualSupportedVersions.SequenceEqual(expectedSupportedVersions) ||
            !actualSignatureAlgorithms.SequenceEqual(GetExpectedChromeSignatureAlgorithms()))
        {
            return false;
        }

        if (expectsGreasedSupportedGroups &&
            (actualSupportedGroupsWithGrease.Length == 0 || !IsGreaseValue(actualSupportedGroupsWithGrease[0])))
        {
            return false;
        }

        if (expectsGreasedSupportedVersions &&
            (actualSupportedVersionsWithGrease.Length == 0 || !IsGreaseValue(actualSupportedVersionsWithGrease[0])))
        {
            return false;
        }

        if (!expectsKeyShare)
        {
            if (HasExtension(hello, 0x0033) || actualKeyShareGroups.Length != 0)
            {
                return false;
            }
        }
        else if (!actualKeyShareGroups.SequenceEqual(expectedKeyShareGroups) ||
                 actualKeyShareGroupsWithGrease.Length == 0 ||
                 !IsGreaseValue(actualKeyShareGroupsWithGrease[0]))
        {
            return false;
        }

        var hasPadding = HasExtension(hello, 0x0015);
        if (HasExtension(hello, 0x0032) ||
            HasExtension(hello, 0x0029) ||
            HasExtension(hello, 0xFE0D) != expectsEchGrease ||
            (!allowsOptionalPadding && hasPadding != expectsPadding) ||
            HasExtension(hello, 17513) != (expectedApplicationSettingsExtensionType == 17513) ||
            HasExtension(hello, 17613) != (expectedApplicationSettingsExtensionType == 17613))
        {
            return false;
        }

        var expectedExtensionTypeSet = allowsOptionalPadding
            ? BuildExpectedChromeExtensionTypeSet(
                includeKeyShare: expectsKeyShare,
                includePskKeyExchangeModes: expectsKeyShare,
                includeSupportedVersions: true,
                includeCompressCertificate: expectedSupportedVersions[0] == 0x0304,
                applicationSettingsExtensionType: expectedApplicationSettingsExtensionType == 0
                    ? null
                    : expectedApplicationSettingsExtensionType,
                includeEchGrease: expectsEchGrease,
                includePadding: hasPadding)
            : expectedExtensionTypes;
        if (!SetEquals(actualExtensionTypesWithoutGrease, expectedExtensionTypeSet))
        {
            return false;
        }

        if (expectedHybridKeyShareGroup != 0)
        {
            var hybridKeyShare = GetKeyShares(hello)
                .SingleOrDefault(entry => entry.Group == expectedHybridKeyShareGroup);
            if (hybridKeyShare is null ||
                hybridKeyShare.KeyExchange.Length != expectedHybridKeyShareLength)
            {
                return false;
            }
        }

        return true;
    }

    private static string DescribeCapturedClientHello(
        CapturedTlsClientHello capture,
        string? identifiedFingerprint)
    {
        var metadata = capture.Metadata;
        if (metadata is null)
        {
            return $"identifiedFingerprint: {identifiedFingerprint ?? "(none)"}{Environment.NewLine}metadata: (null)";
        }

        var hello = capture.Document;
        return string.Join(
            Environment.NewLine,
            [
                $"identifiedFingerprint: {identifiedFingerprint ?? "(none)"}",
                $"legacyVersion: 0x{metadata.LegacyVersion:X4}",
                $"applicationProtocols: {FormatStringSequence(metadata.ApplicationProtocols)}",
                $"cipherSuites: {FormatIntSequence(metadata.CipherSuites)}",
                $"supportedGroups: {FormatIntSequence(GetSupportedGroups(hello, includeGrease: true))}",
                $"supportedVersions: {FormatIntSequence(GetSupportedVersions(hello, includeGrease: true))}",
                $"keyShareGroups: {FormatIntSequence(GetKeyShareGroups(hello, includeGrease: true))}",
                $"extensions: {FormatIntSequence(hello.Extensions.Select(static extension => (int)extension.Type))}",
                $"normalizedExtensions: {FormatIntSequence(GetNormalizedExtensionTypes(hello))}",
                $"signatureAlgorithms: {FormatIntSequence(GetSignatureAlgorithms(hello))}"
            ]);
    }

    private static bool HasRandomSessionId(RuntimeRealityClientHelloDocument hello)
        => hello.SessionId.Length == 32 && !IsAllZero(hello.SessionId);

    private static bool HasExtension(
        RuntimeRealityClientHelloDocument hello,
        int extensionType)
        => hello.Extensions.Any(extension => extension.Type == extensionType);

    private static int[] GetNormalizedExtensionTypes(RuntimeRealityClientHelloDocument hello)
        => hello.Extensions
            .Select(static extension => NormalizeGreaseValue(extension.Type))
            .ToArray();

    private static int[] GetExtensionTypes(
        RuntimeRealityClientHelloDocument hello,
        bool includeGrease)
        => hello.Extensions
            .Select(static extension => (int)extension.Type)
            .Where(extensionType => includeGrease || !IsGreaseValue(extensionType))
            .ToArray();

    private static int[] GetSupportedGroups(
        RuntimeRealityClientHelloDocument hello,
        bool includeGrease)
        => hello.SupportedGroups
            .Select(static group => (int)group)
            .Where(group => includeGrease || !IsGreaseValue(group))
            .ToArray();

    private static int[] GetSupportedVersions(
        RuntimeRealityClientHelloDocument hello,
        bool includeGrease)
        => hello.SupportedVersions
            .Select(static version => (int)version)
            .Where(version => includeGrease || !IsGreaseValue(version))
            .ToArray();

    private static int[] GetKeyShareGroups(
        RuntimeRealityClientHelloDocument hello,
        bool includeGrease)
        => GetKeyShares(hello)
            .Select(static entry => (int)entry.Group)
            .Where(group => includeGrease || !IsGreaseValue(group))
            .ToArray();

    private static List<TlsKeyShareEntry> GetKeyShares(RuntimeRealityClientHelloDocument hello)
    {
        var extension = hello.Extensions.SingleOrDefault(static current => current.Type == 0x0033);
        return extension is null
            ? []
            : ParseKeyShares(extension.Payload);
    }

    private static IReadOnlyList<int> GetSignatureAlgorithms(RuntimeRealityClientHelloDocument hello)
    {
        var extension = hello.Extensions.SingleOrDefault(static current => current.Type == 0x000D);
        if (extension is null || extension.Payload.Length < 2)
        {
            return Array.Empty<int>();
        }

        return ParseUInt16Vector(extension.Payload.AsSpan(2));
    }

    private static bool SetEquals(
        IReadOnlyList<int> actual,
        IReadOnlyList<int> expected)
        => actual.Count == expected.Count &&
           actual.OrderBy(static value => value).SequenceEqual(expected.OrderBy(static value => value));

    private static int[] BuildExpectedChromeExtensionTypeSet(
        bool includeKeyShare,
        bool includePskKeyExchangeModes,
        bool includeSupportedVersions,
        bool includeCompressCertificate,
        int? applicationSettingsExtensionType,
        bool includeEchGrease,
        bool includePadding)
    {
        var values = new List<int>
        {
            0x0000,
            0x0017,
            0xFF01,
            0x000A,
            0x000B,
            0x0023,
            0x0010,
            0x0005,
            0x000D,
            0x0012
        };
        if (includeKeyShare)
        {
            values.Add(0x0033);
        }

        if (includePskKeyExchangeModes)
        {
            values.Add(0x002D);
        }

        if (includeSupportedVersions)
        {
            values.Add(0x002B);
        }

        if (includeCompressCertificate)
        {
            values.Add(0x001B);
        }

        if (applicationSettingsExtensionType.HasValue)
        {
            values.Add(applicationSettingsExtensionType.Value);
        }

        if (includeEchGrease)
        {
            values.Add(0xFE0D);
        }

        if (includePadding)
        {
            values.Add(0x0015);
        }

        return values.ToArray();
    }

    private static IReadOnlyList<int> GetExpectedChromeMixedCipherSuites()
        => [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035];

    private static IReadOnlyList<int> GetExpectedChromeTls13OnlyCipherSuites()
        => [0x1301, 0x1302, 0x1303];

    private static IReadOnlyList<int> GetExpectedChromeLegacyCipherSuitesWithoutTls13()
        => [0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035];

    private static IReadOnlyList<int> GetExpectedChromeSignatureAlgorithms()
        => [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601];

    private static List<int> ParseUInt16Vector(ReadOnlySpan<byte> payload)
    {
        var values = new List<int>(payload.Length / 2);
        for (var index = 0; index + 1 < payload.Length; index += 2)
        {
            values.Add((payload[index] << 8) | payload[index + 1]);
        }

        return values;
    }

    private const int GreasePlaceholder = -1;

    private static bool IsGreaseValue(int value)
        => (value & 0x0f0f) == 0x0a0a && ((value >> 8) & 0xff) == (value & 0xff);

    private static int NormalizeGreaseValue(int value)
        => IsGreaseValue(value) ? GreasePlaceholder : value;

    private static bool IsAllZero(ReadOnlySpan<byte> value)
    {
        foreach (var current in value)
        {
            if (current != 0)
            {
                return false;
            }
        }

        return true;
    }

    private static string FormatIntSequence(IEnumerable<int> values)
        => "[" + string.Join(", ", values.Select(FormatIntValue)) + "]";

    private static string FormatStringSequence(IEnumerable<string> values)
        => "[" + string.Join(", ", values.Select(static value => $"\"{value}\"")) + "]";

    private static string FormatIntValue(int value)
        => value == GreasePlaceholder ? "GREASE" : $"0x{value:X4}";

    private static List<TlsKeyShareEntry> ParseKeyShares(ReadOnlySpan<byte> payload)
    {
        var entries = new List<TlsKeyShareEntry>();
        if (payload.Length < 2)
        {
            return entries;
        }

        var totalLength = BinaryPrimitives.ReadUInt16BigEndian(payload);
        var cursor = 2;
        var end = Math.Min(payload.Length, cursor + totalLength);
        while (cursor + 4 <= end)
        {
            var group = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(cursor, 2));
            var keyExchangeLength = BinaryPrimitives.ReadUInt16BigEndian(payload.Slice(cursor + 2, 2));
            cursor += 4;
            if (cursor + keyExchangeLength > end)
            {
                break;
            }

            entries.Add(new TlsKeyShareEntry(group, payload.Slice(cursor, keyExchangeLength).ToArray()));
            cursor += keyExchangeLength;
        }

        return entries;
    }

    private static bool PreferAesGcmCipherSuites()
        => AesGcm.IsSupported &&
           ((System.Runtime.Intrinsics.X86.Aes.IsSupported &&
             System.Runtime.Intrinsics.X86.Pclmulqdq.IsSupported &&
             System.Runtime.Intrinsics.X86.Sse41.IsSupported &&
             System.Runtime.Intrinsics.X86.Ssse3.IsSupported) ||
            System.Runtime.Intrinsics.Arm.Aes.IsSupported);

    private static async Task AssertEchoAsync(
        Stream stream,
        string payload,
        CancellationToken cancellationToken)
    {
        var bytes = Encoding.ASCII.GetBytes(payload);
        await stream.WriteAsync(bytes, cancellationToken);
        await stream.FlushAsync(cancellationToken);

        var echoed = new byte[bytes.Length];
        var offset = 0;
        while (offset < echoed.Length)
        {
            var read = await stream.ReadAsync(echoed.AsMemory(offset, echoed.Length - offset), cancellationToken);
            if (read == 0)
            {
                throw new EndOfStreamException(
                    $"Expected {echoed.Length} echo bytes but only received {offset}. Partial payload: '{Encoding.ASCII.GetString(echoed, 0, offset)}'.");
            }

            offset += read;
        }

        Assert.Equal(bytes, echoed);
    }

    private static (TcpListener Listener, Task Task, int Port) StartEchoServer(CancellationToken cancellationToken)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        return (listener, RunEchoServerAsync(listener, cancellationToken), port);
    }

    private static async Task RunEchoServerAsync(
        TcpListener listener,
        CancellationToken cancellationToken)
    {
        try
        {
            using var client = await listener.AcceptTcpClientAsync(cancellationToken);
            await using var stream = client.GetStream();
            var buffer = new byte[4096];

            while (!cancellationToken.IsCancellationRequested)
            {
                var read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken);
                if (read == 0)
                {
                    break;
                }

                await stream.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
                await stream.FlushAsync(cancellationToken);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (IOException)
        {
        }
        catch (SocketException)
        {
        }
        catch (ObjectDisposedException) when (cancellationToken.IsCancellationRequested)
        {
        }
        finally
        {
            listener.Stop();
        }
    }

    private static async Task StopRuntimeAsync(DefaultRuntime runtime)
    {
        if (runtime.State is RuntimeState.Stopped or RuntimeState.Stopping)
        {
            return;
        }

        using var stopCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try
        {
            await runtime.StopAsync(stopCts.Token);
        }
        catch (OperationCanceledException) when (stopCts.IsCancellationRequested)
        {
        }
    }

    private static async Task AwaitCompletionAsync(Task task)
    {
        try
        {
            await task;
        }
        catch (OperationCanceledException)
        {
        }
    }

    private static Exception CreateInteropFailure(
        string message,
        DefaultRuntime runtime,
        XrayProcessHandle xray,
        Exception innerException,
        RuntimeEventCollector? runtimeEvents = null)
    {
        var status = runtime.GetStatus();
        var listeners = status.Listeners.Count == 0
            ? "(empty)"
            : string.Join(
                Environment.NewLine,
                status.Listeners.Select(listener =>
                    $"{listener.Protocol}/{listener.Tag} {listener.Binding.ListenAddress}:{listener.Binding.Port} {listener.State}"));
        var eventText = runtimeEvents?.FormatSnapshot() ?? string.Empty;
        var runtimeEventsSection = string.IsNullOrWhiteSpace(eventText)
            ? string.Empty
            : $"runtime-events:{Environment.NewLine}{eventText}{Environment.NewLine}";

        return new InvalidOperationException(
            $"{message}{Environment.NewLine}" +
            $"runtime: {status.State}, revision={status.Revision}, message={status.Message}{Environment.NewLine}" +
            $"listeners:{Environment.NewLine}{listeners}{Environment.NewLine}" +
            runtimeEventsSection +
            $"{xray.GetDiagnostics()}",
            innerException);
    }

    private static async Task<(string Stdout, string Stderr)> WaitForProcessExitWithDiagnosticsAsync(
        Process process,
        string processName,
        DefaultRuntime runtime,
        RuntimeEventCollector runtimeEvents,
        CancellationToken cancellationToken)
    {
        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();

        try
        {
            await process.WaitForExitAsync(cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            TryTerminateProcess(process);
            var stdoutOnTimeout = await stdoutTask;
            var stderrOnTimeout = await stderrTask;
            throw new TimeoutException(
                $"{processName} timed out before exit.{Environment.NewLine}" +
                $"{FormatRuntimeDiagnostics(runtime, runtimeEvents)}" +
                $"stdout:{Environment.NewLine}{FormatCapturedText(stdoutOnTimeout)}{Environment.NewLine}" +
                $"stderr:{Environment.NewLine}{FormatCapturedText(stderrOnTimeout)}");
        }

        return (await stdoutTask, await stderrTask);
    }

    private static string FormatRuntimeDiagnostics(
        DefaultRuntime runtime,
        RuntimeEventCollector? runtimeEvents = null)
    {
        var status = runtime.GetStatus();
        var listeners = status.Listeners.Count == 0
            ? "(empty)"
            : string.Join(
                Environment.NewLine,
                status.Listeners.Select(listener =>
                    $"{listener.Protocol}/{listener.Tag} {listener.Binding.ListenAddress}:{listener.Binding.Port} {listener.State}"));
        var eventText = runtimeEvents?.FormatSnapshot() ?? string.Empty;
        var runtimeEventsSection = string.IsNullOrWhiteSpace(eventText)
            ? string.Empty
            : $"runtime-events:{Environment.NewLine}{eventText}{Environment.NewLine}";

        return
            $"runtime: {status.State}, revision={status.Revision}, message={status.Message}{Environment.NewLine}" +
            $"listeners:{Environment.NewLine}{listeners}{Environment.NewLine}" +
            runtimeEventsSection;
    }

    private static string FormatCapturedText(string text)
        => string.IsNullOrWhiteSpace(text) ? "(empty)" : text;

    private static void TryTerminateProcess(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch
        {
        }
    }

    private sealed class RuntimeEventCollector : IAsyncDisposable
    {
        private readonly object _syncRoot = new();
        private readonly CancellationTokenSource _cancellationTokenSource = new();
        private readonly List<RuntimeEvent> _events = new();
        private readonly Task _pumpTask;

        public RuntimeEventCollector(DefaultRuntime runtime)
        {
            ArgumentNullException.ThrowIfNull(runtime);

            _pumpTask = Task.Run(
                async () =>
                {
                    try
                    {
                        await foreach (var runtimeEvent in runtime.GetEventsAsync(_cancellationTokenSource.Token))
                        {
                            lock (_syncRoot)
                            {
                                _events.Add(runtimeEvent);
                                if (_events.Count > 32)
                                {
                                    _events.RemoveAt(0);
                                }
                            }
                        }
                    }
                    catch (OperationCanceledException) when (_cancellationTokenSource.IsCancellationRequested)
                    {
                    }
                },
                CancellationToken.None);
        }

        public string FormatSnapshot()
        {
            RuntimeEvent[] snapshot;
            lock (_syncRoot)
            {
                if (_events.Count == 0)
                {
                    return string.Empty;
                }

                snapshot = _events.ToArray();
            }

            return string.Join(
                Environment.NewLine,
                snapshot.Select(static runtimeEvent =>
                {
                    var details = runtimeEvent switch
                    {
                        RuntimeConnectionErrorEvent connectionError => $"protocol={connectionError.Protocol}, tag={connectionError.Tag}, remote={connectionError.RemoteEndPoint ?? "(unknown)"}, exception={connectionError.Exception}",
                        RuntimeListenerStartedEvent listenerStarted => $"listener={listenerStarted.Listener.Protocol}/{listenerStarted.Listener.Tag} {listenerStarted.Listener.Binding.ListenAddress}:{listenerStarted.Listener.Binding.Port} {listenerStarted.Listener.State}",
                        RuntimeListenerFaultedEvent listenerFaulted => $"task={listenerFaulted.TaskName}, listeners={listenerFaulted.Listeners.Count}",
                        RuntimeFaultedEvent runtimeFaulted => $"task={runtimeFaulted.TaskName}, exception={runtimeFaulted.Exception}",
                        RuntimeStateChangedEvent stateChanged => $"state={stateChanged.State}",
                        RuntimeClientHelloRejectedEvent clientHelloRejected => $"protocol={clientHelloRejected.Protocol}, remote={clientHelloRejected.RemoteEndPoint ?? "(unknown)"}, serverName={clientHelloRejected.ServerName}, reason={clientHelloRejected.Reason}",
                        RuntimeUnknownServerNameRejectedEvent unknownServerNameRejected => $"protocol={unknownServerNameRejected.Protocol}, remote={unknownServerNameRejected.RemoteEndPoint ?? "(unknown)"}, requestedServerName={unknownServerNameRejected.RequestedServerName}",
                        _ => string.Empty
                    };

                    return $"{runtimeEvent.Timestamp:O} {runtimeEvent.GetType().Name}: {runtimeEvent.Message}" +
                           (string.IsNullOrWhiteSpace(details) ? string.Empty : $" | {details}");
                }));
        }

        public async ValueTask DisposeAsync()
        {
            _cancellationTokenSource.Cancel();
            try
            {
                await _pumpTask;
            }
            catch (OperationCanceledException) when (_cancellationTokenSource.IsCancellationRequested)
            {
            }
            finally
            {
                _cancellationTokenSource.Dispose();
            }
        }
    }

    private static IDispatcher CreateDirectVlessDispatcher(
        VlessOutboundSettings settings,
        out VlessOutboundHandler handler)
    {
        handler = new VlessOutboundHandler(
            new VlessOutboundClient(),
            new StaticVlessOutboundSettingsProvider(settings),
            new VlessUdpPacketReader(),
            new VlessUdpPacketWriter());

        return new DefaultDispatcher(
            new DefaultOutboundRouter(
                new IOutboundHandler[]
                {
                    new FreedomOutboundHandler(),
                    handler
                },
                new StaticOutboundRuntimePlanProvider(
                    new OutboundRuntimePlan
                    {
                        Outbounds =
                        [
                            new OutboundRuntime
                            {
                                Tag = settings.Tag,
                                Protocol = OutboundProtocols.Vless
                            }
                        ],
                        DefaultOutboundTag = settings.Tag
                    })));
    }

    private static IDispatcher CreateDirectVmessDispatcher(
        VmessOutboundSettings settings,
        out VmessOutboundHandler handler)
    {
        handler = new VmessOutboundHandler(
            new VmessOutboundClient(),
            new StaticVmessOutboundSettingsProvider(settings));

        return new DefaultDispatcher(
            new DefaultOutboundRouter(
                new IOutboundHandler[]
                {
                    new FreedomOutboundHandler(),
                    handler
                },
                new StaticOutboundRuntimePlanProvider(
                    new OutboundRuntimePlan
                    {
                        Outbounds =
                        [
                            new OutboundRuntime
                            {
                                Tag = settings.Tag,
                                Protocol = OutboundProtocols.Vmess
                            }
                        ],
                        DefaultOutboundTag = settings.Tag
                    })));
    }

    private static IDispatcher CreateDirectTrojanDispatcher(
        TrojanOutboundSettings settings,
        out TrojanOutboundHandler handler)
    {
        handler = new TrojanOutboundHandler(
            new TrojanOutboundClient(),
            new StaticTrojanOutboundSettingsProvider(settings),
            new TrojanUdpPacketReader(),
            new TrojanUdpPacketWriter());

        return new DefaultDispatcher(
            new DefaultOutboundRouter(
                new IOutboundHandler[]
                {
                    new FreedomOutboundHandler(),
                    handler
                },
                new StaticOutboundRuntimePlanProvider(
                    new OutboundRuntimePlan
                    {
                        Outbounds =
                        [
                            new OutboundRuntime
                            {
                                Tag = settings.Tag,
                                Protocol = OutboundProtocols.Trojan
                            }
                        ],
                        DefaultOutboundTag = settings.Tag
                    })));
    }

    private sealed class StaticVlessOutboundSettingsProvider : IVlessOutboundSettingsProvider
    {
        private readonly VlessOutboundSettings _settings;

        public StaticVlessOutboundSettingsProvider(VlessOutboundSettings settings)
        {
            _settings = settings;
        }

        public bool TryResolve(DispatchContext context, out VlessOutboundSettings settings)
        {
            settings = _settings;
            return true;
        }
    }

    private sealed class StaticVmessOutboundSettingsProvider : IVmessOutboundSettingsProvider
    {
        private readonly VmessOutboundSettings _settings;

        public StaticVmessOutboundSettingsProvider(VmessOutboundSettings settings)
        {
            _settings = settings;
        }

        public bool TryResolve(DispatchContext context, out VmessOutboundSettings settings)
        {
            settings = _settings;
            return true;
        }
    }

    private sealed class StaticTrojanOutboundSettingsProvider : ITrojanOutboundSettingsProvider
    {
        private readonly TrojanOutboundSettings _settings;

        public StaticTrojanOutboundSettingsProvider(TrojanOutboundSettings settings)
        {
            _settings = settings;
        }

        public bool TryResolve(DispatchContext context, out TrojanOutboundSettings settings)
        {
            settings = _settings;
            return true;
        }
    }

    private sealed class StaticOutboundRuntimePlanProvider : IOutboundRuntimePlanProvider
    {
        private readonly OutboundRuntimePlan _plan;

        public StaticOutboundRuntimePlanProvider(OutboundRuntimePlan plan)
        {
            _plan = plan;
        }

        public OutboundRuntimePlan GetCurrentOutboundPlan() => _plan;
    }

    private static int GetAvailableTcpPort()
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        return ((IPEndPoint)socket.LocalEndPoint!).Port;
    }

    private static int GetAvailableUdpPort()
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        return ((IPEndPoint)socket.LocalEndPoint!).Port;
    }

    private static string CreateInteropTempDirectory(string scenario)
    {
        var directory = Path.Combine(
            FindWorkspaceRoot(),
            ".codex-build",
            "interop",
            $"{scenario}-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        return directory;
    }

    private static bool TryGetXrayExecutablePath(out string path)
    {
        var fileName = OperatingSystem.IsWindows() ? "xray.exe" : "xray";
        path = Path.Combine(FindWorkspaceRoot(), ".codex-build", fileName);
        return File.Exists(path);
    }

    private static bool SupportsLegacyMkcpInteropWithXrayR(string xrayExecutable)
    {
        if (string.IsNullOrWhiteSpace(xrayExecutable) || !File.Exists(xrayExecutable))
        {
            return false;
        }

        try
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = xrayExecutable,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };
            process.StartInfo.ArgumentList.Add("version");

            if (!process.Start())
            {
                return false;
            }

            var versionLine = process.StandardOutput.ReadLine();
            process.WaitForExit();
            if (string.IsNullOrWhiteSpace(versionLine))
            {
                return false;
            }

            var match = Regex.Match(versionLine, @"\bXray\s+(?<version>\d+\.\d+\.\d+)\b");
            if (!match.Success ||
                !Version.TryParse(match.Groups["version"].Value, out var version))
            {
                return false;
            }

            return version.Major < 26;
        }
        catch
        {
            return false;
        }
    }

    private static bool TryGetXrayRExecutablePath(out string path)
    {
        var workspaceRoot = FindWorkspaceRoot();
        var fileNames = OperatingSystem.IsWindows()
            ? new[] { "XrayR.exe", "xrayr.exe" }
            : new[] { "XrayR", "xrayr" };

        foreach (var fileName in fileNames)
        {
            var candidate = Path.Combine(workspaceRoot, ".codex-build", fileName);
            if (File.Exists(candidate))
            {
                path = candidate;
                return true;
            }
        }

        path = string.Empty;
        return false;
    }

    private static bool TryGetGoExecutablePath(out string path)
    {
        var toolsDirectory = Path.Combine(FindWorkspaceRoot(), ".codex-build", "tools");
        if (Directory.Exists(toolsDirectory))
        {
            path = Directory
                .EnumerateFiles(toolsDirectory, "go.exe", SearchOption.AllDirectories)
                .Where(static candidate =>
                    candidate.EndsWith(
                        $"{Path.DirectorySeparatorChar}go{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}go.exe",
                        StringComparison.OrdinalIgnoreCase))
                .Where(IsCompleteGoExecutablePath)
                .OrderByDescending(static candidate => candidate.Contains("-full", StringComparison.OrdinalIgnoreCase))
                .ThenByDescending(static candidate => candidate, StringComparer.OrdinalIgnoreCase)
                .FirstOrDefault() ?? string.Empty;
            if (!string.IsNullOrWhiteSpace(path))
            {
                return true;
            }
        }

        var tool = OperatingSystem.IsWindows() ? "where.exe" : "which";
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = tool,
                Arguments = "go",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            }
        };

        if (!process.Start())
        {
            path = string.Empty;
            return false;
        }

        var output = process.StandardOutput.ReadLine();
        process.WaitForExit();
        path = string.IsNullOrWhiteSpace(output) ? string.Empty : output.Trim();
        return process.ExitCode == 0 &&
               !string.IsNullOrWhiteSpace(path) &&
               IsCompleteGoExecutablePath(path);
    }

    private static ProcessStartInfo CreateGoHelperStartInfo(
        string goExecutable,
        string workspaceRoot,
        string helperPath,
        params string[] arguments)
    {
        var codexBuildDirectory = Path.Combine(workspaceRoot, ".codex-build");
        var goCacheDirectory = Path.Combine(codexBuildDirectory, "go-cache");
        var goModuleCacheDirectory = Path.Combine(codexBuildDirectory, "go-mod");
        var goRootDirectory = GetGoRootDirectory(goExecutable);
        Directory.CreateDirectory(goCacheDirectory);
        Directory.CreateDirectory(goModuleCacheDirectory);

        var startInfo = new ProcessStartInfo
        {
            FileName = goExecutable,
            WorkingDirectory = Path.Combine(workspaceRoot, "xray-core"),
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        startInfo.ArgumentList.Add("run");
        startInfo.ArgumentList.Add(helperPath);
        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        startInfo.Environment["GOROOT"] = goRootDirectory;
        startInfo.Environment["GOCACHE"] = goCacheDirectory;
        startInfo.Environment["GOMODCACHE"] = goModuleCacheDirectory;
        return startInfo;
    }

    private static bool IsCompleteGoExecutablePath(string candidate)
    {
        if (string.IsNullOrWhiteSpace(candidate) || !File.Exists(candidate))
        {
            return false;
        }

        var goRootDirectory = GetGoRootDirectory(candidate);
        return File.Exists(Path.Combine(goRootDirectory, "src", "fmt", "print.go")) &&
               File.Exists(Path.Combine(goRootDirectory, "src", "errors", "errors.go"));
    }

    private static string GetGoRootDirectory(string goExecutable)
    {
        var binDirectory = Path.GetDirectoryName(goExecutable);
        return binDirectory is null
            ? string.Empty
            : Path.GetFullPath(Path.Combine(binDirectory, ".."));
    }

    private static string FindWorkspaceRoot()
    {
        if (TryFindWorkspaceRoot(AppContext.BaseDirectory, out var root) ||
            TryFindWorkspaceRoot(Directory.GetCurrentDirectory(), out root))
        {
            return root;
        }

        throw new DirectoryNotFoundException("Could not locate the Xray-core workspace root.");
    }

    private static bool TryFindWorkspaceRoot(string startPath, out string root)
    {
        for (var directory = new DirectoryInfo(startPath); directory is not null; directory = directory.Parent)
        {
            if (Directory.Exists(Path.Combine(directory.FullName, "Xray-dotnet")) &&
                Directory.Exists(Path.Combine(directory.FullName, "xray-core")))
            {
                root = directory.FullName;
                return true;
            }
        }

        root = string.Empty;
        return false;
    }

    private static void TryDeleteDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, recursive: true);
            }
        }
        catch
        {
        }
    }

    private sealed class XrayProcessHandle : IAsyncDisposable
    {
        private readonly string _configPath;
        private readonly string _processName;
        private readonly Process _process;
        private readonly object _sync = new();
        private readonly StringBuilder _standardError = new();
        private readonly StringBuilder _standardOutput = new();
        private bool _captureStarted;

        public XrayProcessHandle(Process process, string configPath, string processName)
        {
            _process = process;
            _configPath = configPath;
            _processName = processName;
            _process.OutputDataReceived += (_, args) => Append(_standardOutput, args.Data);
            _process.ErrorDataReceived += (_, args) => Append(_standardError, args.Data);
        }

        public void BeginCapture()
        {
            if (_captureStarted)
            {
                return;
            }

            _process.BeginOutputReadLine();
            _process.BeginErrorReadLine();
            _captureStarted = true;
        }

        public void AssertStillRunning()
        {
            if (!_process.HasExited)
            {
                return;
            }

            throw new InvalidOperationException(
                $"{_processName} exited unexpectedly with code {_process.ExitCode}.{Environment.NewLine}{GetDiagnostics()}");
        }

        public string GetDiagnostics()
        {
            lock (_sync)
            {
                return
                    $"Config: {_configPath}{Environment.NewLine}" +
                    $"stdout:{Environment.NewLine}{FormatLog(_standardOutput)}{Environment.NewLine}" +
                    $"stderr:{Environment.NewLine}{FormatLog(_standardError)}";
            }
        }

        public async ValueTask DisposeAsync()
        {
            try
            {
                if (!_process.HasExited)
                {
                    _process.Kill(entireProcessTree: true);
                }
            }
            catch (InvalidOperationException)
            {
            }

            try
            {
                await _process.WaitForExitAsync();
            }
            catch (InvalidOperationException)
            {
            }

            if (_captureStarted)
            {
                try
                {
                    _process.CancelOutputRead();
                }
                catch (InvalidOperationException)
                {
                }

                try
                {
                    _process.CancelErrorRead();
                }
                catch (InvalidOperationException)
                {
                }
            }

            _process.Dispose();
        }

        private void Append(StringBuilder builder, string? line)
        {
            if (line is null)
            {
                return;
            }

            lock (_sync)
            {
                builder.AppendLine(line);
            }
        }

        private static string FormatLog(StringBuilder builder)
        {
            var text = builder.ToString().TrimEnd();
            return text.Length == 0 ? "(empty)" : text;
        }
    }

    private sealed class MockSspanelPanelHandle : IAsyncDisposable
    {
        private readonly WebApplication _app;

        public MockSspanelPanelHandle(WebApplication app, string apiHost)
        {
            _app = app;
            ApiHost = apiHost;
        }

        public string ApiHost { get; }

        public async ValueTask DisposeAsync()
        {
            try
            {
                await _app.StopAsync();
            }
            catch
            {
            }

            await _app.DisposeAsync();
        }
    }

    private sealed record CapturedTlsClientHello(
        byte[] ClientHello,
        RuntimeTlsClientHelloMetadata? Metadata,
        RuntimeRealityClientHelloDocument Document);

    private sealed record TlsKeyShareEntry(
        ushort Group,
        byte[] KeyExchange);

    private sealed record TestVlessUserDefinition : IVlessUserDefinition
    {
        public required string UserId { get; init; }

        public required string Uuid { get; init; }

        public string Flow { get; init; } = string.Empty;

        public string ReverseTag { get; init; } = string.Empty;

        public IReadOnlyList<uint> TestSeed { get; init; } = Array.Empty<uint>();

        public int Level { get; init; }

        public required long BytesPerSecond { get; init; }

        public int DeviceLimit { get; init; }
    }

    private sealed record TestVmessUserDefinition : IVmessUserDefinition
    {
        public required string UserId { get; init; }

        public required string Uuid { get; init; }

        public int Level { get; init; }

        public required long BytesPerSecond { get; init; }

        public int DeviceLimit { get; init; }
    }

    private sealed record TestTrojanUserDefinition : ITrojanUserDefinition
    {
        public required string UserId { get; init; }

        public required string Password { get; init; }

        public int Level { get; init; }

        public required long BytesPerSecond { get; init; }

        public int DeviceLimit { get; init; }
    }

    private sealed record TestVlessInboundDefinition
        : IVlessInboundDefinition,
          IVlessInboundScopeDefinition,
          IInboundInternetDefinition,
          IInboundGrpcDefinition,
          IInboundSplitHttpDefinition
    {
        public required string Tag { get; init; }

        public bool Enabled { get; init; }

        public string Protocol { get; init; } = InboundProtocols.Vless;

        public string Transport { get; init; } = string.Empty;

        public string TransportProtocol { get; init; } = RuntimeInternetTransportProtocols.Tcp;

        public string TransportSecurity { get; init; } = RuntimeInternetSecurityTypes.None;

        public string ListenAddress { get; init; } = "127.0.0.1";

        public int Port { get; init; }

        public int HandshakeTimeoutSeconds { get; init; } = 60;

        public bool AcceptProxyProtocol { get; init; }

        public string Host { get; init; } = string.Empty;

        public string Path { get; init; } = string.Empty;

        public int EarlyDataBytes { get; init; }

        public int HeartbeatPeriodSeconds { get; init; }

        public IReadOnlyList<string> ApplicationProtocols { get; init; } = Array.Empty<string>();

        public string GrpcServiceName { get; init; } = string.Empty;

        public string GrpcAuthority { get; init; } = string.Empty;

        public bool GrpcMultiMode { get; init; }

        public string GrpcUserAgent { get; init; } = string.Empty;

        public int GrpcIdleTimeoutSeconds { get; init; }

        public int GrpcHealthCheckTimeoutSeconds { get; init; }

        public bool GrpcPermitWithoutStream { get; init; }

        public int GrpcInitialWindowSize { get; init; }

        public string SplitHttpMode { get; init; } = string.Empty;

        public bool SplitHttpNoSseHeader { get; init; }

        public RuntimeInt32Range SplitHttpXPaddingBytes { get; init; } = RuntimeInt32Range.Empty;

        public bool SplitHttpXPaddingObfsMode { get; init; }

        public string SplitHttpXPaddingKey { get; init; } = string.Empty;

        public string SplitHttpXPaddingHeader { get; init; } = string.Empty;

        public string SplitHttpXPaddingPlacement { get; init; } = string.Empty;

        public string SplitHttpXPaddingMethod { get; init; } = string.Empty;

        public string SplitHttpSessionPlacement { get; init; } = string.Empty;

        public string SplitHttpSessionKey { get; init; } = string.Empty;

        public string SplitHttpSeqPlacement { get; init; } = string.Empty;

        public string SplitHttpSeqKey { get; init; } = string.Empty;

        public string SplitHttpUplinkDataPlacement { get; init; } = string.Empty;

        public string SplitHttpUplinkDataKey { get; init; } = string.Empty;

        public RuntimeInt32Range SplitHttpScMaxEachPostBytes { get; init; } = RuntimeInt32Range.Empty;

        public int SplitHttpScMaxBufferedPosts { get; init; }

        public RuntimeInt32Range SplitHttpScStreamUpServerSecs { get; init; } = RuntimeInt32Range.Empty;

        public int SplitHttpServerMaxHeaderBytes { get; init; }

        public IReadOnlyList<IVlessUserDefinition> Users { get; init; } = Array.Empty<IVlessUserDefinition>();

        public IReadOnlyList<IVlessUserDefinition> GetVlessUsers() => Users;

        public string GetVlessFlow() => string.Empty;

        public IReadOnlyList<uint> GetVlessTestSeed() => Array.Empty<uint>();

        public string GetVlessDecryption() => string.Empty;

        public uint GetVlessXorMode() => 0;

        public int GetVlessSecondsFrom() => 0;

        public int GetVlessSecondsTo() => 0;

        public string GetVlessPadding() => string.Empty;

        public IReadOnlyList<ITrojanFallbackDefinition> GetFallbacks() => Array.Empty<ITrojanFallbackDefinition>();

        public IRuntimeSniffingDefinition GetSniffing() => RuntimeSniffingOptions.Disabled;

        public bool GetReceiveOriginalDestination() => false;
    }

    private sealed record TestVmessInboundDefinition
        : IVmessInboundDefinition,
          IVmessInboundScopeDefinition,
          IInboundInternetDefinition,
          IInboundGrpcDefinition,
          IInboundSplitHttpDefinition
    {
        public required string Tag { get; init; }

        public bool Enabled { get; init; }

        public string Protocol { get; init; } = InboundProtocols.Vmess;

        public string Transport { get; init; } = string.Empty;

        public string TransportProtocol { get; init; } = RuntimeInternetTransportProtocols.Tcp;

        public string TransportSecurity { get; init; } = RuntimeInternetSecurityTypes.None;

        public string ListenAddress { get; init; } = "127.0.0.1";

        public int Port { get; init; }

        public int HandshakeTimeoutSeconds { get; init; } = 60;

        public bool AcceptProxyProtocol { get; init; }

        public string Host { get; init; } = string.Empty;

        public string Path { get; init; } = string.Empty;

        public int EarlyDataBytes { get; init; }

        public int HeartbeatPeriodSeconds { get; init; }

        public IReadOnlyList<string> ApplicationProtocols { get; init; } = Array.Empty<string>();

        public string GrpcServiceName { get; init; } = string.Empty;

        public string GrpcAuthority { get; init; } = string.Empty;

        public bool GrpcMultiMode { get; init; }

        public string GrpcUserAgent { get; init; } = string.Empty;

        public int GrpcIdleTimeoutSeconds { get; init; }

        public int GrpcHealthCheckTimeoutSeconds { get; init; }

        public bool GrpcPermitWithoutStream { get; init; }

        public int GrpcInitialWindowSize { get; init; }

        public string SplitHttpMode { get; init; } = string.Empty;

        public bool SplitHttpNoSseHeader { get; init; }

        public RuntimeInt32Range SplitHttpXPaddingBytes { get; init; } = RuntimeInt32Range.Empty;

        public bool SplitHttpXPaddingObfsMode { get; init; }

        public string SplitHttpXPaddingKey { get; init; } = string.Empty;

        public string SplitHttpXPaddingHeader { get; init; } = string.Empty;

        public string SplitHttpXPaddingPlacement { get; init; } = string.Empty;

        public string SplitHttpXPaddingMethod { get; init; } = string.Empty;

        public string SplitHttpSessionPlacement { get; init; } = string.Empty;

        public string SplitHttpSessionKey { get; init; } = string.Empty;

        public string SplitHttpSeqPlacement { get; init; } = string.Empty;

        public string SplitHttpSeqKey { get; init; } = string.Empty;

        public string SplitHttpUplinkDataPlacement { get; init; } = string.Empty;

        public string SplitHttpUplinkDataKey { get; init; } = string.Empty;

        public RuntimeInt32Range SplitHttpScMaxEachPostBytes { get; init; } = RuntimeInt32Range.Empty;

        public int SplitHttpScMaxBufferedPosts { get; init; }

        public RuntimeInt32Range SplitHttpScStreamUpServerSecs { get; init; } = RuntimeInt32Range.Empty;

        public int SplitHttpServerMaxHeaderBytes { get; init; }

        public IReadOnlyList<IVmessUserDefinition> Users { get; init; } = Array.Empty<IVmessUserDefinition>();

        public IReadOnlyList<IVmessUserDefinition> GetVmessUsers() => Users;

        public IRuntimeSniffingDefinition GetSniffing() => RuntimeSniffingOptions.Disabled;

        public bool GetReceiveOriginalDestination() => false;
    }

    private sealed record TestTrojanInboundDefinition
        : ITrojanInboundDefinition,
          ITrojanInboundScopeDefinition,
          IInboundInternetDefinition,
          IInboundGrpcDefinition,
          IInboundSplitHttpDefinition
    {
        public required string Tag { get; init; }

        public bool Enabled { get; init; }

        public string Protocol { get; init; } = InboundProtocols.Trojan;

        public string Transport { get; init; } = string.Empty;

        public string TransportProtocol { get; init; } = RuntimeInternetTransportProtocols.Tcp;

        public string TransportSecurity { get; init; } = RuntimeInternetSecurityTypes.None;

        public string ListenAddress { get; init; } = "127.0.0.1";

        public int Port { get; init; }

        public int HandshakeTimeoutSeconds { get; init; } = 60;

        public bool AcceptProxyProtocol { get; init; }

        public string Host { get; init; } = string.Empty;

        public string Path { get; init; } = string.Empty;

        public int EarlyDataBytes { get; init; }

        public int HeartbeatPeriodSeconds { get; init; }

        public IReadOnlyList<string> ApplicationProtocols { get; init; } = Array.Empty<string>();

        public string GrpcServiceName { get; init; } = string.Empty;

        public string GrpcAuthority { get; init; } = string.Empty;

        public bool GrpcMultiMode { get; init; }

        public string GrpcUserAgent { get; init; } = string.Empty;

        public int GrpcIdleTimeoutSeconds { get; init; }

        public int GrpcHealthCheckTimeoutSeconds { get; init; }

        public bool GrpcPermitWithoutStream { get; init; }

        public int GrpcInitialWindowSize { get; init; }

        public string SplitHttpMode { get; init; } = string.Empty;

        public bool SplitHttpNoSseHeader { get; init; }

        public RuntimeInt32Range SplitHttpXPaddingBytes { get; init; } = RuntimeInt32Range.Empty;

        public bool SplitHttpXPaddingObfsMode { get; init; }

        public string SplitHttpXPaddingKey { get; init; } = string.Empty;

        public string SplitHttpXPaddingHeader { get; init; } = string.Empty;

        public string SplitHttpXPaddingPlacement { get; init; } = string.Empty;

        public string SplitHttpXPaddingMethod { get; init; } = string.Empty;

        public string SplitHttpSessionPlacement { get; init; } = string.Empty;

        public string SplitHttpSessionKey { get; init; } = string.Empty;

        public string SplitHttpSeqPlacement { get; init; } = string.Empty;

        public string SplitHttpSeqKey { get; init; } = string.Empty;

        public string SplitHttpUplinkDataPlacement { get; init; } = string.Empty;

        public string SplitHttpUplinkDataKey { get; init; } = string.Empty;

        public RuntimeInt32Range SplitHttpScMaxEachPostBytes { get; init; } = RuntimeInt32Range.Empty;

        public int SplitHttpScMaxBufferedPosts { get; init; }

        public RuntimeInt32Range SplitHttpScStreamUpServerSecs { get; init; } = RuntimeInt32Range.Empty;

        public int SplitHttpServerMaxHeaderBytes { get; init; }

        public IReadOnlyList<ITrojanUserDefinition> Users { get; init; } = Array.Empty<ITrojanUserDefinition>();

        public IReadOnlyList<ITrojanUserDefinition> GetUsers() => Users;

        public IReadOnlyList<ITrojanFallbackDefinition> GetFallbacks() => Array.Empty<ITrojanFallbackDefinition>();

        public IRuntimeSniffingDefinition GetSniffing() => RuntimeSniffingOptions.Disabled;

        public bool GetReceiveOriginalDestination() => false;
    }
}

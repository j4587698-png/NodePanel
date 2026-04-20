namespace NodePanel.Core.Runtime;

public static class ShadowsocksOutboundOptionsCompiler
{
    public static IRuntimeOutboundOptions Compile(IRuntimeOutboundOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (!TryCompile(options, out var compiled, out var error))
        {
            throw new InvalidOperationException(error);
        }

        return compiled;
    }

    public static RuntimeShadowsocksOutboundOptions CompileRegular(RuntimeShadowsocksOutboundOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var compiled = Compile((IRuntimeOutboundOptions)options);
        if (compiled is RuntimeShadowsocksOutboundOptions regular)
        {
            return regular;
        }

        throw new NotSupportedException(
            $"Legacy Shadowsocks outbound handler only supports regular Shadowsocks methods. '{GetMethod(compiled)}' must be resolved through the dedicated Shadowsocks 2022 outbound path.");
    }

    public static RuntimeShadowsocks2022OutboundOptions Compile2022(IRuntimeOutboundOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var compiled = Compile(options);
        if (compiled is RuntimeShadowsocks2022OutboundOptions shadowsocks2022)
        {
            return shadowsocks2022;
        }

        throw new NotSupportedException(
            $"Shadowsocks 2022 outbound settings require a Shadowsocks 2022 method, but '{GetMethod(compiled)}' resolved to the regular Shadowsocks path.");
    }

    public static bool TryCompile(
        IRuntimeOutboundOptions options,
        out IRuntimeOutboundOptions compiled,
        out string? error)
    {
        ArgumentNullException.ThrowIfNull(options);

        switch (options)
        {
            case RuntimeShadowsocksOutboundOptions shadowsocks:
                return TryCompile(
                    shadowsocks.Tag,
                    shadowsocks.ServerHost,
                    shadowsocks.ServerPort,
                    shadowsocks.Cipher,
                    shadowsocks.Password,
                    shadowsocks.UdpOverTcp,
                    shadowsocks.UdpOverTcpVersion,
                    shadowsocks.ConnectTimeoutSeconds,
                    out compiled,
                    out error);
            case RuntimeShadowsocks2022OutboundOptions shadowsocks2022:
                return TryCompile(
                    shadowsocks2022.Tag,
                    shadowsocks2022.ServerHost,
                    shadowsocks2022.ServerPort,
                    shadowsocks2022.Method,
                    shadowsocks2022.Key,
                    shadowsocks2022.UdpOverTcp,
                    shadowsocks2022.UdpOverTcpVersion,
                    shadowsocks2022.ConnectTimeoutSeconds,
                    out compiled,
                    out error);
            default:
                compiled = default!;
                error = $"Unsupported Shadowsocks outbound runtime option type: {options.GetType().Name}.";
                return false;
        }
    }

    private static bool TryCompile(
        string tag,
        string serverHost,
        int serverPort,
        string method,
        string secret,
        bool udpOverTcp,
        int udpOverTcpVersion,
        int connectTimeoutSeconds,
        out IRuntimeOutboundOptions compiled,
        out string? error)
    {
        var normalizedHost = serverHost?.Trim() ?? string.Empty;
        if (normalizedHost.Length == 0)
        {
            compiled = default!;
            error = "Shadowsocks server address is not set.";
            return false;
        }

        if (serverPort is <= 0 or > 65535)
        {
            compiled = default!;
            error = "Invalid Shadowsocks port.";
            return false;
        }

        var normalizedMethod = ShadowsocksCipherTypes.Normalize(method);
        if (!ShadowsocksCipherTypes.IsRegularMethod(normalizedMethod) &&
            !ShadowsocksCipherTypes.Is2022Method(normalizedMethod))
        {
            compiled = default!;
            error = $"unknown cipher method: {method?.Trim() ?? string.Empty}";
            return false;
        }

        var normalizedSecret = secret?.Trim() ?? string.Empty;
        if (normalizedSecret.Length == 0)
        {
            compiled = default!;
            error = "Shadowsocks password is not specified.";
            return false;
        }

        var normalizedTag = tag?.Trim() ?? string.Empty;
        var normalizedConnectTimeoutSeconds = Math.Max(0, connectTimeoutSeconds);
        if (ShadowsocksCipherTypes.Is2022Method(normalizedMethod))
        {
            compiled = new RuntimeShadowsocks2022OutboundOptions
            {
                Tag = normalizedTag,
                ServerHost = normalizedHost,
                ServerPort = serverPort,
                Method = normalizedMethod,
                Key = normalizedSecret,
                UdpOverTcp = udpOverTcp,
                UdpOverTcpVersion = Math.Max(0, udpOverTcpVersion),
                ConnectTimeoutSeconds = normalizedConnectTimeoutSeconds
            };
            error = null;
            return true;
        }

        compiled = new RuntimeShadowsocksOutboundOptions
        {
            Tag = normalizedTag,
            ServerHost = normalizedHost,
            ServerPort = serverPort,
            Cipher = normalizedMethod,
            Password = normalizedSecret,
            UdpOverTcp = false,
            UdpOverTcpVersion = 0,
            ConnectTimeoutSeconds = normalizedConnectTimeoutSeconds
        };
        error = null;
        return true;
    }

    private static string GetMethod(IRuntimeOutboundOptions options)
        => options switch
        {
            RuntimeShadowsocksOutboundOptions shadowsocks => shadowsocks.Cipher,
            RuntimeShadowsocks2022OutboundOptions shadowsocks2022 => shadowsocks2022.Method,
            _ => string.Empty
        };
}

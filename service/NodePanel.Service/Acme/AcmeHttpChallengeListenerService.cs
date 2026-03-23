using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NodePanel.ControlPlane.Configuration;
using NodePanel.Service.Runtime;

namespace NodePanel.Service.Acme;

public sealed class AcmeHttpChallengeListenerService : BackgroundService
{
    private const string ChallengePathPrefix = "/.well-known/acme-challenge/";

    private readonly AcmeHttpChallengeStore _challengeStore;
    private readonly ILogger<AcmeHttpChallengeListenerService> _logger;
    private readonly RuntimeConfigStore _runtimeConfigStore;

    public AcmeHttpChallengeListenerService(
        RuntimeConfigStore runtimeConfigStore,
        AcmeHttpChallengeStore challengeStore,
        ILogger<AcmeHttpChallengeListenerService> logger)
    {
        _runtimeConfigStore = runtimeConfigStore;
        _challengeStore = challengeStore;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            var runtime = _runtimeConfigStore.GetSnapshot();
            var binding = GetBinding(runtime.Config.Certificate);
            if (binding is null)
            {
                _challengeStore.ReportListener(new AcmeHttpChallengeListenerSnapshot());
                await _runtimeConfigStore.WaitForChangeAsync(runtime.Revision, stoppingToken).ConfigureAwait(false);
                continue;
            }

            using var listener = new TcpListener(binding.Address, binding.Port);

            try
            {
                listener.Start();
            }
            catch (Exception ex)
            {
                _challengeStore.ReportListener(
                    new AcmeHttpChallengeListenerSnapshot
                    {
                        IsListening = false,
                        ListenAddress = binding.Address.ToString(),
                        Port = binding.Port,
                        LastError = ex.Message
                    });

                _logger.LogWarning(ex, "HTTP-01 challenge listener failed to bind on {Address}:{Port}.", binding.Address, binding.Port);
                var changeTask = _runtimeConfigStore.WaitForChangeAsync(runtime.Revision, stoppingToken);
                var retryTask = Task.Delay(TimeSpan.FromSeconds(15), stoppingToken);
                await Task.WhenAny(changeTask, retryTask).ConfigureAwait(false);
                continue;
            }

            _challengeStore.ReportListener(
                new AcmeHttpChallengeListenerSnapshot
                {
                    IsListening = true,
                    ListenAddress = binding.Address.ToString(),
                    Port = binding.Port,
                    LastError = string.Empty
                });

            _logger.LogInformation("HTTP-01 challenge listener bound on {Address}:{Port}.", binding.Address, binding.Port);

            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
            var acceptLoop = AcceptLoopAsync(listener, linkedCts.Token);
            var changeWait = _runtimeConfigStore.WaitForChangeAsync(runtime.Revision, stoppingToken);
            var completed = await Task.WhenAny(acceptLoop, changeWait).ConfigureAwait(false);

            linkedCts.Cancel();
            listener.Stop();

            try
            {
                await acceptLoop.ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (linkedCts.IsCancellationRequested)
            {
            }

            _challengeStore.ReportListener(
                new AcmeHttpChallengeListenerSnapshot
                {
                    IsListening = false,
                    ListenAddress = binding.Address.ToString(),
                    Port = binding.Port,
                    LastError = string.Empty
                });

            if (completed == acceptLoop && !stoppingToken.IsCancellationRequested)
            {
                _logger.LogWarning("HTTP-01 challenge listener stopped unexpectedly. Restarting.");
                await Task.Delay(TimeSpan.FromSeconds(1), stoppingToken).ConfigureAwait(false);
            }
        }
    }

    private static AcmeHttpChallengeBinding? GetBinding(CertificateOptions certificate)
    {
        if (CertificateModes.Normalize(certificate.Mode) != CertificateModes.AcmeManaged)
        {
            return null;
        }

        if (!string.Equals(CertificateChallengeTypes.Normalize(certificate.ChallengeType), CertificateChallengeTypes.Http01, StringComparison.Ordinal))
        {
            return null;
        }

        if (!IPAddress.TryParse(certificate.HttpChallengeListenAddress, out var address))
        {
            return null;
        }

        return new AcmeHttpChallengeBinding(address, certificate.HttpChallengePort);
    }

    private async Task AcceptLoopAsync(TcpListener listener, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await listener.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }

            _ = Task.Run(() => HandleClientAsync(client, cancellationToken), cancellationToken);
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken cancellationToken)
    {
        using (client)
        {
            using var stream = client.GetStream();
            using var reader = new StreamReader(stream, Encoding.ASCII, detectEncodingFromByteOrderMarks: false, bufferSize: 1024, leaveOpen: true);

            try
            {
                var requestLine = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false);
                if (string.IsNullOrWhiteSpace(requestLine))
                {
                    return;
                }

                while (true)
                {
                    var headerLine = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false);
                    if (headerLine is null || headerLine.Length == 0)
                    {
                        break;
                    }
                }

                if (!TryParseRequest(requestLine, out var method, out var path))
                {
                    await WriteResponseAsync(stream, 400, "Bad Request", "text/plain; charset=utf-8", "bad request", includeBody: true, cancellationToken).ConfigureAwait(false);
                    return;
                }

                var includeBody = !string.Equals(method, "HEAD", StringComparison.OrdinalIgnoreCase);
                if (!string.Equals(method, "GET", StringComparison.OrdinalIgnoreCase) &&
                    !string.Equals(method, "HEAD", StringComparison.OrdinalIgnoreCase))
                {
                    await WriteResponseAsync(stream, 405, "Method Not Allowed", "text/plain; charset=utf-8", "method not allowed", includeBody, cancellationToken).ConfigureAwait(false);
                    return;
                }

                if (!TryExtractToken(path, out var token) || !_challengeStore.TryGetResponse(token, out var keyAuthorization))
                {
                    await WriteResponseAsync(stream, 404, "Not Found", "text/plain; charset=utf-8", "not found", includeBody, cancellationToken).ConfigureAwait(false);
                    return;
                }

                await WriteResponseAsync(stream, 200, "OK", "text/plain; charset=utf-8", keyAuthorization, includeBody, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "HTTP-01 challenge request failed from {RemoteEndPoint}.", client.Client.RemoteEndPoint);
            }
        }
    }

    private static bool TryParseRequest(string requestLine, out string method, out string path)
    {
        method = string.Empty;
        path = string.Empty;

        var parts = requestLine.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length < 2)
        {
            return false;
        }

        method = parts[0];
        path = parts[1];
        return true;
    }

    private static bool TryExtractToken(string requestPath, out string token)
    {
        token = string.Empty;
        var path = requestPath.Split('?', 2, StringSplitOptions.TrimEntries)[0];
        if (!path.StartsWith(ChallengePathPrefix, StringComparison.Ordinal))
        {
            return false;
        }

        token = Uri.UnescapeDataString(path[ChallengePathPrefix.Length..]);
        return !string.IsNullOrWhiteSpace(token);
    }

    private static async Task WriteResponseAsync(
        Stream stream,
        int statusCode,
        string reasonPhrase,
        string contentType,
        string body,
        bool includeBody,
        CancellationToken cancellationToken)
    {
        var bodyBytes = Encoding.UTF8.GetBytes(body);
        var header =
            $"HTTP/1.1 {statusCode} {reasonPhrase}\r\n" +
            $"Content-Type: {contentType}\r\n" +
            $"Content-Length: {bodyBytes.Length}\r\n" +
            "Connection: close\r\n\r\n";

        await stream.WriteAsync(Encoding.ASCII.GetBytes(header), cancellationToken).ConfigureAwait(false);
        if (includeBody && bodyBytes.Length > 0)
        {
            await stream.WriteAsync(bodyBytes, cancellationToken).ConfigureAwait(false);
        }

        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }
}

internal sealed record AcmeHttpChallengeBinding(IPAddress Address, int Port);

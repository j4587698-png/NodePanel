using System.Collections.Concurrent;

namespace NodePanel.Panel.Services;

public sealed class PanelAcmeHttpChallengeStore
{
    private readonly ConcurrentDictionary<string, string> _responses = new(StringComparer.Ordinal);

    public void Put(string token, string keyAuthorization)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);
        ArgumentException.ThrowIfNullOrWhiteSpace(keyAuthorization);
        _responses[token] = keyAuthorization;
    }

    public void Remove(string token)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return;
        }

        _responses.TryRemove(token, out _);
    }

    public bool TryGet(string token, out string keyAuthorization)
        => _responses.TryGetValue(token, out keyAuthorization!);
}

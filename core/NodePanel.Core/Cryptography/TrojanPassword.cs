using System.Text;

namespace NodePanel.Core.Cryptography;

public static class TrojanPassword
{
    public static string ComputeHash(string password)
    {
        var bytes = Encoding.UTF8.GetBytes(password);
        var hash = Sha224.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}

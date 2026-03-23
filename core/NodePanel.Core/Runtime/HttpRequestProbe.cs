using System.Text;

namespace NodePanel.Core.Runtime;

internal static class HttpRequestProbe
{
    public static string ExtractRequestPath(ReadOnlySpan<byte> initialPayload)
    {
        if (initialPayload.Length < 18 || initialPayload[4] == (byte)'*')
        {
            return string.Empty;
        }

        var searchLimit = Math.Min(initialPayload.Length, 64);
        for (var i = 4; i <= 8 && i < searchLimit; i++)
        {
            if (initialPayload[i] != (byte)'/' || initialPayload[i - 1] != (byte)' ')
            {
                continue;
            }

            for (var j = i + 1; j < searchLimit; j++)
            {
                var current = initialPayload[j];
                if (current is (byte)'\r' or (byte)'\n')
                {
                    break;
                }

                if (current is (byte)'?' or (byte)' ')
                {
                    return Encoding.ASCII.GetString(initialPayload[i..j]);
                }
            }

            break;
        }

        return string.Empty;
    }
}

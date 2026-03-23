using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using NodePanel.Panel.Models;

namespace NodePanel.Panel.Services;

public sealed class EpayService
{
    private readonly DatabaseService _db;

    public EpayService(DatabaseService db)
    {
        _db = db;
    }

    public async Task<string> GeneratePaymentUrlAsync(string orderId, decimal amount, string notifyUrl, string returnUrl, CancellationToken cancellationToken = default)
    {
        var settings = await _db.FSql.Select<SettingEntity>().ToListAsync(cancellationToken);
        var s = settings.ToDictionary(k => k.Key, v => v.Value);

        var apiUrl = s.GetValueOrDefault("epay_apiurl");
        var pid = s.GetValueOrDefault("epay_pid");
        var key = s.GetValueOrDefault("epay_key");

        if (string.IsNullOrWhiteSpace(apiUrl) || string.IsNullOrWhiteSpace(pid) || string.IsNullOrWhiteSpace(key))
            throw new InvalidOperationException("Epay gateway is not configured.");

        var dict = new Dictionary<string, string>
        {
            {"pid", pid},
            {"type", "alipay"}, // Default or configurable
            {"out_trade_no", orderId},
            {"notify_url", notifyUrl},
            {"return_url", returnUrl},
            {"name", $"Proxy Subscription - {orderId}"},
            {"money", amount.ToString("F2")},
            {"sitename", s.GetValueOrDefault("site_name") ?? "ProxyPanel"}
        };

        var sign = GenerateSignature(dict, key);
        dict.Add("sign", sign);
        dict.Add("sign_type", "MD5");

        var queryString = string.Join("&", dict.Select(kvp => $"{kvp.Key}={Uri.EscapeDataString(kvp.Value)}"));
        var baseUri = apiUrl.TrimEnd('/');
        var endpoint = baseUri.EndsWith(".php") ? baseUri : $"{baseUri}/submit.php";
        return $"{endpoint}?{queryString}";
    }

    public async Task<bool> VerifySignatureAsync(IFormCollection form, CancellationToken cancellationToken = default)
    {
        var settings = await _db.FSql.Select<SettingEntity>().ToListAsync(cancellationToken);
        var s = settings.ToDictionary(k => k.Key, v => v.Value);
        var key = s.GetValueOrDefault("epay_key");

        if (string.IsNullOrWhiteSpace(key)) return false;

        var dict = new Dictionary<string, string>();
        foreach (var keyName in form.Keys)
        {
            if (keyName == "sign" || keyName == "sign_type") continue;
            var value = form[keyName].ToString();
            if (string.IsNullOrWhiteSpace(value)) continue;
            dict.Add(keyName, value);
        }

        var expectedSign = GenerateSignature(dict, key);
        var actualSign = form["sign"].ToString();

        return string.Equals(expectedSign, actualSign, StringComparison.OrdinalIgnoreCase);
    }

    private static string GenerateSignature(Dictionary<string, string> parameters, string key)
    {
        var sortedParams = parameters.OrderBy(kvp => kvp.Key, StringComparer.Ordinal)
                                     .Where(kvp => !string.IsNullOrEmpty(kvp.Value));
        
        var signStr = string.Join("&", sortedParams.Select(kvp => $"{kvp.Key}={kvp.Value}"));
        signStr += key;

        using var md5 = MD5.Create();
        var hash = md5.ComputeHash(Encoding.UTF8.GetBytes(signStr));
        var sb = new StringBuilder();
        foreach (var b in hash) sb.Append(b.ToString("x2"));
        return sb.ToString();
    }
}

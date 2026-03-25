using NodePanel.Panel.Models;

namespace NodePanel.Panel.Services;

public sealed class SubscriptionProfileResolver
{
    private static readonly string[] ReservedGroupNames =
    [
        "Proxy",
        "GLOBAL",
        "Auto",
        "Fallback",
        "Load Balance",
        "All Nodes",
        "DIRECT",
        "REJECT"
    ];

    private static readonly IReadOnlyDictionary<string, string> RegionAliases =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["hk"] = "香港",
            ["hongkong"] = "香港",
            ["hong kong"] = "香港",
            ["香港"] = "香港",
            ["tw"] = "台湾",
            ["taiwan"] = "台湾",
            ["台湾"] = "台湾",
            ["jp"] = "日本",
            ["japan"] = "日本",
            ["日本"] = "日本",
            ["sg"] = "新加坡",
            ["singapore"] = "新加坡",
            ["新加坡"] = "新加坡",
            ["us"] = "美国",
            ["usa"] = "美国",
            ["united states"] = "美国",
            ["america"] = "美国",
            ["美国"] = "美国",
            ["kr"] = "韩国",
            ["korea"] = "韩国",
            ["韩国"] = "韩国",
            ["uk"] = "英国",
            ["gb"] = "英国",
            ["britain"] = "英国",
            ["united kingdom"] = "英国",
            ["英国"] = "英国",
            ["de"] = "德国",
            ["germany"] = "德国",
            ["德国"] = "德国"
        };

    private static readonly IReadOnlyDictionary<string, string> TagAliases =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["stream"] = "流媒体",
            ["media"] = "流媒体",
            ["unlock"] = "流媒体",
            ["video"] = "流媒体",
            ["ai"] = "AI",
            ["openai"] = "AI",
            ["chatgpt"] = "AI",
            ["claude"] = "AI",
            ["gemini"] = "AI",
            ["game"] = "游戏",
            ["gaming"] = "游戏",
            ["telegram"] = "Telegram",
            ["tg"] = "Telegram",
            ["youtube"] = "YouTube",
            ["yt"] = "YouTube",
            ["google"] = "Google",
            ["netflix"] = "Netflix",
            ["nf"] = "Netflix",
            ["disney"] = "Disney+",
            ["disney+"] = "Disney+",
            ["spotify"] = "Spotify",
            ["apple"] = "Apple",
            ["icloud"] = "Apple",
            ["microsoft"] = "Microsoft",
            ["onedrive"] = "Microsoft"
        };

    public SubscriptionRequestContext ResolveRequest(
        string? flag,
        string? profile,
        string? userAgent,
        IReadOnlyDictionary<string, string>? settings)
    {
        var renderSettings = SubscriptionRenderSettings.FromSettings(settings);
        var resolvedProfile = SubscriptionProfileNames.Normalize(
            string.IsNullOrWhiteSpace(profile)
                ? renderSettings.DefaultProfile
                : profile);

        return new SubscriptionRequestContext
        {
            Format = ResolveFormat(flag, userAgent),
            ProfileName = resolvedProfile,
            Settings = renderSettings
        };
    }

    public SubscriptionRenderPlan BuildPlan(SubscriptionCatalog catalog, SubscriptionRequestContext request)
    {
        ArgumentNullException.ThrowIfNull(catalog);
        ArgumentNullException.ThrowIfNull(request);

        var proxies = BuildProxies(catalog, request.Format);
        if (!SubscriptionFormats.IsStructured(request.Format))
        {
            return new SubscriptionRenderPlan
            {
                Request = request,
                Proxies = proxies,
                FinalGroupName = "Proxy"
            };
        }

        var groups = BuildStructuredGroups(proxies, request);
        var finalGroupName = groups.Any(group => string.Equals(group.Name, "GLOBAL", StringComparison.Ordinal))
            ? "GLOBAL"
            : "Proxy";
        var rules = BuildRules(groups, request, finalGroupName);

        return new SubscriptionRenderPlan
        {
            Request = request,
            Proxies = proxies,
            Groups = groups,
            Rules = rules,
            FinalGroupName = finalGroupName
        };
    }

    private static IReadOnlyList<SubscriptionRenderProxy> BuildProxies(SubscriptionCatalog catalog, string format)
    {
        var nodesById = catalog.AssignedNodes
            .GroupBy(static node => node.NodeId, StringComparer.Ordinal)
            .ToDictionary(static group => group.Key, static group => group.First(), StringComparer.Ordinal);
        var proxies = new List<SubscriptionRenderProxy>(catalog.Endpoints.Count);

        foreach (var endpoint in catalog.Endpoints)
        {
            var protocol = NormalizeProtocol(endpoint.Protocol);
            if (!SupportsFormat(format, protocol))
            {
                continue;
            }

            nodesById.TryGetValue(endpoint.NodeId, out var node);
            var tags = ResolveTags(node);
            proxies.Add(new SubscriptionRenderProxy
            {
                Endpoint = endpoint,
                Name = endpoint.Label,
                Protocol = protocol,
                Region = ResolveRegion(node, endpoint, tags),
                Tags = tags
            });
        }

        return proxies;
    }

    private static IReadOnlyList<SubscriptionProxyGroup> BuildStructuredGroups(
        IReadOnlyList<SubscriptionRenderProxy> proxies,
        SubscriptionRequestContext request)
    {
        var profile = ResolveProfileDefinition(request);
        var allProxyNames = proxies
            .Select(static proxy => proxy.Name)
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        if (allProxyNames.Length == 0)
        {
            var emptyGroups = new List<SubscriptionProxyGroup>
            {
                new()
                {
                    Name = "Proxy",
                    Type = "select",
                    Proxies = ["DIRECT"]
                }
            };

            if (profile.IncludeGlobalGroup)
            {
                emptyGroups.Add(
                    new SubscriptionProxyGroup
                    {
                        Name = "GLOBAL",
                        Type = "select",
                        Proxies = profile.IncludeRejectInGlobalGroup
                            ? ["Proxy", "DIRECT", "REJECT"]
                            : ["Proxy", "DIRECT"]
                    });
            }

            return emptyGroups;
        }

        var groups = new List<SubscriptionProxyGroup>();
        var existingNames = new HashSet<string>(ReservedGroupNames, StringComparer.OrdinalIgnoreCase);
        var proxySelectorTargets = new List<string>();

        if (profile.IncludeAutoGroup && allProxyNames.Length > 1)
        {
            groups.Add(new SubscriptionProxyGroup
            {
                Name = "Auto",
                Type = "url-test",
                Proxies = allProxyNames,
                Url = request.Settings.TestUrl,
                IntervalSeconds = request.Settings.TestIntervalSeconds
            });
            proxySelectorTargets.Add("Auto");
        }

        if (profile.IncludeFallbackGroup && allProxyNames.Length > 1)
        {
            groups.Add(new SubscriptionProxyGroup
            {
                Name = "Fallback",
                Type = "fallback",
                Proxies = allProxyNames,
                Url = request.Settings.TestUrl,
                IntervalSeconds = request.Settings.TestIntervalSeconds
            });
            proxySelectorTargets.Add("Fallback");
        }

        if (profile.IncludeLoadBalanceGroup && allProxyNames.Length > 1)
        {
            groups.Add(new SubscriptionProxyGroup
            {
                Name = "Load Balance",
                Type = "load-balance",
                Proxies = allProxyNames,
                Strategy = "round-robin"
            });
            proxySelectorTargets.Add("Load Balance");
        }

        if (profile.IncludeRegionGroups)
        {
            foreach (var bucket in proxies
                         .Where(static proxy => !string.IsNullOrWhiteSpace(proxy.Region))
                         .GroupBy(static proxy => proxy.Region, StringComparer.OrdinalIgnoreCase)
                         .OrderBy(static bucket => GetRegionSortOrder(bucket.Key))
                         .ThenBy(static bucket => bucket.Key, StringComparer.Ordinal))
            {
                var groupName = EnsureUniqueGroupName(bucket.Key, existingNames);
                var groupProxies = bucket
                    .Select(static proxy => proxy.Name)
                    .Distinct(StringComparer.Ordinal)
                    .ToArray();
                if (groupProxies.Length == 0)
                {
                    continue;
                }

                groups.Add(new SubscriptionProxyGroup
                {
                    Name = groupName,
                    Type = "select",
                    Proxies = groupProxies
                });
                proxySelectorTargets.Add(groupName);
            }
        }

        if (profile.IncludeTagGroups)
        {
            foreach (var bucket in proxies
                         .SelectMany(static proxy => proxy.Tags.Select(tag => (Tag: tag, ProxyName: proxy.Name)))
                         .GroupBy(static item => item.Tag, StringComparer.OrdinalIgnoreCase)
                         .OrderBy(static bucket => GetTagSortOrder(bucket.Key))
                         .ThenBy(static bucket => bucket.Key, StringComparer.Ordinal))
            {
                var groupProxies = bucket
                    .Select(static item => item.ProxyName)
                    .Distinct(StringComparer.Ordinal)
                    .ToArray();
                if (groupProxies.Length == 0)
                {
                    continue;
                }

                var groupName = EnsureUniqueGroupName(bucket.Key, existingNames);
                groups.Add(new SubscriptionProxyGroup
                {
                    Name = groupName,
                    Type = "select",
                    Proxies = groupProxies
                });
                proxySelectorTargets.Add(groupName);
            }
        }

        AddCustomGroups(groups, proxies, request, existingNames, proxySelectorTargets);

        var allNodesGroup = new SubscriptionProxyGroup
        {
            Name = "All Nodes",
            Type = "select",
            Proxies = allProxyNames
        };
        groups.Add(allNodesGroup);
        proxySelectorTargets.Add(allNodesGroup.Name);

        groups.Insert(
            0,
            new SubscriptionProxyGroup
            {
                Name = "Proxy",
                Type = "select",
                Proxies = proxySelectorTargets.Count == 0
                    ? allProxyNames
                    : proxySelectorTargets.Distinct(StringComparer.Ordinal).ToArray()
            });

        if (profile.IncludeGlobalGroup)
        {
            groups.Insert(
                1,
                new SubscriptionProxyGroup
                {
                    Name = "GLOBAL",
                    Type = "select",
                    Proxies = profile.IncludeRejectInGlobalGroup
                        ? ["Proxy", "DIRECT", "REJECT"]
                        : ["Proxy", "DIRECT"]
                });
        }

        return groups;
    }

    private static void AddCustomGroups(
        List<SubscriptionProxyGroup> groups,
        IReadOnlyList<SubscriptionRenderProxy> proxies,
        SubscriptionRequestContext request,
        ISet<string> existingNames,
        ICollection<string> proxySelectorTargets)
    {
        foreach (var definition in request.Settings.CustomGroups)
        {
            var proxyNames = new List<string>();
            if (definition.IncludeAllNodes)
            {
                proxyNames.AddRange(proxies.Select(static proxy => proxy.Name));
            }

            if (definition.MatchRegions.Count > 0)
            {
                proxyNames.AddRange(
                    proxies
                        .Where(proxy => definition.MatchRegions.Any(region =>
                            string.Equals(NormalizeRegion(region), proxy.Region, StringComparison.OrdinalIgnoreCase)))
                        .Select(static proxy => proxy.Name));
            }

            if (definition.MatchTags.Count > 0)
            {
                proxyNames.AddRange(
                    proxies
                        .Where(proxy => definition.MatchTags.Any(matchTag =>
                        {
                            var normalized = NormalizeTag(matchTag);
                            return proxy.Tags.Any(tag => string.Equals(tag, normalized, StringComparison.OrdinalIgnoreCase));
                        }))
                        .Select(static proxy => proxy.Name));
            }

            if (definition.MatchKeywords.Count > 0)
            {
                proxyNames.AddRange(
                    proxies
                        .Where(proxy => definition.MatchKeywords.Any(keyword => ProxyMatchesKeyword(proxy, keyword)))
                        .Select(static proxy => proxy.Name));
            }

            proxyNames.AddRange(
                definition.IncludeGroups
                    .Where(groupName => groups.Any(group => string.Equals(group.Name, groupName, StringComparison.OrdinalIgnoreCase))));

            var normalizedEntries = proxyNames
                .Where(static item => !string.IsNullOrWhiteSpace(item))
                .Distinct(StringComparer.Ordinal)
                .ToArray();
            if (normalizedEntries.Length == 0)
            {
                continue;
            }

            var groupName = EnsureUniqueGroupName(definition.Name, existingNames);
            groups.Add(
                new SubscriptionProxyGroup
                {
                    Name = groupName,
                    Type = definition.Type,
                    Proxies = normalizedEntries,
                    Url = string.IsNullOrWhiteSpace(definition.Url) ? request.Settings.TestUrl : definition.Url,
                    IntervalSeconds = definition.IntervalSeconds,
                    Strategy = definition.Strategy
                });

            if (definition.IncludeInProxySelector)
            {
                proxySelectorTargets.Add(groupName);
            }
        }
    }

    private static IReadOnlyList<string> BuildRules(
        IReadOnlyList<SubscriptionProxyGroup> groups,
        SubscriptionRequestContext request,
        string finalGroupName)
    {
        var groupNames = groups
            .Select(static group => group.Name)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var rules = new List<string>
        {
            "DOMAIN,localhost,DIRECT",
            "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
            "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
            "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve",
            "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
            "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
            "GEOIP,CN,DIRECT"
        };

        AppendIfGroupExists(rules, groupNames, "AI", new[]
        {
            "DOMAIN-SUFFIX,openai.com,AI",
            "DOMAIN-SUFFIX,chatgpt.com,AI",
            "DOMAIN-SUFFIX,oaistatic.com,AI",
            "DOMAIN-SUFFIX,oaiusercontent.com,AI",
            "DOMAIN-SUFFIX,anthropic.com,AI",
            "DOMAIN-SUFFIX,claude.ai,AI",
            "DOMAIN-SUFFIX,gemini.google.com,AI"
        });
        AppendIfGroupExists(rules, groupNames, "Telegram", new[]
        {
            "DOMAIN-SUFFIX,telegram.org,Telegram",
            "DOMAIN-SUFFIX,t.me,Telegram",
            "DOMAIN-SUFFIX,tdesktop.com,Telegram"
        });
        AppendIfGroupExists(rules, groupNames, "YouTube", new[]
        {
            "DOMAIN-SUFFIX,youtube.com,YouTube",
            "DOMAIN-SUFFIX,youtu.be,YouTube",
            "DOMAIN-SUFFIX,googlevideo.com,YouTube",
            "DOMAIN-SUFFIX,ytimg.com,YouTube"
        });
        AppendIfGroupExists(rules, groupNames, "Netflix", new[]
        {
            "DOMAIN-KEYWORD,netflix,Netflix",
            "DOMAIN-SUFFIX,nflxvideo.net,Netflix",
            "DOMAIN-SUFFIX,nflximg.net,Netflix"
        });
        AppendIfGroupExists(rules, groupNames, "Disney+", new[]
        {
            "DOMAIN-KEYWORD,disney,Disney+",
            "DOMAIN-SUFFIX,bamgrid.com,Disney+"
        });
        AppendIfGroupExists(rules, groupNames, "Spotify", new[]
        {
            "DOMAIN-SUFFIX,spotify.com,Spotify",
            "DOMAIN-SUFFIX,scdn.co,Spotify"
        });
        AppendIfGroupExists(rules, groupNames, "Google", new[]
        {
            "DOMAIN-SUFFIX,google.com,Google",
            "DOMAIN-SUFFIX,gstatic.com,Google",
            "DOMAIN-SUFFIX,googleapis.com,Google",
            "DOMAIN-SUFFIX,gvt1.com,Google"
        });
        AppendIfGroupExists(rules, groupNames, "Apple", new[]
        {
            "DOMAIN-SUFFIX,apple.com,Apple",
            "DOMAIN-SUFFIX,icloud.com,Apple",
            "DOMAIN-SUFFIX,cdn-apple.com,Apple"
        });
        AppendIfGroupExists(rules, groupNames, "Microsoft", new[]
        {
            "DOMAIN-SUFFIX,microsoft.com,Microsoft",
            "DOMAIN-SUFFIX,live.com,Microsoft",
            "DOMAIN-SUFFIX,office.com,Microsoft",
            "DOMAIN-SUFFIX,xboxlive.com,Microsoft"
        });
        AppendIfGroupExists(rules, groupNames, "流媒体", new[]
        {
            "DOMAIN-KEYWORD,netflix,流媒体",
            "DOMAIN-KEYWORD,disney,流媒体",
            "DOMAIN-KEYWORD,youtube,流媒体",
            "DOMAIN-KEYWORD,spotify,流媒体"
        });

        foreach (var customRule in request.Settings.CustomRules)
        {
            var normalized = NormalizeRuleLine(customRule, groupNames);
            if (!string.IsNullOrWhiteSpace(normalized))
            {
                rules.Add(normalized);
            }
        }

        rules.Add($"MATCH,{finalGroupName}");
        return rules;
    }

    private static void AppendIfGroupExists(
        List<string> rules,
        ISet<string> groupNames,
        string groupName,
        IEnumerable<string> candidates)
    {
        if (!groupNames.Contains(groupName))
        {
            return;
        }

        rules.AddRange(candidates);
    }

    private static string NormalizeRuleLine(string line, ISet<string> groupNames)
    {
        var trimmed = line.Trim();
        if (string.IsNullOrWhiteSpace(trimmed))
        {
            return string.Empty;
        }

        var parts = trimmed
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length < 2)
        {
            return string.Empty;
        }

        var target = parts[^1];
        if (string.Equals(target, "no-resolve", StringComparison.OrdinalIgnoreCase))
        {
            if (parts.Length < 3)
            {
                return string.Empty;
            }

            target = parts[^2];
        }

        var allowedTarget =
            groupNames.Contains(target) ||
            string.Equals(target, "DIRECT", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(target, "REJECT", StringComparison.OrdinalIgnoreCase);

        return allowedTarget ? string.Join(",", parts) : string.Empty;
    }

    private static SubscriptionProfileDefinition ResolveProfileDefinition(SubscriptionRequestContext request)
    {
        var includeReject = request.ProfileName != SubscriptionProfileNames.NoReject &&
                            request.Settings.EnableRejectInGlobalGroup;

        return request.ProfileName switch
        {
            SubscriptionProfileNames.Minimal => new SubscriptionProfileDefinition(
                IncludeAutoGroup: false,
                IncludeFallbackGroup: false,
                IncludeLoadBalanceGroup: false,
                IncludeRegionGroups: false,
                IncludeTagGroups: false,
                IncludeGlobalGroup: true,
                IncludeRejectInGlobalGroup: includeReject),
            SubscriptionProfileNames.Region => new SubscriptionProfileDefinition(
                IncludeAutoGroup: true,
                IncludeFallbackGroup: true,
                IncludeLoadBalanceGroup: true,
                IncludeRegionGroups: true,
                IncludeTagGroups: false,
                IncludeGlobalGroup: true,
                IncludeRejectInGlobalGroup: includeReject),
            _ => new SubscriptionProfileDefinition(
                IncludeAutoGroup: true,
                IncludeFallbackGroup: true,
                IncludeLoadBalanceGroup: true,
                IncludeRegionGroups: true,
                IncludeTagGroups: true,
                IncludeGlobalGroup: true,
                IncludeRejectInGlobalGroup: includeReject)
        };
    }

    private static string ResolveRegion(
        PanelNodeRecord? node,
        SubscriptionEndpoint endpoint,
        IReadOnlyList<string> tags)
    {
        var explicitRegion = NormalizeRegion(node?.SubscriptionRegion);
        if (!string.IsNullOrWhiteSpace(explicitRegion))
        {
            return explicitRegion;
        }

        var candidates = new[]
        {
            node?.DisplayName,
            endpoint.DisplayName,
            endpoint.Label,
            string.Join(",", tags)
        };

        foreach (var candidate in candidates)
        {
            var inferred = NormalizeRegion(candidate);
            if (!string.IsNullOrWhiteSpace(inferred))
            {
                return inferred;
            }
        }

        return string.Empty;
    }

    private static IReadOnlyList<string> ResolveTags(PanelNodeRecord? node)
    {
        if (node is null)
        {
            return Array.Empty<string>();
        }

        var tags = new List<string>();
        foreach (var tag in node.SubscriptionTags)
        {
            AddTag(tags, tag);
        }

        var inferred = $"{node.DisplayName},{node.SubscriptionRegion}";
        AddIfMatches(tags, inferred, "stream", "流媒体");
        AddIfMatches(tags, inferred, "media", "流媒体");
        AddIfMatches(tags, inferred, "unlock", "流媒体");
        AddIfMatches(tags, inferred, "ai", "AI");
        AddIfMatches(tags, inferred, "openai", "AI");
        AddIfMatches(tags, inferred, "chatgpt", "AI");
        AddIfMatches(tags, inferred, "claude", "AI");
        AddIfMatches(tags, inferred, "gemini", "AI");
        AddIfMatches(tags, inferred, "game", "游戏");
        AddIfMatches(tags, inferred, "gaming", "游戏");
        AddIfMatches(tags, inferred, "telegram", "Telegram");
        AddIfMatches(tags, inferred, "youtube", "YouTube");
        AddIfMatches(tags, inferred, "netflix", "Netflix");
        AddIfMatches(tags, inferred, "disney", "Disney+");
        AddIfMatches(tags, inferred, "spotify", "Spotify");
        AddIfMatches(tags, inferred, "google", "Google");
        AddIfMatches(tags, inferred, "apple", "Apple");
        AddIfMatches(tags, inferred, "microsoft", "Microsoft");

        return tags.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static void AddIfMatches(List<string> tags, string source, string token, string normalizedTag)
    {
        if (ContainsToken(source, token))
        {
            AddTag(tags, normalizedTag);
        }
    }

    private static void AddTag(List<string> tags, string? rawTag)
    {
        var normalized = NormalizeTag(rawTag);
        if (!string.IsNullOrWhiteSpace(normalized))
        {
            tags.Add(normalized);
        }
    }

    private static bool ProxyMatchesKeyword(SubscriptionRenderProxy proxy, string keyword)
    {
        if (string.IsNullOrWhiteSpace(keyword))
        {
            return false;
        }

        var source = string.Join(
            ' ',
            proxy.Name,
            proxy.Endpoint.DisplayName,
            proxy.Region,
            string.Join(' ', proxy.Tags));
        return source.Contains(keyword.Trim(), StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeTag(string? value)
    {
        var candidate = value?.Trim();
        if (string.IsNullOrWhiteSpace(candidate))
        {
            return string.Empty;
        }

        return TagAliases.TryGetValue(candidate, out var normalized)
            ? normalized
            : candidate;
    }

    private static string NormalizeRegion(string? value)
    {
        var candidate = value?.Trim();
        if (string.IsNullOrWhiteSpace(candidate))
        {
            return string.Empty;
        }

        if (RegionAliases.TryGetValue(candidate, out var alias))
        {
            return alias;
        }

        foreach (var pair in RegionAliases)
        {
            var matched = pair.Key.Length <= 2
                ? ContainsToken(candidate, pair.Key)
                : candidate.Contains(pair.Key, StringComparison.OrdinalIgnoreCase);
            if (matched)
            {
                return pair.Value;
            }
        }

        return candidate;
    }

    private static bool ContainsToken(string? source, string token)
    {
        if (string.IsNullOrWhiteSpace(source))
        {
            return false;
        }

        var normalized = source
            .Replace('-', ' ')
            .Replace('_', ' ')
            .Replace('/', ' ')
            .Replace('|', ' ')
            .Replace(':', ' ')
            .Replace('(', ' ')
            .Replace(')', ' ')
            .Replace('[', ' ')
            .Replace(']', ' ')
            .Replace('.', ' ')
            .Trim();

        return normalized
            .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Any(part => string.Equals(part, token, StringComparison.OrdinalIgnoreCase));
    }

    private static string EnsureUniqueGroupName(string preferredName, ISet<string> existingNames)
    {
        var normalized = preferredName.Trim();
        if (!existingNames.Contains(normalized))
        {
            existingNames.Add(normalized);
            return normalized;
        }

        var candidate = $"标签-{normalized}";
        var index = 2;
        while (!existingNames.Add(candidate))
        {
            candidate = $"标签-{normalized}-{index}";
            index++;
        }

        return candidate;
    }

    private static int GetRegionSortOrder(string region)
        => region switch
        {
            "香港" => 1,
            "台湾" => 2,
            "日本" => 3,
            "新加坡" => 4,
            "美国" => 5,
            "韩国" => 6,
            "英国" => 7,
            "德国" => 8,
            _ => 99
        };

    private static int GetTagSortOrder(string tag)
        => tag switch
        {
            "流媒体" => 1,
            "AI" => 2,
            "游戏" => 3,
            "Telegram" => 4,
            "YouTube" => 5,
            "Netflix" => 6,
            "Disney+" => 7,
            "Spotify" => 8,
            "Google" => 9,
            "Apple" => 10,
            "Microsoft" => 11,
            _ => 99
        };

    private static bool SupportsFormat(string format, string protocol)
        => format switch
        {
            SubscriptionFormats.Clash or SubscriptionFormats.Stash =>
                protocol is "trojan" or "vmess" or "vless" or "shadowsocks",
            SubscriptionFormats.Surge or SubscriptionFormats.QuantumultX =>
                protocol is "trojan" or "vmess" or "vless",
            _ => true
        };

    private static string NormalizeProtocol(string? protocol)
        => string.IsNullOrWhiteSpace(protocol)
            ? "trojan"
            : protocol.Trim().ToLowerInvariant();

    private static string ResolveFormat(string? flag, string? userAgent)
        => TryResolveFromValue(flag, out var format)
            ? format
            : TryResolveFromValue(userAgent, out format)
                ? format
                : SubscriptionFormats.General;

    private static bool TryResolveFromValue(string? value, out string format)
    {
        var normalized = NormalizeMarker(value);
        if (string.IsNullOrWhiteSpace(normalized))
        {
            format = string.Empty;
            return false;
        }

        if (normalized.Contains("shadowrocket", StringComparison.Ordinal))
        {
            format = SubscriptionFormats.Shadowrocket;
            return true;
        }

        if (normalized.Contains("quantumult", StringComparison.Ordinal))
        {
            format = SubscriptionFormats.QuantumultX;
            return true;
        }

        if (normalized.Contains("stash", StringComparison.Ordinal))
        {
            format = SubscriptionFormats.Stash;
            return true;
        }

        if (normalized.Contains("surge", StringComparison.Ordinal) ||
            normalized.Contains("surfboard", StringComparison.Ordinal))
        {
            format = SubscriptionFormats.Surge;
            return true;
        }

        if (normalized.Contains("clash", StringComparison.Ordinal) ||
            normalized.Contains("mihomo", StringComparison.Ordinal))
        {
            format = SubscriptionFormats.Clash;
            return true;
        }

        if (normalized.Contains("raw", StringComparison.Ordinal) ||
            normalized.Contains("trojan", StringComparison.Ordinal))
        {
            format = SubscriptionFormats.RawTrojan;
            return true;
        }

        if (normalized.Contains("general", StringComparison.Ordinal))
        {
            format = SubscriptionFormats.General;
            return true;
        }

        format = string.Empty;
        return false;
    }

    private static string NormalizeMarker(string? value)
    {
        try
        {
            return string.IsNullOrWhiteSpace(value)
                ? string.Empty
                : Uri.UnescapeDataString(value).Trim().ToLowerInvariant();
        }
        catch (UriFormatException)
        {
            return value?.Trim().ToLowerInvariant() ?? string.Empty;
        }
    }

    private sealed record SubscriptionProfileDefinition(
        bool IncludeAutoGroup,
        bool IncludeFallbackGroup,
        bool IncludeLoadBalanceGroup,
        bool IncludeRegionGroups,
        bool IncludeTagGroups,
        bool IncludeGlobalGroup,
        bool IncludeRejectInGlobalGroup);
}

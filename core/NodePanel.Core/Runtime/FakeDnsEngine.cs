using System.Numerics;
using System.Net;
using System.Net.Sockets;

namespace NodePanel.Core.Runtime;

public interface IFakeDnsEngine
{
    IReadOnlyList<IPAddress> GetFakeIPForDomain(string domain, bool ipv4, bool ipv6);

    string? GetDomainFromFakeDns(IPAddress ip);

    bool IsIPInPool(IPAddress ip);
}

public sealed record FakeDnsPoolRuntime
{
    public required string IpPool { get; init; }

    public int LruSize { get; init; } = FakeDnsDefaults.DefaultLruSize;
}

public static class FakeDnsDefaults
{
    public const string IPv4Pool = "198.18.0.0/15";
    public const string IPv6Pool = "fc00::/18";
    public const int DefaultLruSize = 65535;
    public const uint DefaultTtlSeconds = 1;
}

public sealed class FakeDnsEngine : IFakeDnsEngine
{
    private readonly FakeDnsPoolState[] _pools;

    public FakeDnsEngine(IEnumerable<FakeDnsPoolRuntime> pools)
    {
        ArgumentNullException.ThrowIfNull(pools);

        _pools = pools
            .Select(static pool => new FakeDnsPoolState(pool))
            .ToArray();
        if (_pools.Length == 0)
        {
            throw new ArgumentException("At least one fake DNS pool must be configured.", nameof(pools));
        }
    }

    public IReadOnlyList<IPAddress> GetFakeIPForDomain(string domain, bool ipv4, bool ipv6)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(domain);

        if (!ipv4 && !ipv6)
        {
            return Array.Empty<IPAddress>();
        }

        var normalizedDomain = domain.Trim();
        var addresses = new List<IPAddress>(_pools.Length);
        foreach (var pool in _pools)
        {
            if ((pool.Family == AddressFamily.InterNetwork && !ipv4) ||
                (pool.Family == AddressFamily.InterNetworkV6 && !ipv6))
            {
                continue;
            }

            addresses.Add(pool.GetOrAdd(normalizedDomain));
        }

        return addresses;
    }

    public string? GetDomainFromFakeDns(IPAddress ip)
    {
        ArgumentNullException.ThrowIfNull(ip);

        foreach (var pool in _pools)
        {
            var domain = pool.GetDomain(ip);
            if (!string.IsNullOrEmpty(domain))
            {
                return domain;
            }
        }

        return null;
    }

    public bool IsIPInPool(IPAddress ip)
    {
        ArgumentNullException.ThrowIfNull(ip);
        return _pools.Any(pool => pool.IsInPool(ip));
    }

    private sealed class FakeDnsPoolState
    {
        private readonly Dictionary<string, Entry> _entriesByDomain = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<IPAddress, string> _domainsByAddress = new();
        private readonly LinkedList<string> _lruOrder = new();
        private readonly object _sync = new();
        private readonly IPAddress _networkAddress;
        private readonly BigInteger _networkValue;
        private readonly BigInteger _upperExclusive;
        private readonly BigInteger _addressCount;
        private readonly int _addressByteCount;
        private readonly int _capacity;
        private BigInteger _nextOffset;

        public FakeDnsPoolState(FakeDnsPoolRuntime pool)
        {
            ArgumentNullException.ThrowIfNull(pool);
            if (string.IsNullOrWhiteSpace(pool.IpPool))
            {
                throw new ArgumentException("Fake DNS pool CIDR is required.", nameof(pool));
            }

            if (pool.LruSize <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(pool), "Fake DNS pool LRU size must be greater than zero.");
            }

            (_networkAddress, var prefixLength) = ParseCidr(pool.IpPool.Trim());
            Family = _networkAddress.AddressFamily;
            _addressByteCount = Family switch
            {
                AddressFamily.InterNetwork => 4,
                AddressFamily.InterNetworkV6 => 16,
                _ => throw new InvalidOperationException("Fake DNS pool only supports IPv4 and IPv6 CIDR ranges.")
            };

            var hostBits = (_addressByteCount * 8) - prefixLength;
            _addressCount = BigInteger.One << hostBits;
            if (new BigInteger(pool.LruSize) > _addressCount)
            {
                throw new InvalidOperationException("Fake DNS pool LRU size exceeds the available address space.");
            }

            _capacity = pool.LruSize;
            _networkValue = ToUnsignedBigInteger(_networkAddress);
            _upperExclusive = _networkValue + _addressCount;
            _nextOffset = SeedOffset(_addressCount);
        }

        public AddressFamily Family { get; }

        public IPAddress GetOrAdd(string domain)
        {
            lock (_sync)
            {
                if (_entriesByDomain.TryGetValue(domain, out var existing))
                {
                    Touch(existing.Node);
                    return existing.Address;
                }

                if (_entriesByDomain.Count >= _capacity)
                {
                    EvictOldest();
                }

                var address = AllocateAddress();
                var node = _lruOrder.AddFirst(domain);
                _entriesByDomain[domain] = new Entry(address, node);
                _domainsByAddress[NormalizeAddressKey(address)] = domain;
                return address;
            }
        }

        public string? GetDomain(IPAddress ip)
        {
            var normalized = NormalizeAddressKey(ip);
            if (!IsInPool(normalized))
            {
                return null;
            }

            lock (_sync)
            {
                return _domainsByAddress.TryGetValue(normalized, out var domain)
                    ? domain
                    : null;
            }
        }

        public bool IsInPool(IPAddress ip)
        {
            ArgumentNullException.ThrowIfNull(ip);

            var normalized = NormalizeAddressKey(ip);
            if (normalized.AddressFamily != Family)
            {
                return false;
            }

            var value = ToUnsignedBigInteger(normalized);
            return value >= _networkValue && value < _upperExclusive;
        }

        private void Touch(LinkedListNode<string> node)
        {
            if (ReferenceEquals(_lruOrder.First, node))
            {
                return;
            }

            _lruOrder.Remove(node);
            _lruOrder.AddFirst(node);
        }

        private void EvictOldest()
        {
            var last = _lruOrder.Last
                ?? throw new InvalidOperationException("Fake DNS pool eviction failed because the LRU list is empty.");
            _lruOrder.RemoveLast();

            if (_entriesByDomain.Remove(last.Value, out var removed))
            {
                _domainsByAddress.Remove(NormalizeAddressKey(removed.Address));
            }
        }

        private IPAddress AllocateAddress()
        {
            for (var attempts = 0; attempts <= _capacity; attempts++)
            {
                var candidate = CreateAddress(_nextOffset);
                _nextOffset = AdvanceOffset(_nextOffset);
                if (!_domainsByAddress.ContainsKey(NormalizeAddressKey(candidate)))
                {
                    return candidate;
                }
            }

            throw new InvalidOperationException("Fake DNS pool is exhausted.");
        }

        private BigInteger AdvanceOffset(BigInteger current)
        {
            var next = current + BigInteger.One;
            return next < _addressCount ? next : BigInteger.Zero;
        }

        private IPAddress CreateAddress(BigInteger offset)
        {
            var value = _networkValue + offset;
            var bytes = value.ToByteArray(isUnsigned: true, isBigEndian: true);
            if (bytes.Length > _addressByteCount)
            {
                throw new InvalidOperationException("Fake DNS address overflowed the configured address family.");
            }

            if (bytes.Length < _addressByteCount)
            {
                var padded = new byte[_addressByteCount];
                bytes.AsSpan().CopyTo(padded.AsSpan(_addressByteCount - bytes.Length));
                bytes = padded;
            }

            return new IPAddress(bytes);
        }

        private static BigInteger SeedOffset(BigInteger addressCount)
        {
            var seed = new BigInteger(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
            return addressCount > BigInteger.Zero
                ? seed % addressCount
                : BigInteger.Zero;
        }

        private static IPAddress NormalizeAddressKey(IPAddress address)
            => new(address.GetAddressBytes());

        private static BigInteger ToUnsignedBigInteger(IPAddress address)
            => new(address.GetAddressBytes(), isUnsigned: true, isBigEndian: true);

        private static (IPAddress NetworkAddress, int PrefixLength) ParseCidr(string cidr)
        {
            var separatorIndex = cidr.IndexOf('/');
            if (separatorIndex <= 0 || separatorIndex == cidr.Length - 1)
            {
                throw new ArgumentException("Fake DNS pool must be a valid CIDR value.", nameof(cidr));
            }

            var addressPart = cidr[..separatorIndex];
            var prefixPart = cidr[(separatorIndex + 1)..];
            if (!IPAddress.TryParse(addressPart, out var address) ||
                address is null)
            {
                throw new ArgumentException("Fake DNS pool contains an invalid IP address.", nameof(cidr));
            }

            var maxPrefixLength = address.GetAddressBytes().Length * 8;
            if (!int.TryParse(prefixPart, out var prefixLength) ||
                prefixLength < 0 ||
                prefixLength > maxPrefixLength)
            {
                throw new ArgumentException("Fake DNS pool contains an invalid prefix length.", nameof(cidr));
            }

            var networkBytes = address.GetAddressBytes();
            ZeroHostBits(networkBytes.AsSpan(), prefixLength);
            return (new IPAddress(networkBytes), prefixLength);
        }

        private static void ZeroHostBits(Span<byte> bytes, int prefixLength)
        {
            var fullBytes = prefixLength / 8;
            var remainingBits = prefixLength % 8;

            if (fullBytes >= bytes.Length)
            {
                return;
            }

            if (remainingBits > 0)
            {
                var mask = (byte)(0xFF << (8 - remainingBits));
                bytes[fullBytes] &= mask;
                fullBytes++;
            }

            bytes[fullBytes..].Clear();
        }

        private sealed record Entry(IPAddress Address, LinkedListNode<string> Node);
    }
}

internal sealed class RuntimeFakeDnsEngine : IFakeDnsEngine
{
    private readonly IDnsRuntimeSettingsProvider _settingsProvider;
    private readonly object _sync = new();
    private FakeDnsEngine? _engine;
    private string? _signature;

    public RuntimeFakeDnsEngine(IDnsRuntimeSettingsProvider settingsProvider)
    {
        _settingsProvider = settingsProvider ?? throw new ArgumentNullException(nameof(settingsProvider));
    }

    public IReadOnlyList<IPAddress> GetFakeIPForDomain(string domain, bool ipv4, bool ipv6)
        => GetCurrentEngine()?.GetFakeIPForDomain(domain, ipv4, ipv6) ?? Array.Empty<IPAddress>();

    public string? GetDomainFromFakeDns(IPAddress ip)
        => GetCurrentEngine()?.GetDomainFromFakeDns(ip);

    public bool IsIPInPool(IPAddress ip)
        => GetCurrentEngine()?.IsIPInPool(ip) ?? false;

    private FakeDnsEngine? GetCurrentEngine()
    {
        var settings = _settingsProvider.GetCurrentDnsSettings();
        var signature = CreateSignature(settings.FakeDnsPools);

        lock (_sync)
        {
            if (string.Equals(_signature, signature, StringComparison.Ordinal))
            {
                return _engine;
            }

            _engine = settings.FakeDnsPools.Count == 0
                ? null
                : new FakeDnsEngine(settings.FakeDnsPools);
            _signature = signature;
            return _engine;
        }
    }

    private static string CreateSignature(IReadOnlyList<FakeDnsPoolRuntime> pools)
    {
        if (pools.Count == 0)
        {
            return string.Empty;
        }

        return string.Join(
            "|",
            pools.Select(static pool => $"{pool.IpPool.Trim().ToLowerInvariant()}#{pool.LruSize}"));
    }
}

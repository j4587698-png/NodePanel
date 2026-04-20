using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace NodePanel.Core.Runtime;

internal static class DnsOutboundProtocolCodec
{
    public const ushort TypeA = 1;
    public const ushort TypeAAAA = 28;
    public const ushort ClassInternet = 1;

    private const ushort FlagResponse = 0x8000;
    private const ushort FlagAuthoritativeAnswer = 0x0400;
    private const ushort FlagRecursionDesired = 0x0100;
    private const ushort FlagRecursionAvailable = 0x0080;
    private const ushort PointerToQuestionName = 0xC00C;

    public static bool TryParseQuery(ReadOnlySpan<byte> message, out DnsOutboundQuery query)
    {
        if (message.Length < 12)
        {
            query = default;
            return false;
        }

        var questionCount = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(4, 2));
        if (questionCount == 0)
        {
            query = default;
            return false;
        }

        const int questionStart = 12;
        var offset = questionStart;
        if (!TryReadDomain(message, ref offset, out var domain) ||
            offset + 4 > message.Length)
        {
            query = default;
            return false;
        }

        var type = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(offset, 2));
        var dnsClass = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(offset + 2, 2));
        offset += 4;

        query = new DnsOutboundQuery
        {
            Id = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(0, 2)),
            Flags = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(2, 2)),
            Domain = domain,
            Type = type,
            Class = dnsClass,
            QuestionBytes = message.Slice(questionStart, offset - questionStart).ToArray()
        };
        return true;
    }

    public static byte[] BuildResponse(
        DnsOutboundQuery query,
        IReadOnlyList<IPAddress> addresses,
        byte rCode = 0,
        uint ttl = 60)
    {
        ArgumentNullException.ThrowIfNull(addresses);

        using var buffer = new MemoryStream(512);
        WriteHeader(buffer, query, checked((ushort)addresses.Count), rCode);
        buffer.Write(query.QuestionBytes);

        for (var index = 0; index < addresses.Count; index++)
        {
            WriteAnswer(buffer, query.Type, addresses[index], ttl);
        }

        return buffer.ToArray();
    }

    public static byte[] BuildRefusedResponse(DnsOutboundQuery query)
        => BuildResponse(query, Array.Empty<IPAddress>(), DnsResponseCodes.Refused, ttl: 0);

    public static byte[] BuildErrorResponse(DnsOutboundQuery query, byte rCode)
        => BuildResponse(query, Array.Empty<IPAddress>(), rCode, ttl: 0);

    public static byte[] FrameTcpMessage(ReadOnlySpan<byte> payload)
    {
        var framed = new byte[payload.Length + 2];
        BinaryPrimitives.WriteUInt16BigEndian(framed.AsSpan(0, 2), checked((ushort)payload.Length));
        payload.CopyTo(framed.AsSpan(2));
        return framed;
    }

    public static bool TryParseResponse(ReadOnlySpan<byte> message, out DnsOutboundResponseMessage response)
    {
        if (message.Length < 12)
        {
            response = default;
            return false;
        }

        var questionCount = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(4, 2));
        var answerCount = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(6, 2));
        var offset = 12;
        string domain = string.Empty;
        ushort questionType = 0;

        if (questionCount > 0)
        {
            if (!TryReadDomain(message, ref offset, out domain) ||
                offset + 4 > message.Length)
            {
                response = default;
                return false;
            }

            questionType = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(offset, 2));
            offset += 4;
        }

        var addresses = new List<IPAddress>(answerCount);
        var answerTtls = new List<uint>(answerCount);
        for (var index = 0; index < answerCount; index++)
        {
            if (!TryReadDomain(message, ref offset, out _) ||
                offset + 10 > message.Length)
            {
                response = default;
                return false;
            }

            var answerType = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(offset, 2));
            offset += 2;

            offset += 2;
            var answerTtl = BinaryPrimitives.ReadUInt32BigEndian(message.Slice(offset, 4));
            offset += 4;

            var dataLength = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(offset, 2));
            offset += 2;
            if (offset + dataLength > message.Length)
            {
                response = default;
                return false;
            }

            if (answerType == TypeA && dataLength == 4)
            {
                addresses.Add(new IPAddress(message.Slice(offset, dataLength)));
                answerTtls.Add(answerTtl);
            }
            else if (answerType == TypeAAAA && dataLength == 16)
            {
                addresses.Add(new IPAddress(message.Slice(offset, dataLength)));
                answerTtls.Add(answerTtl);
            }

            offset += dataLength;
        }

        response = new DnsOutboundResponseMessage
        {
            Id = BinaryPrimitives.ReadUInt16BigEndian(message.Slice(0, 2)),
            ResponseCode = (byte)(BinaryPrimitives.ReadUInt16BigEndian(message.Slice(2, 2)) & 0x000F),
            Domain = domain,
            Type = questionType,
            Addresses = addresses.ToArray(),
            AnswerTtls = answerTtls.ToArray()
        };
        return true;
    }

    private static void WriteHeader(
        Stream buffer,
        DnsOutboundQuery query,
        ushort answerCount,
        byte rCode)
    {
        Span<byte> header = stackalloc byte[12];
        BinaryPrimitives.WriteUInt16BigEndian(header.Slice(0, 2), query.Id);

        var flags = (ushort)(
            FlagResponse |
            FlagAuthoritativeAnswer |
            FlagRecursionAvailable |
            (query.Flags & FlagRecursionDesired) |
            rCode);
        BinaryPrimitives.WriteUInt16BigEndian(header.Slice(2, 2), flags);
        BinaryPrimitives.WriteUInt16BigEndian(header.Slice(4, 2), 1);
        BinaryPrimitives.WriteUInt16BigEndian(header.Slice(6, 2), answerCount);
        BinaryPrimitives.WriteUInt16BigEndian(header.Slice(8, 2), 0);
        BinaryPrimitives.WriteUInt16BigEndian(header.Slice(10, 2), 0);
        buffer.Write(header);
    }

    private static void WriteAnswer(
        Stream buffer,
        ushort questionType,
        IPAddress address,
        uint ttl)
    {
        var normalized = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
        var addressBytes = normalized.GetAddressBytes();
        var resourceType = questionType == TypeAAAA ? TypeAAAA : TypeA;

        Span<byte> resourceHeader = stackalloc byte[12];
        BinaryPrimitives.WriteUInt16BigEndian(resourceHeader.Slice(0, 2), PointerToQuestionName);
        BinaryPrimitives.WriteUInt16BigEndian(resourceHeader.Slice(2, 2), resourceType);
        BinaryPrimitives.WriteUInt16BigEndian(resourceHeader.Slice(4, 2), ClassInternet);
        BinaryPrimitives.WriteUInt32BigEndian(resourceHeader.Slice(6, 4), ttl);
        BinaryPrimitives.WriteUInt16BigEndian(resourceHeader.Slice(10, 2), checked((ushort)addressBytes.Length));
        buffer.Write(resourceHeader);
        buffer.Write(addressBytes);
    }

    private static bool TryReadDomain(
        ReadOnlySpan<byte> message,
        ref int offset,
        out string domain)
    {
        var labels = new List<string>(4);
        var position = offset;
        var jumped = false;
        var jumpCount = 0;

        while (position < message.Length)
        {
            var length = message[position++];
            if (length == 0)
            {
                if (!jumped)
                {
                    offset = position;
                }

                domain = labels.Count == 0
                    ? string.Empty
                    : string.Join('.', labels);
                return true;
            }

            if ((length & 0xC0) == 0xC0)
            {
                if (position >= message.Length || jumpCount++ > 16)
                {
                    break;
                }

                var pointer = ((length & 0x3F) << 8) | message[position++];
                if (pointer >= message.Length)
                {
                    break;
                }

                if (!jumped)
                {
                    offset = position;
                    jumped = true;
                }

                position = pointer;
                continue;
            }

            if ((length & 0xC0) != 0 ||
                position + length > message.Length)
            {
                break;
            }

            labels.Add(Encoding.ASCII.GetString(message.Slice(position, length)));
            position += length;
        }

        domain = string.Empty;
        return false;
    }
}

internal readonly record struct DnsOutboundQuery
{
    public required ushort Id { get; init; }

    public required ushort Flags { get; init; }

    public required string Domain { get; init; }

    public required ushort Type { get; init; }

    public required ushort Class { get; init; }

    public required byte[] QuestionBytes { get; init; }

    public bool IsIpQuery => Type is DnsOutboundProtocolCodec.TypeA or DnsOutboundProtocolCodec.TypeAAAA;
}

internal readonly record struct DnsOutboundResponseMessage
{
    public required ushort Id { get; init; }

    public required byte ResponseCode { get; init; }

    public required string Domain { get; init; }

    public required ushort Type { get; init; }

    public required IReadOnlyList<IPAddress> Addresses { get; init; }

    public required IReadOnlyList<uint> AnswerTtls { get; init; }
}

internal static class DnsResponseCodes
{
    public const byte Success = 0;
    public const byte ServerFailure = 2;
    public const byte NameError = 3;
    public const byte Refused = 5;
}

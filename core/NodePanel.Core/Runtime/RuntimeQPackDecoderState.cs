using System.Globalization;
using System.Text;

namespace NodePanel.Core.Runtime;

internal sealed class RuntimeQPackDecoderState
{
    private const long SettingsQPackMaxTableCapacity = 0x01;
    private const long SettingsQPackBlockedStreams = 0x07;
    private const int DefaultMaxTableCapacity = 4096;
    private const int DefaultBlockedStreams = 16;

    private static readonly QPackHeaderField[] StaticTable =
    [
        new(":authority", string.Empty),
        new(":path", "/"),
        new("age", "0"),
        new("content-disposition", string.Empty),
        new("content-length", "0"),
        new("cookie", string.Empty),
        new("date", string.Empty),
        new("etag", string.Empty),
        new("if-modified-since", string.Empty),
        new("if-none-match", string.Empty),
        new("last-modified", string.Empty),
        new("link", string.Empty),
        new("location", string.Empty),
        new("referer", string.Empty),
        new("set-cookie", string.Empty),
        new(":method", "CONNECT"),
        new(":method", "DELETE"),
        new(":method", "GET"),
        new(":method", "HEAD"),
        new(":method", "OPTIONS"),
        new(":method", "POST"),
        new(":method", "PUT"),
        new(":scheme", "http"),
        new(":scheme", "https"),
        new(":status", "103"),
        new(":status", "200"),
        new(":status", "304"),
        new(":status", "404"),
        new(":status", "503"),
        new("accept", "*/*"),
        new("accept", "application/dns-message"),
        new("accept-encoding", "gzip, deflate, br"),
        new("accept-ranges", "bytes"),
        new("access-control-allow-headers", "cache-control"),
        new("access-control-allow-headers", "content-type"),
        new("access-control-allow-origin", "*"),
        new("cache-control", "max-age=0"),
        new("cache-control", "max-age=2592000"),
        new("cache-control", "max-age=604800"),
        new("cache-control", "no-cache"),
        new("cache-control", "no-store"),
        new("cache-control", "public, max-age=31536000"),
        new("content-encoding", "br"),
        new("content-encoding", "gzip"),
        new("content-type", "application/dns-message"),
        new("content-type", "application/javascript"),
        new("content-type", "application/json"),
        new("content-type", "application/x-www-form-urlencoded"),
        new("content-type", "image/gif"),
        new("content-type", "image/jpeg"),
        new("content-type", "image/png"),
        new("content-type", "text/css"),
        new("content-type", "text/html; charset=utf-8"),
        new("content-type", "text/plain"),
        new("content-type", "text/plain;charset=utf-8"),
        new("range", "bytes=0-"),
        new("strict-transport-security", "max-age=31536000"),
        new("strict-transport-security", "max-age=31536000; includesubdomains"),
        new("strict-transport-security", "max-age=31536000; includesubdomains; preload"),
        new("vary", "accept-encoding"),
        new("vary", "origin"),
        new("x-content-type-options", "nosniff"),
        new("x-xss-protection", "1; mode=block"),
        new(":status", "100"),
        new(":status", "204"),
        new(":status", "206"),
        new(":status", "302"),
        new(":status", "400"),
        new(":status", "403"),
        new(":status", "421"),
        new(":status", "425"),
        new(":status", "500"),
        new("accept-language", string.Empty),
        new("access-control-allow-credentials", "FALSE"),
        new("access-control-allow-credentials", "TRUE"),
        new("access-control-allow-headers", "*"),
        new("access-control-allow-methods", "get"),
        new("access-control-allow-methods", "get, post, options"),
        new("access-control-allow-methods", "options"),
        new("access-control-expose-headers", "content-length"),
        new("access-control-request-headers", "content-type"),
        new("access-control-request-method", "get"),
        new("access-control-request-method", "post"),
        new("alt-svc", "clear"),
        new("authorization", string.Empty),
        new("content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"),
        new("early-data", "1"),
        new("expect-ct", string.Empty),
        new("forwarded", string.Empty),
        new("if-range", string.Empty),
        new("origin", string.Empty),
        new("purpose", "prefetch"),
        new("server", string.Empty),
        new("timing-allow-origin", "*"),
        new("upgrade-insecure-requests", "1"),
        new("user-agent", string.Empty),
        new("x-forwarded-for", string.Empty),
        new("x-frame-options", "deny"),
        new("x-frame-options", "sameorigin")
    ];

    private readonly object _stateLock = new();
    private readonly List<QPackDynamicEntry> _dynamicEntries = [];
    private readonly Dictionary<long, QPackDynamicEntry> _dynamicEntriesByAbsoluteIndex = [];
    private int _currentTableCapacity;
    private int _currentTableSize;
    private long _insertCount;
    private TaskCompletionSource<object?> _insertCountChanged = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public static byte[] BuildSettingsPayload()
    {
        var buffer = new MemoryStream(16);
        WriteVariableLengthInteger(buffer, SettingsQPackMaxTableCapacity);
        WriteVariableLengthInteger(buffer, DefaultMaxTableCapacity);
        WriteVariableLengthInteger(buffer, SettingsQPackBlockedStreams);
        WriteVariableLengthInteger(buffer, DefaultBlockedStreams);
        return buffer.ToArray();
    }

    public void Complete(Exception? exception = null)
    {
        TaskCompletionSource<object?>? pending;
        lock (_stateLock)
        {
            pending = _insertCountChanged;
            _insertCountChanged = new(TaskCreationOptions.RunContinuationsAsynchronously);
        }

        if (exception is null)
        {
            pending.TrySetCanceled();
            return;
        }

        pending.TrySetException(exception);
    }

    public async Task ProcessEncoderStreamAsync(
        Stream stream,
        Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask> decoderInstructionWriter,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(decoderInstructionWriter);

        while (true)
        {
            var firstByte = await ReadOptionalByteAsync(stream, cancellationToken).ConfigureAwait(false);
            if (!firstByte.HasValue)
            {
                return;
            }

            var insertCountIncrement = 0;
            if ((firstByte.Value & 0x80) != 0)
            {
                var isStatic = (firstByte.Value & 0x40) != 0;
                var nameIndex = await ReadPrefixedIntegerAsync(stream, firstByte.Value, 6, cancellationToken)
                    .ConfigureAwait(false);
                var name = isStatic
                    ? ResolveStaticHeaderName(nameIndex)
                    : ResolveEncoderDynamicHeader(nameIndex).Name;
                var value = await ReadQPackStringAsync(stream, 7, 0x80, cancellationToken).ConfigureAwait(false);
                InsertDynamicEntry(name, value);
                insertCountIncrement = 1;
            }
            else if ((firstByte.Value & 0x40) != 0)
            {
                var name = await ReadQPackStringAsync(stream, firstByte.Value, 5, 0x20, cancellationToken)
                    .ConfigureAwait(false);
                var value = await ReadQPackStringAsync(stream, 7, 0x80, cancellationToken).ConfigureAwait(false);
                InsertDynamicEntry(name, value);
                insertCountIncrement = 1;
            }
            else if ((firstByte.Value & 0x20) != 0)
            {
                var capacity = await ReadPrefixedIntegerAsync(stream, firstByte.Value, 5, cancellationToken)
                    .ConfigureAwait(false);
                SetDynamicTableCapacity(capacity);
            }
            else
            {
                var index = await ReadPrefixedIntegerAsync(stream, firstByte.Value, 5, cancellationToken)
                    .ConfigureAwait(false);
                DuplicateDynamicEntry(index);
                insertCountIncrement = 1;
            }

            if (insertCountIncrement > 0)
            {
                await decoderInstructionWriter(
                        BuildInsertCountIncrementInstruction(insertCountIncrement),
                        cancellationToken)
                    .ConfigureAwait(false);
            }
        }
    }

    public async ValueTask<int> DecodeStatusCodeAsync(
        ReadOnlyMemory<byte> headerBlock,
        long streamId,
        Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask> decoderInstructionWriter,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(decoderInstructionWriter);

        var prefix = ParseDynamicHeaderBlockPrefix(headerBlock.Span);
        var requiresAcknowledgement = prefix.RequiredInsertCount > 0;

        try
        {
            if (requiresAcknowledgement)
            {
                await WaitForInsertCountAsync(prefix.RequiredInsertCount, cancellationToken).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
            }

            if (!TryReadIntegerHeaderValue(headerBlock.Span, prefix, this, ":status", out var statusCode))
            {
                throw new InvalidDataException("SplitHTTP HTTP/3 response headers did not include a valid :status pseudo-header.");
            }

            if (requiresAcknowledgement)
            {
                cancellationToken.ThrowIfCancellationRequested();
                await decoderInstructionWriter(
                        BuildSectionAcknowledgementInstruction(streamId),
                        CancellationToken.None)
                    .ConfigureAwait(false);
            }

            return statusCode;
        }
        catch (OperationCanceledException) when (requiresAcknowledgement)
        {
            await TryWriteStreamCancellationAsync(streamId, decoderInstructionWriter).ConfigureAwait(false);
            throw;
        }
    }

    public static int DecodeStatusCode(ReadOnlyMemory<byte> headerBlock)
    {
        var prefix = ParseStaticHeaderBlockPrefix(headerBlock.Span);
        if (!TryReadIntegerHeaderValue(headerBlock.Span, prefix, state: null, ":status", out var statusCode))
        {
            throw new InvalidDataException("SplitHTTP HTTP/3 response headers did not include a valid :status pseudo-header.");
        }

        return statusCode;
    }

    public async ValueTask<IReadOnlyDictionary<string, string>> DecodeHeadersAsync(
        ReadOnlyMemory<byte> headerBlock,
        long streamId,
        Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask> decoderInstructionWriter,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(decoderInstructionWriter);

        var prefix = ParseDynamicHeaderBlockPrefix(headerBlock.Span);
        var requiresAcknowledgement = prefix.RequiredInsertCount > 0;

        try
        {
            if (requiresAcknowledgement)
            {
                await WaitForInsertCountAsync(prefix.RequiredInsertCount, cancellationToken).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
            }

            var headers = DecodeHeadersCore(headerBlock.Span, prefix, this);
            if (requiresAcknowledgement)
            {
                cancellationToken.ThrowIfCancellationRequested();
                await decoderInstructionWriter(
                        BuildSectionAcknowledgementInstruction(streamId),
                        CancellationToken.None)
                    .ConfigureAwait(false);
            }

            return headers;
        }
        catch (OperationCanceledException) when (requiresAcknowledgement)
        {
            await TryWriteStreamCancellationAsync(streamId, decoderInstructionWriter).ConfigureAwait(false);
            throw;
        }
    }

    public static IReadOnlyDictionary<string, string> DecodeHeaders(ReadOnlyMemory<byte> headerBlock)
    {
        var prefix = ParseStaticHeaderBlockPrefix(headerBlock.Span);
        return DecodeHeadersCore(headerBlock.Span, prefix, state: null);
    }

    private void SetDynamicTableCapacity(int capacity)
    {
        if (capacity < 0 || capacity > DefaultMaxTableCapacity)
        {
            throw new InvalidDataException("QPACK encoder stream announced an invalid dynamic table capacity.");
        }

        lock (_stateLock)
        {
            _currentTableCapacity = capacity;
            while (_currentTableSize > _currentTableCapacity)
            {
                EvictOldestEntryNoLock();
            }
        }
    }

    private void InsertDynamicEntry(string name, string value)
    {
        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(value);

        lock (_stateLock)
        {
            InsertDynamicEntryNoLock(name, value);
            NotifyInsertCountChangedNoLock();
        }
    }

    private void DuplicateDynamicEntry(int index)
    {
        lock (_stateLock)
        {
            if (index < 0 || index >= _dynamicEntries.Count)
            {
                throw new InvalidDataException("QPACK duplicate instruction referenced an invalid dynamic table entry.");
            }

            var entry = _dynamicEntries[_dynamicEntries.Count - 1 - index];
            InsertDynamicEntryNoLock(entry.Name, entry.Value);
            NotifyInsertCountChangedNoLock();
        }
    }

    private void InsertDynamicEntryNoLock(string name, string value)
    {
        var entrySize = 32 + Encoding.UTF8.GetByteCount(name) + Encoding.UTF8.GetByteCount(value);
        if (entrySize > _currentTableCapacity)
        {
            throw new InvalidDataException("QPACK dynamic table entry exceeded the negotiated table capacity.");
        }

        while (_currentTableSize + entrySize > _currentTableCapacity)
        {
            EvictOldestEntryNoLock();
        }

        var entry = new QPackDynamicEntry(_insertCount, name, value, entrySize);
        _insertCount++;
        _dynamicEntries.Add(entry);
        _dynamicEntriesByAbsoluteIndex[entry.AbsoluteIndex] = entry;
        _currentTableSize += entrySize;
    }

    private void EvictOldestEntryNoLock()
    {
        if (_dynamicEntries.Count == 0)
        {
            throw new InvalidDataException("QPACK dynamic table eviction underflow.");
        }

        var entry = _dynamicEntries[0];
        _dynamicEntries.RemoveAt(0);
        _dynamicEntriesByAbsoluteIndex.Remove(entry.AbsoluteIndex);
        _currentTableSize -= entry.Size;
    }

    private void NotifyInsertCountChangedNoLock()
    {
        var completed = _insertCountChanged;
        _insertCountChanged = new(TaskCreationOptions.RunContinuationsAsynchronously);
        completed.TrySetResult(null);
    }

    private async ValueTask WaitForInsertCountAsync(long requiredInsertCount, CancellationToken cancellationToken)
    {
        while (true)
        {
            Task waitTask;
            lock (_stateLock)
            {
                if (_insertCount >= requiredInsertCount)
                {
                    return;
                }

                waitTask = _insertCountChanged.Task;
            }

            await waitTask.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    private HeaderBlockPrefix ParseDynamicHeaderBlockPrefix(ReadOnlySpan<byte> headerBlock)
    {
        var offset = 0;
        var encodedRequiredInsertCount = ReadPrefixedInteger(headerBlock, ref offset, 8);
        var requiredInsertCount = DecodeRequiredInsertCount(encodedRequiredInsertCount);
        if (offset >= headerBlock.Length)
        {
            throw new InvalidDataException("QPACK header block prefix exceeded the available header block bytes.");
        }

        var deltaBaseNegative = (headerBlock[offset] & 0x80) != 0;
        var deltaBase = ReadPrefixedInteger(headerBlock, ref offset, 7);
        var baseValue = deltaBaseNegative
            ? requiredInsertCount - deltaBase - 1
            : requiredInsertCount + deltaBase;
        if (baseValue < 0)
        {
            throw new InvalidDataException("QPACK header block prefix encoded an invalid base value.");
        }

        return new HeaderBlockPrefix(requiredInsertCount, baseValue, offset);
    }

    private long DecodeRequiredInsertCount(int encodedRequiredInsertCount)
    {
        if (encodedRequiredInsertCount == 0)
        {
            return 0;
        }

        var maxEntries = DefaultMaxTableCapacity / 32;
        if (maxEntries <= 0)
        {
            throw new InvalidDataException("QPACK header block required dynamic table support, but the table capacity is zero.");
        }

        var fullRange = 2L * maxEntries;
        if (encodedRequiredInsertCount > fullRange)
        {
            throw new InvalidDataException("QPACK header block encoded an invalid required insert count.");
        }

        long insertCountSnapshot;
        lock (_stateLock)
        {
            insertCountSnapshot = _insertCount;
        }

        var maxValue = insertCountSnapshot + maxEntries;
        var maxWrapped = (maxValue / fullRange) * fullRange;
        var requiredInsertCount = maxWrapped + encodedRequiredInsertCount - 1L;
        if (requiredInsertCount > maxValue)
        {
            if (requiredInsertCount <= fullRange)
            {
                throw new InvalidDataException("QPACK header block encoded a wrapped required insert count that cannot be resolved.");
            }

            requiredInsertCount -= fullRange;
        }

        return requiredInsertCount;
    }

    private static HeaderBlockPrefix ParseStaticHeaderBlockPrefix(ReadOnlySpan<byte> headerBlock)
    {
        var offset = 0;
        var encodedRequiredInsertCount = ReadPrefixedInteger(headerBlock, ref offset, 8);
        if (encodedRequiredInsertCount != 0)
        {
            throw new NotSupportedException("SplitHTTP HTTP/3 static header decoding does not support QPACK dynamic table references.");
        }

        if (offset >= headerBlock.Length)
        {
            throw new InvalidDataException("QPACK header block prefix exceeded the available header block bytes.");
        }

        var deltaBaseNegative = (headerBlock[offset] & 0x80) != 0;
        var deltaBase = ReadPrefixedInteger(headerBlock, ref offset, 7);
        if (deltaBaseNegative || deltaBase != 0)
        {
            throw new NotSupportedException("SplitHTTP HTTP/3 static header decoding only supports a zero QPACK base.");
        }

        return new HeaderBlockPrefix(0, 0, offset);
    }

    private static bool TryReadIntegerHeaderValue(
        ReadOnlySpan<byte> headerBlock,
        HeaderBlockPrefix prefix,
        RuntimeQPackDecoderState? state,
        string headerName,
        out int headerValue)
    {
        headerValue = 0;
        var offset = prefix.PayloadOffset;

        while (offset < headerBlock.Length)
        {
            var first = headerBlock[offset];
            if ((first & 0x80) != 0)
            {
                var isStatic = (first & 0x40) != 0;
                var index = ReadPrefixedInteger(headerBlock, ref offset, 6);
                var indexedHeader = isStatic
                    ? ResolveStaticHeader(index)
                    : state?.ResolveDynamicHeader(prefix.Base, index, postBase: false)
                      ?? throw new NotSupportedException("SplitHTTP HTTP/3 static header decoding does not support QPACK dynamic table references.");
                if (string.Equals(indexedHeader.Name, headerName, StringComparison.Ordinal) &&
                    int.TryParse(indexedHeader.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out headerValue))
                {
                    return true;
                }

                continue;
            }

            if ((first & 0x40) != 0)
            {
                var isStatic = (first & 0x10) != 0;
                var nameIndex = ReadPrefixedInteger(headerBlock, ref offset, 4);
                var literalHeaderName = isStatic
                    ? ResolveStaticHeaderName(nameIndex)
                    : state?.ResolveDynamicHeaderName(prefix.Base, nameIndex, postBase: false)
                      ?? throw new NotSupportedException("SplitHTTP HTTP/3 static header decoding does not support QPACK dynamic table references.");
                var literalHeaderValue = ReadStringLiteral(
                    headerBlock,
                    ref offset,
                    decode: string.Equals(literalHeaderName, headerName, StringComparison.Ordinal));
                if (string.Equals(literalHeaderName, headerName, StringComparison.Ordinal) &&
                    !string.IsNullOrWhiteSpace(literalHeaderValue) &&
                    int.TryParse(literalHeaderValue, NumberStyles.Integer, CultureInfo.InvariantCulture, out headerValue))
                {
                    return true;
                }

                continue;
            }

            if ((first & 0x20) != 0)
            {
                var literalHeaderName = ReadLiteralHeaderName(headerBlock, ref offset);
                var literalHeaderValue = ReadStringLiteral(
                    headerBlock,
                    ref offset,
                    decode: string.Equals(literalHeaderName, headerName, StringComparison.Ordinal));
                if (string.Equals(literalHeaderName, headerName, StringComparison.Ordinal) &&
                    !string.IsNullOrWhiteSpace(literalHeaderValue) &&
                    int.TryParse(literalHeaderValue, NumberStyles.Integer, CultureInfo.InvariantCulture, out headerValue))
                {
                    return true;
                }

                continue;
            }

            if ((first & 0x10) != 0)
            {
                var index = ReadPrefixedInteger(headerBlock, ref offset, 4);
                var indexedHeader = state?.ResolveDynamicHeader(prefix.Base, index, postBase: true)
                    ?? throw new NotSupportedException("SplitHTTP HTTP/3 static header decoding does not support QPACK dynamic table references.");
                if (string.Equals(indexedHeader.Name, headerName, StringComparison.Ordinal) &&
                    int.TryParse(indexedHeader.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out headerValue))
                {
                    return true;
                }

                continue;
            }

            var postBaseNameIndex = ReadPrefixedInteger(headerBlock, ref offset, 3);
            var postBaseHeaderName = state?.ResolveDynamicHeaderName(prefix.Base, postBaseNameIndex, postBase: true)
                ?? throw new NotSupportedException("SplitHTTP HTTP/3 static header decoding does not support QPACK dynamic table references.");
            var postBaseHeaderValue = ReadStringLiteral(
                headerBlock,
                ref offset,
                decode: string.Equals(postBaseHeaderName, headerName, StringComparison.Ordinal));
            if (string.Equals(postBaseHeaderName, headerName, StringComparison.Ordinal) &&
                !string.IsNullOrWhiteSpace(postBaseHeaderValue) &&
                int.TryParse(postBaseHeaderValue, NumberStyles.Integer, CultureInfo.InvariantCulture, out headerValue))
            {
                return true;
            }
        }

        return false;
    }

    private static Dictionary<string, string> DecodeHeadersCore(
        ReadOnlySpan<byte> headerBlock,
        HeaderBlockPrefix prefix,
        RuntimeQPackDecoderState? state)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var offset = prefix.PayloadOffset;

        while (offset < headerBlock.Length)
        {
            var header = ReadHeaderField(headerBlock, ref offset, prefix, state);
            if (header.Name.Length == 0)
            {
                continue;
            }

            headers[header.Name] = header.Value;
        }

        return headers;
    }

    private static QPackHeaderField ReadHeaderField(
        ReadOnlySpan<byte> headerBlock,
        ref int offset,
        HeaderBlockPrefix prefix,
        RuntimeQPackDecoderState? state)
    {
        var first = headerBlock[offset];
        if ((first & 0x80) != 0)
        {
            var isStatic = (first & 0x40) != 0;
            var index = ReadPrefixedInteger(headerBlock, ref offset, 6);
            return isStatic
                ? ResolveStaticHeader(index)
                : state?.ResolveDynamicHeader(prefix.Base, index, postBase: false)
                  ?? throw new NotSupportedException("SplitHTTP HTTP/3 static header decoding does not support QPACK dynamic table references.");
        }

        if ((first & 0x40) != 0)
        {
            var isStatic = (first & 0x10) != 0;
            var nameIndex = ReadPrefixedInteger(headerBlock, ref offset, 4);
            var name = isStatic
                ? ResolveStaticHeaderName(nameIndex)
                : state?.ResolveDynamicHeaderName(prefix.Base, nameIndex, postBase: false)
                  ?? throw new NotSupportedException("SplitHTTP HTTP/3 static header decoding does not support QPACK dynamic table references.");
            var value = ReadStringLiteral(headerBlock, ref offset, decode: true)
                ?? throw new InvalidDataException("QPACK literal header value could not be decoded.");
            return new QPackHeaderField(name, value);
        }

        if ((first & 0x20) != 0)
        {
            var name = ReadLiteralHeaderName(headerBlock, ref offset)
                ?? throw new InvalidDataException("QPACK literal header name could not be decoded.");
            var value = ReadStringLiteral(headerBlock, ref offset, decode: true)
                ?? throw new InvalidDataException("QPACK literal header value could not be decoded.");
            return new QPackHeaderField(name, value);
        }

        if ((first & 0x10) != 0)
        {
            var index = ReadPrefixedInteger(headerBlock, ref offset, 4);
            return state?.ResolveDynamicHeader(prefix.Base, index, postBase: true)
                ?? throw new NotSupportedException("SplitHTTP HTTP/3 static header decoding does not support QPACK dynamic table references.");
        }

        var postBaseNameIndex = ReadPrefixedInteger(headerBlock, ref offset, 3);
        var postBaseName = state?.ResolveDynamicHeaderName(prefix.Base, postBaseNameIndex, postBase: true)
            ?? throw new NotSupportedException("SplitHTTP HTTP/3 static header decoding does not support QPACK dynamic table references.");
        var postBaseValue = ReadStringLiteral(headerBlock, ref offset, decode: true)
            ?? throw new InvalidDataException("QPACK literal header value could not be decoded.");
        return new QPackHeaderField(postBaseName, postBaseValue);
    }

    private QPackHeaderField ResolveDynamicHeader(long baseValue, int index, bool postBase)
    {
        var absoluteIndex = postBase
            ? baseValue + index
            : baseValue - index - 1;
        if (absoluteIndex < 0)
        {
            throw new InvalidDataException("QPACK dynamic table reference resolved to a negative absolute index.");
        }

        lock (_stateLock)
        {
            if (!_dynamicEntriesByAbsoluteIndex.TryGetValue(absoluteIndex, out var entry))
            {
                throw new InvalidDataException("QPACK header block referenced an unavailable dynamic table entry.");
            }

            return new QPackHeaderField(entry.Name, entry.Value);
        }
    }

    private string ResolveDynamicHeaderName(long baseValue, int index, bool postBase)
        => ResolveDynamicHeader(baseValue, index, postBase).Name;

    private QPackHeaderField ResolveEncoderDynamicHeader(int index)
    {
        lock (_stateLock)
        {
            if (index < 0 || index >= _dynamicEntries.Count)
            {
                throw new InvalidDataException("QPACK encoder stream referenced an invalid dynamic table entry.");
            }

            var entry = _dynamicEntries[_dynamicEntries.Count - 1 - index];
            return new QPackHeaderField(entry.Name, entry.Value);
        }
    }

    private static QPackHeaderField ResolveStaticHeader(int index)
    {
        if ((uint)index >= StaticTable.Length)
        {
            throw new InvalidDataException("QPACK header block referenced an invalid static table entry.");
        }

        return StaticTable[index];
    }

    private static string ResolveStaticHeaderName(int index)
        => ResolveStaticHeader(index).Name;

    private static string? ReadLiteralHeaderName(ReadOnlySpan<byte> headerBlock, ref int offset)
    {
        if (offset >= headerBlock.Length)
        {
            throw new InvalidDataException("QPACK literal header name exceeded the available header block bytes.");
        }

        var huffmanEncoded = (headerBlock[offset] & 0x08) != 0;
        var length = ReadPrefixedInteger(headerBlock, ref offset, 3);
        if (offset + length > headerBlock.Length)
        {
            throw new InvalidDataException("QPACK literal header name exceeded the available header block bytes.");
        }

        var valueSlice = headerBlock.Slice(offset, length);
        offset += length;
        return DecodeQPackString(valueSlice, huffmanEncoded, decode: true);
    }

    private static string? ReadStringLiteral(
        ReadOnlySpan<byte> headerBlock,
        ref int offset,
        bool decode)
    {
        if (offset >= headerBlock.Length)
        {
            throw new InvalidDataException("QPACK string literal exceeded the available header block bytes.");
        }

        var huffmanEncoded = (headerBlock[offset] & 0x80) != 0;
        var length = ReadPrefixedInteger(headerBlock, ref offset, 7);
        if (offset + length > headerBlock.Length)
        {
            throw new InvalidDataException("QPACK string literal exceeded the available header block bytes.");
        }

        var valueSlice = headerBlock.Slice(offset, length);
        offset += length;
        return DecodeQPackString(valueSlice, huffmanEncoded, decode);
    }

    private static string DecodeQPackString(
        ReadOnlySpan<byte> valueSlice,
        bool huffmanEncoded)
        => huffmanEncoded
            ? RuntimeHpackHuffman.DecodeToUtf8String(valueSlice)
            : Encoding.UTF8.GetString(valueSlice);

    private static string? DecodeQPackString(
        ReadOnlySpan<byte> valueSlice,
        bool huffmanEncoded,
        bool decode)
        => decode
            ? DecodeQPackString(valueSlice, huffmanEncoded)
            : null;

    private static int ReadPrefixedInteger(
        ReadOnlySpan<byte> buffer,
        ref int offset,
        int prefixBits)
    {
        if (offset >= buffer.Length)
        {
            throw new InvalidDataException("QPACK integer exceeded the available header block bytes.");
        }

        var maxPrefixValue = (1 << prefixBits) - 1;
        var value = buffer[offset] & maxPrefixValue;
        offset++;

        if (value < maxPrefixValue)
        {
            return value;
        }

        var shift = 0;
        while (true)
        {
            if (offset >= buffer.Length)
            {
                throw new InvalidDataException("QPACK integer exceeded the available header block bytes.");
            }

            var next = buffer[offset++];
            value += (next & 0x7F) << shift;
            if ((next & 0x80) == 0)
            {
                return value;
            }

            shift += 7;
        }
    }

    private static async ValueTask<int> ReadPrefixedIntegerAsync(
        Stream stream,
        byte firstByte,
        int prefixBits,
        CancellationToken cancellationToken)
    {
        var maxPrefixValue = (1 << prefixBits) - 1;
        var value = firstByte & maxPrefixValue;
        if (value < maxPrefixValue)
        {
            return value;
        }

        var shift = 0;
        while (true)
        {
            var next = await ReadRequiredByteAsync(stream, cancellationToken).ConfigureAwait(false);
            value += (next & 0x7F) << shift;
            if ((next & 0x80) == 0)
            {
                return value;
            }

            shift += 7;
        }
    }

    private static async ValueTask<string> ReadQPackStringAsync(
        Stream stream,
        int prefixBits,
        byte huffmanMask,
        CancellationToken cancellationToken)
    {
        var firstByte = await ReadRequiredByteAsync(stream, cancellationToken).ConfigureAwait(false);
        return await ReadQPackStringAsync(stream, firstByte, prefixBits, huffmanMask, cancellationToken)
            .ConfigureAwait(false);
    }

    private static async ValueTask<string> ReadQPackStringAsync(
        Stream stream,
        byte firstByte,
        int prefixBits,
        byte huffmanMask,
        CancellationToken cancellationToken)
    {
        var huffmanEncoded = (firstByte & huffmanMask) != 0;
        var length = await ReadPrefixedIntegerAsync(stream, firstByte, prefixBits, cancellationToken)
            .ConfigureAwait(false);
        if (length == 0)
        {
            return string.Empty;
        }

        var payload = new byte[length];
        await ReadExactAsync(stream, payload, cancellationToken).ConfigureAwait(false);
        return DecodeQPackString(payload, huffmanEncoded);
    }

    private static async ValueTask<byte> ReadRequiredByteAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        var result = await ReadOptionalByteAsync(stream, cancellationToken).ConfigureAwait(false);
        if (!result.HasValue)
        {
            throw new EndOfStreamException("Unexpected EOF while reading a QPACK stream.");
        }

        return result.Value;
    }

    private static async ValueTask<byte?> ReadOptionalByteAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[1];
        var read = await stream.ReadAsync(buffer.AsMemory(0, 1), cancellationToken).ConfigureAwait(false);
        return read == 0
            ? null
            : buffer[0];
    }

    private static async ValueTask ReadExactAsync(
        Stream stream,
        Memory<byte> buffer,
        CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer[offset..], cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw new EndOfStreamException("Unexpected EOF while reading a QPACK stream.");
            }

            offset += read;
        }
    }

    private static byte[] BuildInsertCountIncrementInstruction(int increment)
        => BuildPrefixedIntegerInstruction(increment, prefixBits: 6, prefixMask: 0x00);

    private static byte[] BuildSectionAcknowledgementInstruction(long streamId)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(streamId);
        if ((streamId & 0x03) != 0)
        {
            throw new InvalidDataException("QPACK section acknowledgements require a client-initiated bidirectional stream ID.");
        }

        return BuildPrefixedIntegerInstruction(streamId >> 2, prefixBits: 7, prefixMask: 0x80);
    }

    private static byte[] BuildStreamCancellationInstruction(long streamId)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(streamId);
        if ((streamId & 0x03) != 0)
        {
            throw new InvalidDataException("QPACK stream cancellations require a client-initiated bidirectional stream ID.");
        }

        return BuildPrefixedIntegerInstruction(streamId >> 2, prefixBits: 6, prefixMask: 0x40);
    }

    private static async ValueTask TryWriteStreamCancellationAsync(
        long streamId,
        Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask> decoderInstructionWriter)
    {
        try
        {
            await decoderInstructionWriter(
                    BuildStreamCancellationInstruction(streamId),
                    CancellationToken.None)
                .ConfigureAwait(false);
        }
        catch
        {
        }
    }

    private static byte[] BuildPrefixedIntegerInstruction(
        long value,
        int prefixBits,
        byte prefixMask)
    {
        var buffer = new MemoryStream(8);
        WritePrefixedInteger(buffer, value, prefixBits, prefixMask);
        return buffer.ToArray();
    }

    private static void WritePrefixedInteger(
        MemoryStream buffer,
        long value,
        int prefixBits,
        byte prefixMask)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        ArgumentOutOfRangeException.ThrowIfNegative(value);

        var maxPrefixValue = (1 << prefixBits) - 1;
        if (value < maxPrefixValue)
        {
            buffer.WriteByte((byte)(prefixMask | value));
            return;
        }

        buffer.WriteByte((byte)(prefixMask | maxPrefixValue));
        value -= maxPrefixValue;
        while (value >= 128)
        {
            buffer.WriteByte((byte)((value & 0x7F) | 0x80));
            value >>= 7;
        }

        buffer.WriteByte((byte)value);
    }

    private static void WriteVariableLengthInteger(MemoryStream buffer, long value)
    {
        Span<byte> encoded = stackalloc byte[8];
        var offset = 0;
        WriteVariableLengthInteger(encoded, ref offset, value);
        buffer.Write(encoded[..offset]);
    }

    private static void WriteVariableLengthInteger(
        Span<byte> buffer,
        ref int offset,
        long value)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(value);
        if (value < 64)
        {
            buffer[offset++] = (byte)value;
            return;
        }

        if (value < 16_384)
        {
            buffer[offset++] = (byte)(0x40 | ((value >> 8) & 0x3F));
            buffer[offset++] = (byte)(value & 0xFF);
            return;
        }

        if (value < 1_073_741_824L)
        {
            buffer[offset++] = (byte)(0x80 | ((value >> 24) & 0x3F));
            buffer[offset++] = (byte)((value >> 16) & 0xFF);
            buffer[offset++] = (byte)((value >> 8) & 0xFF);
            buffer[offset++] = (byte)(value & 0xFF);
            return;
        }

        if (value < 4_611_686_018_427_387_904L)
        {
            buffer[offset++] = (byte)(0xC0 | ((value >> 56) & 0x3F));
            buffer[offset++] = (byte)((value >> 48) & 0xFF);
            buffer[offset++] = (byte)((value >> 40) & 0xFF);
            buffer[offset++] = (byte)((value >> 32) & 0xFF);
            buffer[offset++] = (byte)((value >> 24) & 0xFF);
            buffer[offset++] = (byte)((value >> 16) & 0xFF);
            buffer[offset++] = (byte)((value >> 8) & 0xFF);
            buffer[offset++] = (byte)(value & 0xFF);
            return;
        }

        throw new ArgumentOutOfRangeException(
            nameof(value),
            value,
            "HTTP/3 variable-length integers must be smaller than 2^62.");
    }

    private readonly record struct QPackHeaderField(string Name, string Value);

    private readonly record struct QPackDynamicEntry(long AbsoluteIndex, string Name, string Value, int Size);

    private readonly record struct HeaderBlockPrefix(long RequiredInsertCount, long Base, int PayloadOffset);
}

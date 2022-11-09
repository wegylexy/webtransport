extern alias Quic;
using Quic.System.Net.Quic;
using System.Buffers;
using System.Collections.Concurrent;
using System.Net.Http.HPack;
using System.Text;
using System.Threading.Channels;

namespace FlyByWireless.WebTransport;

public class WebTransportConnection : IAsyncDisposable
{
    private int _disposed;

    private readonly QuicConnection _connection;

    private long _clientGoAway = long.MaxValue, _serverGoAway = long.MaxValue, _lastAcceptedStreamId;

    private readonly QuicStream _clientControlStream, _serverControlStream;

    public Task Completion { get; }

    internal readonly ConcurrentDictionary<long, WebTransportSession> _sessions = new();

    private readonly Channel<(long HeaderSize, QuicStream Stream)> _requests = Channel.CreateUnbounded<(long, QuicStream)>(new()
    {
        AllowSynchronousContinuations = false,
        SingleReader = false,
        SingleWriter = true
    });

    internal WebTransportConnection(QuicConnection connection, QuicStream clientControlStrem, QuicStream serverControlStream)
    {
        _connection = connection;
        _clientControlStream = clientControlStrem;
        _lastAcceptedStreamId = _clientControlStream.StreamId;
        _serverControlStream = serverControlStream;
        Completion = RunAsync();
    }

    private async Task RunAsync()
    {
        using CancellationTokenSource cts = new();
        try
        {
            _ = Task.Run(async () =>
            {
                try
                {
                    for (; ; )
                    {
                        var (type, length) = await _clientControlStream.ReadH3FrameHeaderAsync(cts.Token);
                        if (type == 7) // GOAWAY
                        {
                            var id = await _clientControlStream.ReadQuicIntegerAsync(cts.Token);
                            if (id.QuicIntegerSize() != length)
                            {
                                _clientControlStream.AbortRead(0x106); // H3_FRAME_ERROR
                                break;
                            }
                            else if (id > _clientGoAway)
                            {
                                _clientControlStream.AbortRead(0x108); // H3_ID_ERROR
                                break;
                            }
                            else
                            {
                                _clientGoAway = id;
                            }
                        }
                        else
                        {
                            await _clientControlStream.DropExactlyAsync(length, cts.Token);
                        }
                    }
                }
                catch { }
                finally
                {
                    try { await _clientControlStream.ShutdownCompleted(); } catch { }
                    cts.Cancel();
                }
            });
            _ = _serverControlStream.ShutdownCompleted().AsTask().ContinueWith(task => cts.Cancel());
            var cancellationToken = cts.Token;
            _connection.DatagramReceived += (s, e) =>
            {
                var data = e;
                if (data.TryReadQuicInteger(out var sessionId))
                {
                    sessionId *= 4;
                    if (_sessions.TryGetValue(sessionId, out var session))
                    {
                        session.ReceiveDatagram(data);
                    }
                }
            };
            while (!_clientControlStream.ReadsCompleted)
            {
                var stream = await _connection.AcceptStreamAsync(cancellationToken);
                _lastAcceptedStreamId = stream.StreamId;
                _ = Task.Run(async () =>
                {
                    var buffered = false;
                    try
                    {
                        if (stream.StreamId > _serverGoAway)
                        {
                            stream.AbortRead(0x10b); // H3_REQUEST_REJECTED
                            if (stream.CanWrite)
                            {
                                stream.AbortWrite(0x10b);
                            }
                        }
                        else if (stream.CanWrite)
                        {
                            var (type, lengthOrSessionId) = await stream.ReadH3FrameHeaderAsync(cancellationToken);
                            if (type == 0x41) // WEBTRANSPORT_STREAM
                            {
                                if (_sessions.TryGetValue(lengthOrSessionId, out var session))
                                {
                                    if (await session.TryQueueStreamAsync(stream))
                                    {
                                        buffered = true;
                                    }
                                    else
                                    {
                                        stream.AbortRead(0x3994bd84); // H3_WEBTRANSPORT_BUFFERED_STREAM_REJECTED
                                        stream.AbortWrite(0x3994bd84);
                                    }
                                }
                                else
                                {
                                    stream.AbortRead(0x108); // H3_ID_ERROR
                                    stream.AbortWrite(0x108);
                                }
                            }
                            else if (type == 1) // HEADERS
                            {
                                if (_requests.Writer.TryWrite((lengthOrSessionId, stream)))
                                {
                                    buffered = true;
                                }
                                else
                                {
                                    stream.AbortRead(0x107); // H3_EXCESSIVE_LOAD
                                    stream.AbortWrite(0x107);
                                }
                            }
                            else
                            {
                                stream.AbortRead(0x105); // H3_FRAME_UNEXPECTED
                                stream.AbortWrite(0x105);
                            }
                        }
                        else
                        {
                            // for some reason, stream reading always hangs unless connection begins to accept another stream
                            var type = await stream.ReadQuicIntegerAsync(cancellationToken);
                            if (type == 0x54) // WEBTRANSPORT_STREAM
                            {
                                var length = await stream.ReadQuicIntegerAsync(cancellationToken);
                                if (_sessions.TryGetValue(length, out var session))
                                {
                                    if (await session.TryQueueStreamAsync(stream))
                                    {
                                        buffered = true;
                                    }
                                    else
                                    {
                                        stream.AbortRead(0x3994bd84); // H3_WEBTRANSPORT_BUFFERED_STREAM_REJECTED
                                    }
                                }
                                else
                                {
                                    stream.AbortRead(0x108); // H3_ID_ERROR
                                }
                            }
                            else if ((type - 0x21) % 0x1f == 0) // reserved stream type
                            {
                                stream.AbortRead(type); // reserved error code
                            }
                            else
                            {
                                stream.AbortRead(0x103); // H3_STREAM_CREATION_ERROR
                            }
                        }
                    }
                    catch when (cancellationToken.IsCancellationRequested)
                    {
                        stream.AbortRead(0x104); // H3_CLOSED_CRITICAL_STREAM
                        if (stream.CanWrite)
                        {
                            stream.AbortWrite(0x104);
                        }
                    }
                    catch (EndOfStreamException)
                    {
                        stream.AbortRead(0x101); // H3_GENERAL_PROTOCOL_ERROR
                        if (stream.CanWrite)
                        {
                            stream.AbortWrite(0x101);
                        }
                    }
                    catch
                    {
                        stream.AbortRead(0x102); // H3_INTERNAL_ERROR
                        if (stream.CanWrite)
                        {
                            stream.AbortWrite(0x102);
                        }
                    }
                    finally
                    {
                        if (!buffered)
                        {
                            await using (stream) { }
                        }
                    }
                });
            }
        }
        finally
        {
            try
            {
                await CloseAsync(cts.IsCancellationRequested ? 0x104 : 0x100); // H3_CLOSED_CRITICAL_STREAM or H3_NO_ERROR
            }
            catch (ObjectDisposedException) { }
            catch (QuicConnectionAbortedException) { }
            finally
            {
                if (_requests.Writer.TryComplete())
                {
                    await foreach (var request in _requests.Reader.ReadAllAsync())
                    {
                        await using (request.Stream) { }
                    }
                }
            }
        }
    }

    public async ValueTask<WebTransportRequest> AcceptRequestAsync(CancellationToken cancellationToken = default)
    {
        var reader = _requests.Reader;
        for (; ; )
        {
            long headerSize;
            QuicStream stream;
            try
            {
                (headerSize, stream) = await reader.ReadAsync(cancellationToken);
            }
            catch (ChannelClosedException)
            {
                break;
            }
            if (headerSize > 2)
            {
                var buffer = ArrayPool<byte>.Shared.Rent((int)Math.Min(headerSize, 0x2000));
                try
                {
                    await stream.ReadExactlyAsync(buffer.AsMemory(0, 2), cancellationToken);
                    if (buffer[0] != 0 || buffer[1] != 0)
                    {
                        throw new InvalidDataException("Required insert count and delta base must be 0.");
                    }
                    headerSize -= 2;
                    using HttpRequestMessage message = new();
                    bool isHttps = false, isConnect = false, isWebtransport = false;
                    string? authority = null, path = null, origin = null, version = null;
                    void CheckHeaderSize()
                    {
                        if (headerSize < 0)
                        {
                            stream.AbortRead(0x106); // H3_FRAME_ERROR
                            stream.AbortWrite(0x106);
                            throw new InvalidDataException("Incomplete header.");
                        }
                    }
                    while (headerSize > 0)
                    {
                        async ValueTask ReadByteAsync()
                        {
                            await stream.ReadExactlyAsync(buffer.AsMemory(0, 1), cancellationToken);
                            --headerSize;
                            CheckHeaderSize();
                        }
                        async ValueTask<long> ContinueReadPrefixedIntegerAsync(int prefixSize)
                        {
                            var mask = (1 << prefixSize) - 1;
                            var value = buffer![0] & mask;
                            if (value == mask)
                            {
                                var shift = 0;
                                do
                                {
                                    await ReadByteAsync();
                                    value += (buffer[0] & 0b1111111) << shift;
                                    shift += 7;
                                } while ((buffer[0] & 0b10000000) == 0b10000000);
                            }
                            return value;
                        }
                        async ValueTask<string> ContinueReadLiteralAsync(int prefixSize)
                        {
                            var compressed = ((buffer![0] >> prefixSize) & 1) == 1;
                            var length = await ContinueReadPrefixedIntegerAsync(prefixSize);
                            headerSize -= length;
                            CheckHeaderSize();
                            if (length > 0x2000)
                            {
                                throw new InvalidOperationException("Header field too large.");
                            }
                            var memory = buffer.AsMemory(0, (int)length);
                            await stream.ReadExactlyAsync(memory, cancellationToken);
                            if (compressed)
                            {
                                var raw = GC.AllocateUninitializedArray<byte>(0x400);
                                var decoded = Huffman.Decode(memory.Span, ref raw);
                                memory = raw.AsMemory(0, decoded);
                            }
                            return Encoding.ASCII.GetString(memory.Span);
                        }
                        await ReadByteAsync();
                        switch (buffer[0] >> 6)
                        {
                            case 3: // static indexed field line
                                {
                                    var index = await ContinueReadPrefixedIntegerAsync(6);
                                    switch (index)
                                    {
                                        case 1: // :path /
                                            path = "/";
                                            break;
                                        case 15: // :method CONNECT
                                            isConnect = true;
                                            break;
                                        case 16: // :method DELETE
                                        case 17: // :method GET
                                        case 18: // :method HEAD
                                        case 19: // :method OPTIONS
                                        case 20: // :method POST
                                        case 21: // :method PUT
                                            throw new InvalidOperationException(":method must be CONNECT.");
                                        case 22: // :scheme http
                                            throw new InvalidOperationException(":scheme must be https.");
                                        case 23: // :scheme https
                                            isHttps = true;
                                            break;
                                    }
                                }
                                break;
                            case 1: // static literal field line with name reference
                                {
                                    var index = await ContinueReadPrefixedIntegerAsync(4);
                                    await ReadByteAsync();
                                    var value = await ContinueReadLiteralAsync(7);
                                    switch (index)
                                    {
                                        case 0: // :authority
                                            authority = value;
                                            break;
                                        case 1: // :path
                                            path = value;
                                            break;
                                        case 90: // :origin
                                            origin = value;
                                            break;
                                    }
                                }
                                break;
                            case 0 when buffer[0] >> 5 == 1: // literal field line with literal name
                                {
                                    var name = await ContinueReadLiteralAsync(3);
                                    await ReadByteAsync();
                                    var value = await ContinueReadLiteralAsync(7);
                                    if (name == ":protocol")
                                    {
                                        if (value != "webtransport")
                                        {
                                            throw new InvalidOperationException(":protocol must be webtransport");
                                        }
                                        isWebtransport = true;
                                    }
                                    else if (value == "1" && name.StartsWith("sec-webtransport-http3-draft"))
                                    {
                                        var draft = name[23..];
                                        if (version == null || draft.CompareTo(version) == 1)
                                        {
                                            version = draft;
                                        }
                                    }
                                }
                                break;
                            default:
                                throw new InvalidDataException("No QPACK dynamic table.");
                        }
                        CheckHeaderSize();
                    }
                    if (isHttps && isConnect && isWebtransport && version != null && authority != null && path != null && origin != null)
                    {
                        return new(this, stream, version, authority, path, origin);
                    }
                }
                catch { }
                finally
                {
                    ArrayPool<byte>.Shared.Return(buffer);
                }
            }
            await using (stream)
            {
                var errorCode = cancellationToken.IsCancellationRequested ? 0x10c : 0x101; // H3_REQUEST_CANCELLED or H3_GENERAL_PROTOCOL_ERROR
                stream.AbortRead(errorCode); // H3_GENERAL_PROTOCOL_ERROR
                stream.AbortWrite(errorCode);
            }
        }
        await Completion;
        throw new QuicConnectionAbortedException(string.Empty, default);
    }

    internal QuicStream OpenBidirectionalStream()
    {
        var stream = _connection.OpenBidirectionalStream();
        if (stream.StreamId > _clientGoAway)
        {
            using (stream)
            {
                throw new InvalidOperationException("Client going away");
            }
        }
        return stream;
    }

    internal QuicStream OpenUnidirectionalStream()
    {
        var stream = _connection.OpenUnidirectionalStream();
        if (stream.StreamId > _clientGoAway)
        {
            using (stream)
            {
                throw new InvalidOperationException("Client going away");
            }
        }
        return stream;
    }

    internal Task<QuicDatagramSendingResult> SendDatagramAsync(ReadOnlySequence<byte> buffers, bool priority = false) =>
        _connection.SendDatagramAsync(buffers, priority);

    public async ValueTask GoAwayAsync(CancellationToken cancellationToken = default)
    {
        if (Interlocked.CompareExchange(ref _serverGoAway, _lastAcceptedStreamId, long.MaxValue) != long.MaxValue)
        {
            _serverGoAway = _lastAcceptedStreamId;
            var buffer = ArrayPool<byte>.Shared.Rent(10);
            try
            {
                var size = buffer.AsSpan().WriteQuicInteger(7); // GOAWAY
                size += buffer.AsSpan(size).WriteQuicInteger(_serverGoAway.QuicIntegerSize());
                size += buffer.AsSpan(size).WriteQuicInteger(_serverGoAway);
                await _serverControlStream.WriteAsync(buffer.AsMemory(0, size), cancellationToken);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }
        else
        {
            throw new InvalidOperationException("ALrady gone away.");
        }
    }

    public ValueTask CloseAsync(long errorCode = 0x100) =>
        _connection.CloseAsync(errorCode);

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 1)
        {
            await using (_clientControlStream)
            await using (_serverControlStream)
            using (_connection)
            {
                var close = CloseAsync();
                try { await Completion; } catch { }
                try { await close; } catch { }
            }
            foreach (var session in _sessions.Values)
            {
                await using (session) { }
            }
            _sessions.Clear();
        }
        GC.SuppressFinalize(this);
    }
}
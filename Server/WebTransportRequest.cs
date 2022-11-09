extern alias Quic;
using Quic.System.Net.Quic;
using System.Buffers;
using System.Diagnostics;
using System.Net.Http.QPack;

namespace FlyByWireless.WebTransport;

public sealed class WebTransportRequest : IAsyncDisposable
{
    private readonly WebTransportConnection _connection;

    private QuicStream? _stream;

    private readonly string _version;

    public string Authority { get; }

    public string Path { get; }

    public string Origin { get; }

    internal WebTransportRequest(WebTransportConnection connection, QuicStream stream, string version, string authority, string path, string origin)
    {
        _connection = connection;
        _stream = stream;
        _version = version;
        Authority = authority;
        Path = path;
        Origin = origin;
    }

    public async ValueTask<WebTransportSession> AcceptAsync(CancellationToken cancellationToken = default)
    {
        var stream = Interlocked.Exchange(ref _stream, null);
        if (stream == null)
        {
            throw new InvalidOperationException("Request expired.");
        }
        try
        {
            var buffer = ArrayPool<byte>.Shared.Rent(0x40);
            try
            {
                if (QPackEncoder.EncodeStaticIndexedHeaderField(25 /* :status 200 */, buffer.AsSpan(11), out var statusSize) &&
                    QPackEncoder.EncodeLiteralHeaderFieldWithoutNameReference("sec-webtransport-http3-draft", _version, buffer.AsSpan(11 + statusSize), out var versionSize))
                {
                    long headerSize = 2 + statusSize + versionSize;
                    var lengthSize = headerSize.QuicIntegerSize();
                    var offset = 8 - lengthSize;
                    buffer.AsSpan(offset + 1).WriteQuicInteger(headerSize);
                    buffer[10] = buffer[9] = 0;
                    buffer[offset] = 1;
                    WebTransportSession session = new(_connection, stream);
                    var added = _connection._sessions.TryAdd(stream.StreamId, session);
                    Debug.Assert(added);
                    _ = session.Completion.ContinueWith(async task =>
                    {
                        await using (session)
                        {
                            var removed = _connection._sessions.TryRemove(stream.StreamId, out _);
                            Debug.Assert(removed);
                        }
                    });
                    using var cancellation = cancellationToken.Register(() =>
                    {
                        stream.AbortWrite(0x10c); // H3_REQUEST_CANCELLED
                    });
                    await stream.WriteAsync(buffer.AsMemory(offset, 1 + lengthSize + (int)headerSize), CancellationToken.None);
                    return session;
                }
                throw new InvalidOperationException("Error packing headers.");
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }
        catch
        {
            await using (stream)
            {
                stream.AbortRead(0x102); // H3_INTERNAL_ERROR
                stream.AbortWrite(0x102);
            }
            throw;
        }
    }

    public async ValueTask RejectAsync()
    {
        var stream = Interlocked.Exchange(ref _stream, null);
        if (stream == null)
        {
            throw new InvalidOperationException("Request expired.");
        }
        await using (stream)
        {
            stream.AbortRead(0x10b); // H3_REQUEST_REJECTED
            stream.AbortWrite(0x10b);
        }
    }

    public async ValueTask DisposeAsync()
    {
        var stream = Interlocked.Exchange(ref _stream, null);
        if (stream != null)
        {
            await using (stream)
            {
                stream.AbortRead(0x10b); // H3_REQUEST_REJECTED
                stream.AbortWrite(0x10b);
            }
        }
        GC.SuppressFinalize(this);
    }
}
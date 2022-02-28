using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Net.Quic;
using System.Text;
using System.Threading.Channels;

namespace FlyByWireless.WebTransport;

public class WebTransportSession : IAsyncDisposable
{
    private int _disposed;

    private readonly WebTransportConnection _connection;

    private readonly QuicStream _requestStream;

    public bool IsDatagramRegistered { get; private set; }

    public event QuicDatagramReceivedEventHandler? DatagramReceived;

    public Task Completion { get; }

    private readonly Channel<QuicStream> _acceptQueue = Channel.CreateUnbounded<QuicStream>(new()
    {
        AllowSynchronousContinuations = true,
        SingleReader = false,
        SingleWriter = true
    });

    internal WebTransportSession(WebTransportConnection connection, QuicStream requestStream)
    {
        _connection = connection;
        _requestStream = requestStream;
        Completion = RunAsync();
    }

    private async Task RunAsync()
    {
        try
        {
            while (!_requestStream.ReadsCompleted)
            {
                var (capsuleType, length) = await _requestStream.ReadH3DataFrameCapsuleHeaderAsync();
                switch (capsuleType)
                {
                    case 0xff37a2 when length == 4: // REGISTER_DATAGRAM
                        if (await _requestStream.ReadQuicIntegerAsync() == 0xff7c00) // WEBTRANSPORT_DATAGRAM
                        {
                            IsDatagramRegistered = true;
                            break;
                        }
                        else
                        {
                            throw new NotSupportedException("Unexepected datagram format type.");
                        }
                    case 0x2843: // CLOSE_WEBTRANSPORT_SESSION
                        if (length > 1028)
                        {
                            _requestStream.AbortRead(0x10e); // H3_MESSAGE_ERROR
                            throw new InvalidDataException("CLOSE_WEBTRANSPORT_SESSION capsule too large");
                        }
                        else
                        {
                            var buffer = ArrayPool<byte>.Shared.Rent(Math.Min((int)length, 1024));
                            try
                            {
                                await _requestStream.ReadExactlyAsync(buffer.AsMemory(0, 4));
                                var code = BinaryPrimitives.ReadInt32BigEndian(buffer.AsSpan(0, 4));
                                string message;
                                var messageLength = (int)length - sizeof(int);
                                if (messageLength > 0)
                                {
                                    await _requestStream.ReadExactlyAsync(buffer.AsMemory(0, messageLength));
                                    message = Encoding.UTF8.GetString(buffer.AsSpan(0, messageLength));
                                }
                                else
                                {
                                    message = string.Empty;
                                }
                                if (!_requestStream.ReadsCompleted)
                                {
                                    throw new InvalidOperationException("CLOSE_WEBTRANSPORT_SESSION without FIN");
                                }
                                throw new QuicStreamAbortedException(message, code);
                            }
                            finally
                            {
                                ArrayPool<byte>.Shared.Return(buffer);
                            }
                        }
                    case 0xff37a3: // CLOSE_DATAGRAM_CONTEXT
                    case 0xff37a1: // REGISTER_DATAGRAM_CONTEXT
                    case 0xff37a4: // DATAGRAM_WITH_CONTEXT
                    case 0xff37a5: // DATAGRAM
                        throw new InvalidOperationException("Unexpected capsule type.");
                    default:
                        await _requestStream.DropExactlyAsync(length);
                        break;
                }
            }
        }
        catch
        {
            _requestStream.AbortRead(0x101); // H3_GENERAL_PROTOCOL_ERROR
            _requestStream.AbortWrite(0x101);
        }
        finally
        {
            try
            {
                _requestStream.Shutdown();
                await _requestStream.ShutdownCompleted();
            }
            catch (ObjectDisposedException) { }
            finally
            {
                if (_acceptQueue.Writer.TryComplete())
                {
                    await foreach (var stream in _acceptQueue.Reader.ReadAllAsync())
                    {
                        await using (stream)
                        {
                            stream.AbortRead(0x3994bd84); // H3_WEBTRANSPORT_BUFFERED_STREAM_REJECTED
                        }
                    }
                }
            }
        }
    }

    internal async ValueTask<bool> TryQueueStreamAsync(QuicStream stream)
    {
        if (_acceptQueue.Writer.TryWrite(stream))
        {
            return true;
        }
        await using (stream)
        {
            stream.AbortRead(0x3994bd84); // H3_WEBTRANSPORT_BUFFERED_STREAM_REJECTED
        }
        return false;
    }

    public async ValueTask<QuicStream> AcceptStreamAsync(CancellationToken cancellationToken = default)
    {
        var reader = _acceptQueue.Reader;
        try
        {
            return await reader.ReadAsync(cancellationToken);
        }
        catch (ChannelClosedException) { }
        await Completion;
        throw new QuicStreamAbortedException(string.Empty, default);
    }

    public async ValueTask<QuicStream> OpenUnidirectionalStreamAsync(CancellationToken cancellationToken = default)
    {
        var stream = _connection.OpenUnidirectionalStream();
        var buffer = ArrayPool<byte>.Shared.Rent(16);
        try
        {
            var size = buffer.AsSpan().WriteQuicInteger(0x54); // WEBTRANSPORT_STREAM
            size += buffer.AsSpan(size).WriteQuicInteger(_requestStream.StreamId);
            await stream.WriteAsync(buffer.AsMemory(0, size), cancellationToken);
        }
        catch
        {
            await using (stream)
            {
                var errorCode = cancellationToken.IsCancellationRequested ? 0x10c : 0x102; // H3_REQUEST_CANCELLED or H3_INTERNAL_ERROR
                stream.AbortWrite(errorCode);
            }
            throw;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
        return stream;
    }

    public async ValueTask<QuicStream> OpenBidirectionalStreamAsync(CancellationToken cancellationToken = default)
    {
        var stream = _connection.OpenBidirectionalStream();
        var buffer = ArrayPool<byte>.Shared.Rent(16);
        try
        {
            var size = buffer.AsSpan().WriteQuicInteger(0x41);
            size += buffer.AsSpan(size).WriteQuicInteger(_requestStream.StreamId);
            await stream.WriteAsync(buffer.AsMemory(0, size), cancellationToken);
        }
        catch
        {
            await using (stream)
            {
                var errorCode = cancellationToken.IsCancellationRequested ? 0x10c : 0x102; // H3_REQUEST_CANCELLED or H3_INTERNAL_ERROR
                stream.AbortWrite(errorCode);
                stream.AbortRead(errorCode);
            }
            throw;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
        return stream;
    }

    internal void ReceiveDatagram(ReadOnlySpan<byte> buffer) =>
        DatagramReceived?.Invoke(this, buffer);

    public Task<QuicDatagramSendingResult> SendDatagramAsync(ReadOnlyMemory<byte> buffer, bool priority = false) =>
        SendDatagramAsync(new ReadOnlySequence<byte>(buffer), priority);

    private sealed class ReadOnlyByteSequenceSegment : ReadOnlySequenceSegment<byte>
    {
        public ReadOnlyByteSequenceSegment(long runningIndex, ReadOnlyMemory<byte> memory)
        {
            RunningIndex = runningIndex;
            Memory = memory;
        }

        public ReadOnlyByteSequenceSegment Chain(ReadOnlyMemory<byte> next)
        {
            Debug.Assert(Next == null, "Already chained.");
            ReadOnlyByteSequenceSegment segment = new(RunningIndex + Memory.Length, next);
            Next = segment;
            return segment;
        }
    }

    public async Task<QuicDatagramSendingResult> SendDatagramAsync(ReadOnlySequence<byte> buffers, bool priority = false)
    {
        if (!IsDatagramRegistered)
        {
            throw new InvalidOperationException("Datagram format not registered");
        }
        var prefix = ArrayPool<byte>.Shared.Rent(8);
        void Finally() => ArrayPool<byte>.Shared.Return(prefix);
        try
        {
            var prefixSize = prefix.AsSpan().WriteQuicInteger(_requestStream.StreamId / 4);
            ReadOnlyByteSequenceSegment
                start = new(0, prefix.AsMemory(0, prefixSize)),
                end = start;
            foreach (var b in buffers)
            {
                end = end.Chain(b);
            }
            buffers = new(start, 0, end, end.Memory.Length);
            var sent = await _connection.SendDatagramAsync(buffers, priority);
            _ = sent.Completion.ContinueWith(task => Finally());
            return sent;
        }
        catch
        {
            Finally();
            throw;
        }
    }

    public async ValueTask CloseAsync(int code = 0, string? message = null, CancellationToken cancellationToken = default)
    {
        var messageLength = message != null ? Encoding.UTF8.GetByteCount(message) : 0;
        if (code == 0 && messageLength == 0)
        {
            await _requestStream.WriteAsync(ReadOnlyMemory<byte>.Empty, true, cancellationToken);
        }
        else
        {
            if (messageLength > 1024)
            {
                throw new ArgumentException("Message too long.");
            }
            var buffer = ArrayPool<byte>.Shared.Rent(20 + messageLength);
            try
            {
                var size = buffer.AsSpan().WriteQuicInteger(0x2843); // CLOSE_WEBTRANSPORT_SESSION
                size += buffer.AsSpan(size).WriteQuicInteger(sizeof(int) + messageLength);
                BinaryPrimitives.WriteInt32BigEndian(buffer.AsSpan(size), code);
                size += sizeof(int);
                if (messageLength > 0)
                {
                    var written = Encoding.UTF8.GetBytes(message, buffer.AsSpan(size));
                    Debug.Assert(written == messageLength);
                    size += messageLength;
                }
                using var cancellation = cancellationToken.Register(() =>
                {
                    _requestStream.AbortWrite(0x10c); // H3_REQUEST_CANCELLED
                });
                await _requestStream.WriteAsync(buffer.AsMemory(0, size), true, CancellationToken.None);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 1)
        {
            await using (_requestStream)
            {
                _requestStream.Shutdown();
                try { await Completion; } catch { }
                try { await _requestStream.ShutdownCompleted(); } catch { }
            }
        }
        GC.SuppressFinalize(this);
    }
}
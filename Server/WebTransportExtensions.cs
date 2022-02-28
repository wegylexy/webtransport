using System.Buffers;
using System.Buffers.Binary;
using System.Net.Quic;
using System.Net.Security;

namespace FlyByWireless.WebTransport;

public static class WebTransportExtensions
{
    public static QuicListenerOptions WithWebTransport(this QuicListenerOptions options)
    {
        options.DatagramReceiveEnabled = true;
        var alpns = options.ServerAuthenticationOptions!.ApplicationProtocols ??= new();
        if (!alpns.Contains(SslApplicationProtocol.Http3))
        {
            alpns.Add(SslApplicationProtocol.Http3);
        }
        return options;
    }

    private static async Task<QuicStream> OpenWebTransportControlStreamAsync(this QuicConnection connection, CancellationToken cancellationToken = default)
    {
        var controlStream = connection.OpenUnidirectionalStream();
        try
        {
            using var cancellation = cancellationToken.Register(() =>
            {
                controlStream.AbortWrite(0x101); // H3_GENERAL_PROTOCOL_ERROR
            });
            // Sets H3_DATAGRAM (0xffd276) and ENABLE_WEBTRANSPORT (0x2b603742) to 1
            await controlStream.WriteAsync(new byte[] { 0, 4, 10, 0x80, 0xFF, 0xD2, 0x77, 1, 0xAB, 0x60, 0x37, 0x42, 1 }, CancellationToken.None);
        }
        catch
        {
            using (controlStream) { }
            throw;
        }
        return controlStream;
    }

    internal static async ValueTask ReadExactlyAsync(this Stream stream, Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        for (var offset = 0; offset < buffer.Length;)
        {
            var read = await stream.ReadAsync(buffer[offset..], cancellationToken);
            if (read == 0)
            {
                throw new EndOfStreamException();
            }
            offset += read;
        }
    }

    internal static async ValueTask DropExactlyAsync(this Stream stream, long length, CancellationToken cancellationToken = default)
    {
        var buffer = ArrayPool<byte>.Shared.Rent((int)Math.Min(1024, length));
        try
        {
            while (length > 0)
            {
                var read = await stream.ReadAsync(buffer.AsMemory(0, (int)Math.Min(length, buffer.Length)), cancellationToken);
                if (read == 0)
                {
                    throw new EndOfStreamException();
                }
                length -= read;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    internal static bool TryReadQuicInteger(this ref ReadOnlySpan<byte> span, out long value)
    {
        if (span.Length > 0)
        {
            switch (span[0] >> 6)
            {
                case 0:
                    value = span[0];
                    span = span[1..];
                    return true;
                case 1 when span.Length > 1:
                    value = BinaryPrimitives.ReadInt16BigEndian(span[..2]) & 0x3FFF;
                    span = span[2..];
                    return true;
                case 2 when span.Length > 3:
                    value = BinaryPrimitives.ReadInt32BigEndian(span[..4]) & 0x3FFF_FFFF;
                    span = span[4..];
                    return true;
                case 3 when span.Length > 7:
                    value = BinaryPrimitives.ReadInt64BigEndian(span[..8]) & 0x3FFF_FFFF_FFFF_FFFF;
                    span = span[8..];
                    return true;
            }
        }
        value = default;
        return false;
    }

    internal static async ValueTask<long> ReadQuicIntegerAsync(this Stream stream, CancellationToken cancellationToken = default)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(8);
        try
        {
            await stream.ReadExactlyAsync(buffer.AsMemory(0, 1), cancellationToken);
            var prefix = buffer[0] >> 6;
            if (prefix == 0)
            {
                return buffer[0];
            }
            buffer[0] &= 0b111111;
            switch (prefix)
            {
                case 1:
                    await stream.ReadExactlyAsync(buffer.AsMemory(1, 1), cancellationToken);
                    return BinaryPrimitives.ReadInt16BigEndian(buffer.AsSpan(0, 2));
                case 2:
                    await stream.ReadExactlyAsync(buffer.AsMemory(1, 3), cancellationToken);
                    return BinaryPrimitives.ReadInt32BigEndian(buffer.AsSpan(0, 4));
                case 3:
                    await stream.ReadExactlyAsync(buffer.AsMemory(1, 7), cancellationToken);
                    return BinaryPrimitives.ReadInt64BigEndian(buffer.AsSpan(0, 8));
            }
            throw new AccessViolationException(); // unreachable
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    internal static int WriteQuicInteger(this Span<byte> destination, long value)
    {
        switch ((ulong)value)
        {
            case < 0x40:
                destination[0] = (byte)value;
                return 1;
            case < 0x4000:
                BinaryPrimitives.WriteUInt16BigEndian(destination, (ushort)(0x4000 | value));
                return 2;
            case < 0x4000_0000:
                BinaryPrimitives.WriteUInt32BigEndian(destination, 0x8000_0000 | (uint)value);
                return 4;
            case < 0x4000_0000_0000_0000:
                BinaryPrimitives.WriteUInt64BigEndian(destination, 0xC000_0000_0000_0000 | (ulong)value);
                return 8;
            default:
                throw new ArgumentOutOfRangeException(nameof(value));
        }
    }

    internal static int QuicIntegerSize(this long value) => value switch
    {
        < 0x40 => 1,
        < 0x4000 => 2,
        < 0x40000000 => 4,
        _ => 8
    };

    public static async Task<WebTransportConnection> AcceptWebTransportConnectionAsync(this QuicListener listener, CancellationToken cancellationToken = default)
    {
        for (; ; )
        {
            QuicStream? clientControlStream = null, serverControlStream = null;
            var quicConnection = await listener.AcceptConnectionAsync(cancellationToken);
            try
            {
                if (quicConnection.NegotiatedApplicationProtocol.Equals(SslApplicationProtocol.Http3))
                {
                    // Prevents accepting WebTransport request streams before the client control stream
                    // - avoid buffering streams
                    // - limit network egress from client attacks
                    clientControlStream = await quicConnection.AcceptWebTransportControlStreamAsync(cancellationToken);
                    serverControlStream = await quicConnection.OpenWebTransportControlStreamAsync(cancellationToken);
                    return new(quicConnection, clientControlStream, serverControlStream);
                }
            }
            catch { }
            await using (clientControlStream)
            await using (serverControlStream)
            using (quicConnection)
            {
                if (quicConnection.Connected)
                {
                    await quicConnection.CloseAsync(0x101, cancellationToken); // H3_GENERAL_PROTOCOL_ERROR
                }
            }
        }
    }

    private static async ValueTask<(long Type, QuicStream Stream)> AcceptH3StreamAsync(this QuicConnection connection, CancellationToken cancellationToken = default)
    {
        for (; ; )
        {
            var stream = await connection.AcceptStreamAsync(cancellationToken);
            try
            {
                if (stream.CanWrite)
                {
                    return (default, stream);
                }
                // seems to always hang on subsequent unidirectional streams
                var type = await stream.ReadQuicIntegerAsync(cancellationToken);
                if ((type - 0x21) % 0x1f != 0) // not reserved stream type
                {
                    return (type, stream);
                }
                await using (stream)
                {
                    stream.AbortRead(type); // reserved error code
                }
            }
            catch
            {
                await using (stream)
                {
                    var errorCode = cancellationToken.IsCancellationRequested ? 0x10c : 0x101; // H3_REQUEST_CANCELLED or H3_GENERAL_PROTOCOL_ERROR
                    stream.AbortRead(errorCode);
                    if (stream.CanWrite)
                    {
                        stream.AbortWrite(errorCode);
                    }
                }
                throw;
            }
        }
    }

    internal static async ValueTask<(long Type, long Length)> ReadH3FrameHeaderAsync(this QuicStream stream, CancellationToken cancellationToken = default)
    {
        for (; ; )
        {
            var type = await stream.ReadQuicIntegerAsync(cancellationToken);
            var length = await stream.ReadQuicIntegerAsync(cancellationToken);
            if ((type - 0x21) % 0x1f != 0) // not reserved frame type
            {
                return (type, length);
            }
            try
            {
                await stream.DropExactlyAsync(length, cancellationToken);
            }
            catch (EndOfStreamException) when (stream.CanWrite)
            {
                stream.AbortWrite(0x106); // H3_FRAME_ERROR
                throw;
            }
        }
    }

    internal static async ValueTask<(long Type, long Length)> ReadH3DataFrameCapsuleHeaderAsync(this QuicStream stream, CancellationToken cancellationToken = default)
    {
        for (; ; )
        {
            var (frameType, dataFrameLength) = await stream.ReadH3FrameHeaderAsync(cancellationToken);
            if (frameType != 0) // DATA
            {
                stream.AbortRead(0x105); // H3_FRAME_UNEXPECTED
                stream.AbortWrite(0x105);
                throw new InvalidDataException("Unexpected frame");
            }
            var capsuleType = await stream.ReadQuicIntegerAsync(cancellationToken);
            dataFrameLength -= capsuleType.QuicIntegerSize();
            if (dataFrameLength < 0)
            {
                break;
            }
            var length = await stream.ReadQuicIntegerAsync(cancellationToken);
            dataFrameLength -= length.QuicIntegerSize() + length;
            if (dataFrameLength != 0)
            {
                break;
            }
            if ((capsuleType - 23) % 41 != 0) // not reserved capsule type
            {
                return (capsuleType, length);
            }
            try
            {
                await stream.DropExactlyAsync(length, cancellationToken);
            }
            catch (EndOfStreamException)
            {
                stream.AbortWrite(0x101); // H3_GENERAL_PROTOCOL_ERROR
                throw;
            }
        }
        stream.AbortRead(0x101); // H3_GENERAL_PROTOCOL_ERROR
        stream.AbortWrite(0x101);
        throw new InvalidDataException("Protocol error");
    }

    private static async ValueTask<QuicStream> AcceptWebTransportControlStreamAsync(this QuicConnection connection, CancellationToken cancellationToken = default)
    {
        var (streamType, controlStream) = await connection.AcceptH3StreamAsync(cancellationToken);
        try
        {
            if (controlStream.CanWrite || streamType != 0)
            {
                controlStream.AbortRead(0x103); // H3_STREAM_CREATION_ERROR
                throw new InvalidOperationException("No control stream");
            }
            var (frameType, length) = await controlStream.ReadH3FrameHeaderAsync(cancellationToken);
            if (frameType != 4)
            {
                controlStream.AbortRead(0x010a); // H3_MISSING_SETTINGS
                throw new InvalidOperationException("No SETTINGS");
            }
            bool h3Datagram = false, enableWebTransport = false;
            while (length > 0)
            {
                var id = await controlStream.ReadQuicIntegerAsync(cancellationToken);
                length -= id.QuicIntegerSize();
                if (length < 0)
                {
                    controlStream.AbortRead(0x0106); // H3_FRAME_ERROR
                    throw new InvalidDataException("Invalid HTTP/3 SETTINGS ID");
                }
                var value = await controlStream.ReadQuicIntegerAsync(cancellationToken);
                length -= value.QuicIntegerSize();
                if (length < 0)
                {
                    controlStream.AbortRead(0x0106); // H3_FRAME_ERROR
                    throw new InvalidDataException("Invalid HTTP/3 SETTINGS value");
                }
                switch (id)
                {
                    case 0xffd277:
                        h3Datagram = value == 1;
                        break;
                    case 0x2b603742:
                        enableWebTransport = value == 1;
                        break;
                }
            }
            if (!(h3Datagram && enableWebTransport))
            {
                throw new InvalidOperationException("H3_DATAGRAM or ENABLE_WEBTRANSPORT not set to 1");
            }
        }
        catch
        {
            await using (controlStream)
            {
                controlStream.AbortRead(0x101); // H3_GENERAL_PROTOCOL_ERROR
            }
            throw;
        }
        return controlStream;
    }
}
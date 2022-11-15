extern alias Quic;
using FlyByWireless.WebTransport;
using Microsoft.Extensions.DependencyInjection;
using Quic.System.Net.Quic;
using System.Buffers;
using System.Net;
using System.Text;

const int MaxClients = 100;

using CancellationTokenSource cts = new();
Console.CancelKeyPress += (s, e) =>
{
    e.Cancel = true;
    cts.Cancel();
};

var runningInDocker = Environment.GetEnvironmentVariable("DOTNET_RUNNING_IN_CONTAINER") == "true";

ServiceCollection services = new();
services.AddWebTransportCertService("Fly by Wireless", "localhost");
var provider = services.BuildServiceProvider();
var certService = provider.GetRequiredService<CertService>();

using QuicListener listener = new(new QuicListenerOptions()
{
    ListenEndPoint = new(IPAddress.IPv6Any, runningInDocker ? 3297 : 4433),
    ServerAuthenticationOptions = new()
    {
        ServerCertificateSelectionCallback = (sender, hostName) =>
        {
            Console.WriteLine($"Selecting certificate for {hostName}");

            var cert = certService.GetCertificate(out var hash);
            var s = Convert.ToBase64String(hash.Span);
            Console.WriteLine($"Certificate SHA-256 (Base-64): {s}");
            // TODO: certService.EnumerateHashes().Select(h => Convert.ToBase64String(h.Span));
            Console.WriteLine(@$"/*JavaScript*/ new WebTransport(""https://localhost:4433/test"",{{serverCertificateHashes:[{{algorithm:""sha-256"",value:Uint8Array.from(atob(""{s}""),c=>c.charCodeAt(0))}}]}})");

            return cert;
        }
    },
    IdleTimeout = TimeSpan.FromSeconds(30)
}.WithWebTransport());
Console.WriteLine($"Listening on port {listener.ListenEndPoint.Port}");
await RunAsync(listener, MaxClients, cts.Token);

static async Task RunAsync(QuicListener listener, int maxConnections, CancellationToken cancellationToken = default)
{
    SemaphoreSlim backlogSemaphore = new(Environment.ProcessorCount), connectionSemaphore = new(MaxClients);
    while (!cancellationToken.IsCancellationRequested)
    {
        try
        {
            await backlogSemaphore.WaitAsync(cancellationToken);
            _ = Task.Run(async () =>
            {
                var released = false;
                try
                {
                    await connectionSemaphore.WaitAsync(cancellationToken);
                    try
                    {
                        await using var connection = await listener.AcceptWebTransportConnectionAsync(cancellationToken);
                        backlogSemaphore.Release();
                        released = true;
                        using var cancel = cancellationToken.Register(() => connection.CloseAsync(0x10c).AsTask()); // H3_REQUEST_CANCELLED
                        await HandleConnectionAsync(connection, cancellationToken);
                    }
                    catch when (cancellationToken.IsCancellationRequested) { }
                    catch (QuicConnectionAbortedException ex)
                    {
                        Console.WriteLine($"Disconnected with code 0x{ex.ErrorCode:X4}.");
                    }
                    catch (Exception ex)
                    {
                        Console.Error.WriteLine(ex);
                    }
                    finally
                    {
                        connectionSemaphore.Release();
                    }
                }
                finally
                {
                    if (!released)
                    {
                        backlogSemaphore.Release();
                    }
                }
            }, CancellationToken.None);
        }
        catch when (cancellationToken.IsCancellationRequested)
        {
            break;
        }
    }
    for (var i = 0; i < MaxClients; ++i)
    {
        await connectionSemaphore.WaitAsync(CancellationToken.None);
    }
}

static async Task HandleConnectionAsync(WebTransportConnection connection, CancellationToken cancellationToken = default)
{
    for (; ; )
    {
        await using var request = await connection.AcceptRequestAsync(cancellationToken);
        Console.WriteLine(":authority " + request.Authority);
        Console.WriteLine(":path " + request.Path);
        Console.WriteLine(":origin " + request.Origin);
        var session = await request.AcceptAsync(cancellationToken);
        _ = Task.Run(async () =>
        {
            try
            {
                await using (session)
                {
                    session.DatagramReceived += (s, e) =>
                    {
                        var length = e.Length;
                        Console.WriteLine($"Received a datagram of {length} byte(s)");
                        var buffer = ArrayPool<byte>.Shared.Rent(length);
                        e.CopyTo(buffer);
                        _ = Task.Run(async () =>
                        {
                            try
                            {
                                var sent = await session.SendDatagramAsync(buffer.AsMemory(0, length));
                                try
                                {
                                    await sent.LostSuspect;
                                }
                                catch (TimeoutException)
                                {
                                    Console.WriteLine("Datagram lost suspected.");
                                }
                                await sent.Completion;
                            }
                            catch (Exception ex)
                            {
                                Console.Error.WriteLine(ex);
                            }
                            finally
                            {
                                ArrayPool<byte>.Shared.Return(buffer);
                            }
                        }, CancellationToken.None);
                    };
                    for (; ; )
                    {
                        var stream = await session.AcceptStreamAsync(cancellationToken);
                        _ = Task.Run(async () =>
                        {
                            try
                            {
                                await using (stream)
                                {
                                    string data;
                                    {
                                        using StreamReader reader = new(stream, Encoding.UTF8, leaveOpen: true);
                                        data = await reader.ReadToEndAsync();
                                        Console.WriteLine(data);
                                    }
                                    if (stream.CanWrite)
                                    {
                                        using StreamWriter writer = new(stream, Encoding.UTF8, leaveOpen: true);
                                        await writer.WriteAsync(data);
                                    }
                                    else
                                    {
                                        Console.WriteLine("Stream is unidirectional.");
                                    }
                                }
                            }
                            catch when (cancellationToken.IsCancellationRequested) { }
                            catch (Exception ex)
                            {
                                Console.Error.WriteLine(ex);
                            }
                        }, CancellationToken.None);
                    }
                }
            }
            catch when (cancellationToken.IsCancellationRequested) { }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex);
            }
        }, CancellationToken.None);
    }
}
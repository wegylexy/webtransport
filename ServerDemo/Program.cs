using FlyByWireless.WebTransport;
using Microsoft.Extensions.Configuration;
using System.Buffers;
using System.Net;
using System.Net.Quic;
using System.Security.Cryptography.X509Certificates;
using System.Text;

const int MaxClients = 1000;

using CancellationTokenSource cts = new();
Console.CancelKeyPress += (s, e) =>
{
    e.Cancel = true;
    cts.Cancel();
};

var runningInDocker = Environment.GetEnvironmentVariable("DOTNET_RUNNING_IN_CONTAINER") == "true";
static X509Certificate2 ImportCert()
{
    var configuration = new ConfigurationBuilder()
#if DEBUG
        .AddUserSecrets<Program>()
#endif
        .Build();
    var cert = X509Certificate2.CreateFromPem(configuration["Cert"], configuration["Key"]);
    try
    {
        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 20145, 1000))
        {
            using (cert)
            {
                // Converts PEM to PKCS12 for Schannel
                return new(cert.Export(X509ContentType.Pkcs12));
            }
        }
        return cert;
    }
    catch
    {
        using (cert) { }
        throw;
    }
}
using X509Certificate2 cert = ImportCert();
using QuicListener listener = new(new QuicListenerOptions()
{
    ListenEndPoint = new(IPAddress.IPv6Any, runningInDocker ? 3297 : 4433),
    ServerAuthenticationOptions = new()
    {
        ServerCertificate = cert
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
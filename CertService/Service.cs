using Microsoft.Extensions.Options;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace FlyByWireless.WebTransport;

public class CertService
{
    protected static readonly X509Extension
        _purpose = new X509EnhancedKeyUsageExtension(new OidCollection
        {
            new("1.3.6.1.5.5.7.3.1") // serverAuth
        }, false),
        _usage = new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false);

    protected readonly X500DistinguishedName _subjectName;
    protected readonly X509Extension _subjectAlternateNames;
    protected readonly TimeSpan _duration;
    protected readonly ConcurrentQueue<(X509Certificate2 Cert, ReadOnlyMemory<byte> Hash, DateTime Expiry)> _certs;

    protected virtual DateTimeOffset UtcNow => DateTimeOffset.UtcNow;

    public CertService(IOptions<CertServiceOptions> options)
    {
        _subjectName = options.Value.SubjectName;
        SubjectAlternativeNameBuilder sanBuilder = new();
        foreach (var name in options.Value.DnsNames)
        {
            sanBuilder.AddDnsName(name);
        }
        _subjectAlternateNames = sanBuilder.Build();
        _duration = options.Value.Duration;
        _certs = new();
    }

    protected virtual X509Certificate2 GenerateCertificate(out DateTimeOffset expiry)
    {
        // Creates key
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        // Requests
        CertificateRequest req = new(_subjectName, ec, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(_purpose);
        req.CertificateExtensions.Add(_usage);
        req.CertificateExtensions.Add(_subjectAlternateNames);
        // Signs
        var now = UtcNow;
        using var crt = req.CreateSelfSigned(now, expiry = now.Add(_duration - TimeSpan.FromTicks(1)));
        // Exports
        return new(crt.Export(X509ContentType.Pfx));
    }

    protected virtual void Rotate()
    {
        var old = UtcNow.UtcDateTime;
        if (_certs.TryPeek(out var first) && first.Expiry < old)
        {
            lock (_certs)
            {
                while (_certs.TryPeek(out first) && first.Expiry < old)
                {
                    _ = _certs.TryDequeue(out _);
                }
            }
        }
        old += _duration * 2 / 3;
        if (_certs.LastOrDefault().Expiry <= old)
        {
            lock (_certs)
            {
                if (_certs.LastOrDefault().Expiry <= old)
                {
                    var cert = GenerateCertificate(out var expiry);
                    _certs.Enqueue((cert, SHA256.HashData(cert.RawData), expiry.UtcDateTime));
                }
            }
        }
    }

    public virtual IEnumerable<ReadOnlyMemory<byte>> EnumerateHashes()
    {
        Rotate();
        return _certs.Select(t => t.Hash);
    }

    public virtual X509Certificate2 GetCertificate(out ReadOnlyMemory<byte> hash)
    {
        Rotate();
        var last = _certs.TakeLast(2).First();
        hash = last.Hash;
        return last.Cert;
    }
}
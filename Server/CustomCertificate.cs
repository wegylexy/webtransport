using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace FlyByWireless;

public static class CustomCertificate
{
    public static X509Certificate2 Generate(string name, params string[] dnsNames)
    {
        var now = DateTimeOffset.UtcNow;
        SubjectAlternativeNameBuilder sanBuilder = new();
        foreach (var n in dnsNames)
        {
            sanBuilder.AddDnsName(n);
        }
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest req = new($"CN={name}", ec, HashAlgorithmName.SHA256);
        // Adds purpose
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection
        {
            new("1.3.6.1.5.5.7.3.1") // serverAuth
        }, false));
        // Adds usage
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature
        , false));
        // Adds subject alternate names
        req.CertificateExtensions.Add(sanBuilder.Build());
        // Signs
        using var crt = req.CreateSelfSigned(now, now.AddDays(14));
        // Exports
        return new(crt.Export(X509ContentType.Pfx));
    }
}
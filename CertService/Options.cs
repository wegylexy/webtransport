using System.Collections.ObjectModel;
using System.Security.Cryptography.X509Certificates;

namespace FlyByWireless.WebTransport;

public sealed class CertServiceOptions
{
    /// <summary>
    /// Subject name.
    /// </summary>
#if NET7_0_OR_GREATER
    public required X500DistinguishedName SubjectName { get; set; }
#else
    public X500DistinguishedName SubjectName { get; set; } = null!;
#endif

    /// <summary>
    /// DNS names.
    /// </summary>
    public Collection<string> DnsNames { get; } = new();

    /// <summary>
    /// Duration (default to 14 days).
    /// </summary>
    public TimeSpan Duration { get; set; } = TimeSpan.FromDays(14);
}
using FlyByWireless.WebTransport;
using Microsoft.Extensions.DependencyInjection.Extensions;
using System.Security.Cryptography.X509Certificates;

namespace Microsoft.Extensions.DependencyInjection;

public static class WebTransportCertServiceExtensions
{
    public static IServiceCollection AddWebTransportCertService<T>(this IServiceCollection services, X500DistinguishedName subjectName, params string[] dnsNames) where T : CertService
    {
        services.TryAddSingleton<CertService, T>();
        services.Configure<CertServiceOptions>(options =>
        {
            options.SubjectName = subjectName;
            foreach (var name in dnsNames)
            {
                options.DnsNames.Add(name);
            }
        });
        return services;
    }

    public static IServiceCollection AddWebTransportCertService(this IServiceCollection services, X500DistinguishedName subjectName, params string[] dnsNames) =>
        services.AddWebTransportCertService<CertService>(subjectName, dnsNames);

    public static IServiceCollection AddWebTransportCertService<T>(this IServiceCollection services, string commonName, params string[] dnsNames) where T : CertService
    {
#if NET7_0_OR_GREATER
        X500DistinguishedNameBuilder builder = new();
        builder.AddCommonName(commonName);
        return services.AddWebTransportCertService<T>(builder.Build(), dnsNames);
#else
        return services.AddWebTransportCertService<T>(new X500DistinguishedName("CN=" + commonName), dnsNames);
#endif
    }
    public static IServiceCollection AddWebTransportCertService(this IServiceCollection services, string commonName, params string[] dnsNames) =>
        services.AddWebTransportCertService<CertService>(commonName, dnsNames);

    public static IServiceCollection AddWebTransportCertService<T>(this IServiceCollection services) where T : CertService =>
        services.AddWebTransportCertService<T>("localhost", "localhost");
    public static IServiceCollection AddWebTransportCertService(this IServiceCollection services) =>
        services.AddWebTransportCertService<CertService>();
}
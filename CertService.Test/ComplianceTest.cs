using FluentAssertions;
using FlyByWireless.WebTransport.Test;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Linq;
using Xunit;

namespace FlyByWireless.WebTransport;

public sealed class ComplianceTest
{
    private static readonly TimeSpan _duration = TimeSpan.FromDays(14);

    private static TestableCertService CreateTestSubject()
    {
        ServiceCollection services = new();
        services.AddWebTransportCertService<TestableCertService>()
            .Configure<CertServiceOptions>(options =>
            {
                options.Duration = _duration;
            });
        var provider = services.BuildServiceProvider();
        return (TestableCertService)provider.GetRequiredService<CertService>();
    }

    [Fact]
    public void Renewal()
    {
        var now = DateTimeOffset.UtcNow;
        using var service = CreateTestSubject();

        // in the beginning
        service.SetUtcNow(now);
        var before1 = service.EnumerateHashes().ToList();
        var first = service.GetCertificate(out var hash1);
        service.EnumerateHashes().Should().BeEquivalentTo(before1, "no rotation yet")
            .And.ContainSingle("first cert created")
            .Which.Should().Be(hash1, "no rotation");

        // just after 1/3 duration
        service.SetUtcNow(now + _duration / 3 + TimeSpan.FromSeconds(1));
        var before2 = service.EnumerateHashes().ToList();
        before2.Should().HaveCount(2, "first rotation").And
            .Contain(hash1, "existing still valid");
        var second = service.GetCertificate(out var hash2);
        second.Should().BeSameAs(first, "same cert");
        service.EnumerateHashes().Should().BeEquivalentTo(before2, "no change")
            .And.ContainSingle(hash => hash.Equals(hash2), "current")
            .Which.Should().Be(hash1, "same hash");

        // just before 2/3 duration
        service.SetUtcNow(now + _duration * 2 / 3 - TimeSpan.FromSeconds(1));
        var before3 = service.EnumerateHashes().ToList();
        before3.Should().BeEquivalentTo(before2, "still first rotation");
        var third = service.GetCertificate(out var hash3);
        third.Should().BeSameAs(second, "same cert");
        service.EnumerateHashes().Should().BeEquivalentTo(before2, "no change");
        hash3.Should().Be(hash2, "same hash");

        // just after 2/3 duration
        service.SetUtcNow(now + _duration * 2 / 3 + TimeSpan.FromSeconds(1));
        var before4 = service.EnumerateHashes().ToList();
        before4.Should().HaveCount(3, "second rotations");
        var forth = service.GetCertificate(out var hash4);
        forth.Should().NotBe(third, "cert rotated");
        service.EnumerateHashes().Should().BeEquivalentTo(before4, "no change")
            .And.ContainSingle(hash => hash.Equals(hash3), "previous")
            .And.ContainSingle(hash => hash.Equals(hash4), "current")
            .Which.Should().NotBe(hash3, "different hash");

        // just after duration
        service.SetUtcNow(now + _duration + TimeSpan.FromSeconds(1));
        var before5 = service.EnumerateHashes().ToList();
        before5.Should().HaveCount(3, "expired")
            .And.NotBeEquivalentTo(before4, "cert rotated")
            .And.NotContain(hash3, "first cert expired")
            .And.ContainSingle(hash => hash.Equals(hash4), "previous");
    }
}
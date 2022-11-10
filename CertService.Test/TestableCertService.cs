using Microsoft.Extensions.Options;
using System;

namespace FlyByWireless.WebTransport.Test;

internal class TestableCertService : CertService
{
    private DateTimeOffset _UtcNow;

    protected override DateTimeOffset UtcNow => _UtcNow;

    public TestableCertService(IOptions<CertServiceOptions> options) : base(options) { }

    public void SetUtcNow(DateTimeOffset utcNow) => _UtcNow = utcNow;
}

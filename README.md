# WebTransport over HTTP/3 Server

## Features

- HTTP/3 connection
  - Multiple WebTransport sessions per connection
  - QUIC streams buffering
- Connect request filtering
  - `:authority`
  - `:path`
  - `:origin`
- WebTransport session
  - Datagrams in implicit context
  - Multiple unidirectional streams
  - Multiple bidirection streams

Reference: https://www.ietf.org/id/draft-ietf-webtrans-http3-02.html

## Test

According to [Playing with QUIC](https://www.chromium.org/quic/playing-with-quic/), custom certificates (even installed in Local Machine Trusted Root) will not be trusted by Chromium-based browsers. All of `--user-data-dir`, `--origin-to-force-quic-on`, and `--ignore-certificate-errors-spki-list` are required to test with a custom certificate.

Simple client: https://googlechrome.github.io/samples/webtransport/client.html

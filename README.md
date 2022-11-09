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

Simple client: https://googlechrome.github.io/samples/webtransport/client.html (use F12 Dev Console to set a break point and inject custom cert hash(es))

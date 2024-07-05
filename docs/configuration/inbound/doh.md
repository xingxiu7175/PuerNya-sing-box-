`doh` inbound is a dns inbound used to response dns query message over HTTPS and HTTP/3.

### Structure

```json
{
  "type": "doh",
  "tag": "doh-in",
  "network": "udp",
  "listen": "::",
  "listen_port": 443,
  "query_path": "/dns-query",
  "udp_fragment": false,
  "tls": {}
}
```

### Fields

#### network

Listen network, one of `tcp` `udp`.

Both if empty.

When listening TCP network, HTTPS stream will be accepted. As well as HTTP/3 when listening UDP.

#### query_path

Path to receive DNS query.

`/dns-query` as default.

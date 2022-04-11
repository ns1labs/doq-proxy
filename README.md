# DNS-over-QUIC to UDP Proxy

DNS-over-QUIC to UDP proxy and client implementation.

2019—2022 © NSONE, Inc.

## License

This code is released under Apache License 2.0. You can find terms and
conditions in the LICENSE file.

## Protocol compatibility

The DNS-over-QUIC implementation follows
[draft-ietf-dprive-dnsoquic-11](https://datatracker.ietf.org/doc/draft-ietf-dprive-dnsoquic).

The QUIC protocol compatibility depends on the
[quic-go](https:///github.com/lucas-clemente/quic-go) library.

## Getting started

Build the DoQ proxy and testing client.

```
go build ./cmd/proxy
go build ./cmd/client
```

Generate testing key and self-signed certificate for the proxy server.

```
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -out key.pem
openssl req -x509 -days 30 -subj "/CN=DNS-over-QUIC Test" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1" -key key.pem -out cert.pem
```

Start the proxy. By default, the server loads the TLS key and certificate from
the files generated above, will use 8.8.4.4 (Google Public DNS) as a backend
server, and will listen on UDP port 853 (experimental port from the draft). Use
command line options to modify the default behavior. Notice the use of the
default port requires starting the proxy as superuser.

```
sudo ./proxy
```

Query the proxy using the testing utility. The client establishes a QUIC
session to the server and sends each query via a dedicated stream. Upstream, the
XFR requests are sent over TCP, all others are sent over UDP. The replies are
printed in the order of completion:

```
./client ns1.com A ns1.com AAAA
```
```
;; opcode: QUERY, status: NOERROR, id: 25849
;; flags: qr rd ra; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 1

;; QUESTION SECTION:
;ns1.com.	IN	 AAAA

;; ANSWER SECTION:
ns1.com.	195	IN	AAAA	2606:4700:10::6814:31b6
ns1.com.	195	IN	AAAA	2606:4700:10::6814:30b6
ns1.com.	195	IN	RRSIG	AAAA 13 2 200 20190325121641 20190323121641 44688 ns1.com. m17G7sGkXNhBiKINI2LuQLvUL0Qb+l6LMUmKSoVo2TP5sw3Yd27L44QOZhVU1GS//tD1e6YVOVsMrW3arlk/bQ==

;; ADDITIONAL SECTION:

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags: do; udp: 512

;; opcode: QUERY, status: NOERROR, id: 26044
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 1

;; QUESTION SECTION:
;ns1.com.	IN	 A

;; ANSWER SECTION:
ns1.com.	25	IN	A	104.20.49.182
ns1.com.	25	IN	A	104.20.48.182
ns1.com.	25	IN	RRSIG	A 13 2 26 20190325121645 20190323121645 44688 ns1.com. xJK5DhMiFqxWx/gC7gHQXM8wkVFDyocIF3Zuehqa+S92zAq3yOtZMrqVRXxsKNw2lfCMQXLHr7hVUDm5H4B5eA==

;; ADDITIONAL SECTION:

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags: do; udp: 512
```

## Troubleshooting

Note that this is an experimental code built on top of an experimental protocol.

The server and client in this repository use the same QUIC library
and therefore they should be compatible. However, if a different client is
used, the handshake may fail on the version negotiation. We suggest to check
packet capture first when the client is unable to connect.

The proxy also logs information about accepted connections and streams which
can be used to inspect the sequence of events:

```
$ sudo ./proxy -listen 127.0.0.1:853 -cert cert.pem -key key.pem -backend 8.8.4.4:53
ts=2019-03-24T10:31:32.408891Z msg="listening for clients" addr=127.0.0.1:853
ts=2019-03-24T12:16:45.048583Z client=127.0.0.1:52212 msg="session accepted"
ts=2019-03-24T12:16:45.050231Z client=127.0.0.1:52212 stream_id=0 msg="stream accepted"
ts=2019-03-24T12:16:45.050278Z client=127.0.0.1:52212 stream_id=4 msg="stream accepted"
ts=2019-03-24T12:16:45.091568Z client=127.0.0.1:52212 stream_id=4 msg="stream closed"
ts=2019-03-24T12:16:45.104623Z client=127.0.0.1:52212 stream_id=0 msg="stream closed"
ts=2019-03-24T12:16:45.110261Z client=127.0.0.1:52212 msg="session closed"
```

## Contributing

This project is [maintained](https://github.com/ns1/community/blob/master/project_status/MAINTENANCE.md).

Pull Requests and issues are welcome. See the [NS1 Contribution Guidelines](https://github.com/ns1/community) for more information.

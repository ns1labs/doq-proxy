# DNS-over-QUIC to UDP Proxy

DNS-over-QUIC to UDP proxy and client implementation.

2019 © NSONE, Inc.

## License

This code is released under Apache License 2.0. You can find terms and conditions in the LICENSE file.

## Protocol compatibility

The DNS-over-QUIC implementation follows [draft-huitema-quic-dnsoquic-06](https://tools.ietf.org/html/draft-huitema-quic-dnsoquic-06).

The QUIC protocol compatibility depends on the [quic-go](https:///github.com/lucas-clemente/quic-go) library.

## Examples

```
$ ./proxy -cert cert.pem -key key.pem -backend 8.8.4.4:53
ts=2019-03-24T10:31:32.408891Z msg="listening for clients" addr=127.0.0.1:784
```

```
$ ./client ns1.com DNSKEY ns1.com AAAA ns1.com MX
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

;; opcode: QUERY, status: NOERROR, id: 43577
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 1

;; QUESTION SECTION:
;ns1.com.	IN	 DNSKEY

;; ANSWER SECTION:
ns1.com.	3599	IN	DNSKEY	257 3 13 t+4DPP+MFZ0Cr7gAXiDYv6HTyXzq/O2ESVRLc/ysuh5xBXKIsjsj5baV1HzhBNo2F7mbsevsEo0/6UEL8+JBmA==
ns1.com.	3599	IN	DNSKEY	256 3 13 pxEUulkf8UZtE9fy2+4wJwM44xncypgGVps4hE4kQGA5TuC/XJPoKBX6e3B/QL9AmwFCgyFeC4uRNxoqxK0xOg==
ns1.com.	3599	IN	RRSIG	DNSKEY 13 2 3600 20190330133723 20190322133723 48553 ns1.com. gRqjGGeM7dW0dGNaicDPBizH+bHoeI9Q0UeS8v7hfgHGjqZkMDKxmuNc7T3jwCBmT+xVgeeBnRlU2/1fspfFcg==

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

```
ts=2019-03-24T12:16:45.048583Z client=127.0.0.1:52212 msg="session accepted"
ts=2019-03-24T12:16:45.050231Z client=127.0.0.1:52212 stream_id=0 msg="stream accepted"
ts=2019-03-24T12:16:45.050278Z client=127.0.0.1:52212 stream_id=4 msg="stream accepted"
ts=2019-03-24T12:16:45.050303Z client=127.0.0.1:52212 stream_id=8 msg="stream accepted"
ts=2019-03-24T12:16:45.091568Z client=127.0.0.1:52212 stream_id=4 msg="stream closed"
ts=2019-03-24T12:16:45.104623Z client=127.0.0.1:52212 stream_id=0 msg="stream closed"
ts=2019-03-24T12:16:45.10976Z client=127.0.0.1:52212 stream_id=8 msg="stream closed"
ts=2019-03-24T12:16:45.110261Z client=127.0.0.1:52212 msg="session closed"
```

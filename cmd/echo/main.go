package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"

	"github.com/go-kit/log"
	quic "github.com/quic-go/quic-go"
	"github.com/miekg/dns"

	"github.com/ns1/doq-proxy/server"
)

func main() {
	server.Main(genParams, handleStream)
}

func genParams() server.Params {
	var params server.Params
	var dns bool = true

	flag.StringVar(&params.Addr, "listen", "127.0.0.1:853", "UDP address to listen on.")
	flag.StringVar(&params.TlsCert, "cert", "cert.pem", "TLS certificate path.")
	flag.StringVar(&params.TlsKey, "key", "key.pem", "TLS key path.")
	flag.BoolVar(&dns, "dns", true, "If true, validates the traffic as DNS (default).")

	flag.Parse()

	params.Baton = dns

	return params
}

func handleDnsStream(l log.Logger, stream quic.Stream) error {
	defer stream.Close()

	wireLength := make([]byte, 2)
	_, err := io.ReadFull(stream, wireLength)
	if err != nil {
		return fmt.Errorf("read query length: %w", err)
	}

	length := binary.BigEndian.Uint16(wireLength)

	wireQuery := make([]byte, length)
	_, err = io.ReadFull(stream, wireQuery)
	if err != nil {
		return fmt.Errorf("read query payload: %w", err)
	}

	msg := dns.Msg{}
	err = msg.Unpack(wireQuery)
	if err != nil {
		return fmt.Errorf("could not decode query: %w", err)
	}

	if msg.MsgHdr.Response {
		l.Log("msg", "QR bit already set")
	}

	msg.MsgHdr.Response = true

	bundle := make([]byte, 0)
	responseWire, err := msg.Pack()
	if err != nil {
		return fmt.Errorf("could not encode response: %w", err)
	}

	bundle = binary.BigEndian.AppendUint16(bundle, uint16(len(responseWire)))
	bundle = append(bundle, responseWire...)

	_, err = stream.Write(bundle)
	if err != nil {
		return fmt.Errorf("send response: %w", err)
	}

	return nil
}

func handleDumbStream(l log.Logger, stream quic.Stream) error {
	for {
		end := false
		data := make([]byte, 2048)
		n, err := stream.Read(data)
		if err == io.EOF {
			end = true
		} else if err != nil {
			return fmt.Errorf("read query: %w", err)
		}

		_, err = stream.Write(data[:n])
		if err != nil {
			return fmt.Errorf("send response: %w", err)
		}

		if end {
			stream.Close()
			break
		}
	}

	return nil
}

func handleStream(l log.Logger, stream quic.Stream, baton any) error {
	dns := baton.(bool)
	if dns {
		return handleDnsStream(l, stream)
	} else {
		return handleDumbStream(l, stream)
	}
}

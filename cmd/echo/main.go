package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/go-kit/log"
	quic "github.com/quic-go/quic-go"
	"github.com/ns1/doq-proxy/server"
)

func main() {
	server.Main(genParams, handleStream)
}

func genParams() server.Params {
	var params server.Params

	flag.StringVar(&params.Addr, "listen", "127.0.0.1:853", "UDP address to listen on.")
	flag.StringVar(&params.TlsCert, "cert", "cert.pem", "TLS certificate path.")
	flag.StringVar(&params.TlsKey, "key", "key.pem", "TLS key path.")

	flag.Parse()

	return params
}

func handleStream(l log.Logger, stream quic.Stream, baton any) error {
	data := make([]byte, 2048)
	n, err := stream.Read(data)
	if err == io.EOF {
		defer stream.Close()
	} else if err != nil {
		return fmt.Errorf("read query: %w", err)
	}

	_, err = stream.Write(data[:n])
	if err != nil {
		return fmt.Errorf("send response: %w", err)
	}
	return nil
}

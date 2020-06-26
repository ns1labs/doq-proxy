package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"sync"

	"github.com/go-kit/kit/log"
	quic "github.com/lucas-clemente/quic-go"
)

func main() {
	l := log.NewLogfmtLogger(log.NewSyncWriter(os.Stdout))
	l = log.WithPrefix(l, "ts", log.DefaultTimestampUTC)

	err := loop(l)
	if err != nil {
		l.Log("msg", "terminating after error", "err", err)
		os.Exit(1)
	}
}

func loop(l log.Logger) error {
	var (
		addr       string
		tlsCert    string
		tlsKey     string
		udpBackend string
	)

	flag.StringVar(&addr, "listen", "127.0.0.1:784", "UDP address to listen on.")
	flag.StringVar(&tlsCert, "cert", "cert.pem", "TLS certificate path.")
	flag.StringVar(&tlsKey, "key", "key.pem", "TLS key path.")
	flag.StringVar(&udpBackend, "udp_backend", "8.8.4.4:53", "UDP of backend server.")

	flag.Parse()

	cert, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
	if err != nil {
		return fmt.Errorf("load certificate: %w", err)
	}

	tls := tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"dq"},
	}
	conf := quic.Config{}

	listener, err := quic.ListenAddr(addr, &tls, &conf)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer listener.Close()

	l.Log("msg", "listening for clients", "addr", addr)

	wg := sync.WaitGroup{}

	for {
		session, err := listener.Accept()
		if err != nil {
			wg.Wait()
			return fmt.Errorf("accept connection: %w", err)
		}

		l := log.With(l, "client", session.RemoteAddr())
		wg.Add(1)
		go func() {
			handleClient(l, session, udpBackend)
			wg.Done()
		}()
	}
}

func handleClient(l log.Logger, session quic.Session, udpBackend string) {
	defer session.Close()
	l.Log("msg", "session accepted")

	wg := sync.WaitGroup{}
	for {
		stream, err := session.AcceptStream()
		if err != nil {
			break
		}

		l := log.With(l, "stream_id", stream.StreamID())
		l.Log("msg", "stream accepted")

		wg.Add(1)
		go func() {
			err := handleStream(stream, udpBackend)
			if err != nil {
				l.Log("msg", "stream failure", "err", err)
			}
			l.Log("msg", "stream closed")
		}()
	}

	wg.Done()
	session.Close()
	l.Log("msg", "session closed")
}

func handleStream(stream quic.Stream, udpBackend string) error {
	defer stream.Close()

	data, err := ioutil.ReadAll(stream)
	if err != nil {
		return fmt.Errorf("read query: %w", err)
	}

	conn, err := net.Dial("udp", udpBackend)
	if err != nil {
		return fmt.Errorf("connect to backend: %w", err)
	}

	_, err = conn.Write(data)
	if err != nil {
		return fmt.Errorf("send query to backend: %w", err)
	}

	buf := make([]byte, 4096)
	size, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("read response from backend: %w", err)
	}
	buf = buf[:size]

	_, err = stream.Write(buf)
	if err != nil {
		return fmt.Errorf("send response: %w", err)
	}
	return nil
}

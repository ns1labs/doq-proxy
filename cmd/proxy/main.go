package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/go-kit/kit/log"
	quic "github.com/lucas-clemente/quic-go"
	"github.com/miekg/dns"
	"github.com/oklog/run"
)

func main() {
	l := log.NewLogfmtLogger(log.NewSyncWriter(os.Stdout))
	l = log.WithPrefix(l, "ts", log.DefaultTimestampUTC)

	var g run.Group

	// proxy code loop
	{
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		g.Add(func() error {
			return loop(l, ctx)
		}, func(error) {
			cancel()
		})
	}

	// signal termination
	{
		sigterm := make(chan os.Signal, 1)
		g.Add(func() error {
			signal.Notify(sigterm, syscall.SIGINT, syscall.SIGTERM)
			if sig, ok := <-sigterm; ok {
				l.Log("msg", "stopping the proxy", "signal", sig.String())
			}
			return nil
		}, func(error) {
			signal.Stop(sigterm)
			close(sigterm)
		})
	}

	err := g.Run()
	if err != nil {
		l.Log("msg", "terminating after error", "err", err)
		os.Exit(1)
	}
}

func loop(l log.Logger, ctx context.Context) error {
	var (
		addr    string
		tlsCert string
		tlsKey  string
		backend string
	)

	flag.StringVar(&addr, "listen", "127.0.0.1:853", "UDP address to listen on.")
	flag.StringVar(&tlsCert, "cert", "cert.pem", "TLS certificate path.")
	flag.StringVar(&tlsKey, "key", "key.pem", "TLS key path.")
	flag.StringVar(&backend, "backend", "8.8.4.4:53", "IP of backend server.")

	flag.Parse()

	cert, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
	if err != nil {
		return fmt.Errorf("load certificate: %w", err)
	}

	tls := tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"doq-i11"},
	}

	listener, err := quic.ListenAddr(addr, &tls, nil)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer listener.Close()

	l.Log("msg", "listening for clients", "addr", addr)

	wg := sync.WaitGroup{}

	for {
		session, err := listener.Accept(ctx)
		if err != nil {
			wg.Wait()
			return fmt.Errorf("accept connection: %w", err)
		}

		l := log.With(l, "client", session.RemoteAddr())
		wg.Add(1)
		go func() {
			handleClient(l, ctx, session, backend)
			wg.Done()
		}()
	}

}

func handleClient(l log.Logger, ctx context.Context, session quic.Connection, backend string) {
	l.Log("msg", "session accepted")

	var (
		err error
		wg  sync.WaitGroup = sync.WaitGroup{}
	)

	defer func() {
		msg := ""
		if err != nil {
			msg = err.Error()
		}
		session.CloseWithError(0, msg)

		l.Log("msg", "session closed")
	}()

	for {
		stream, err := session.AcceptStream(ctx)
		if err != nil {
			break
		}

		l := log.With(l, "stream_id", stream.StreamID())
		l.Log("msg", "stream accepted")

		wg.Add(1)
		go func() {
			defer func() {
				wg.Done()
				l.Log("msg", "stream closed")
			}()

			if err := handleStream(stream, backend); err != nil {
				l.Log("msg", "stream failure", "err", err)
			}
		}()
	}

	wg.Wait()
}

func handleStream(stream quic.Stream, backend string) error {
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

	query := dns.Msg{}
	err = query.Unpack(wireQuery)
	if err != nil {
		return fmt.Errorf("could not decode query: %w", err)
	}

	var id uint16
	err = binary.Read(rand.Reader, binary.BigEndian, &id)
	if err != nil {
		return fmt.Errorf("generating random id failed: %w", err)
	}

	if len(query.Question) != 0 && (query.Question[0].Qtype == dns.TypeAXFR || query.Question[0].Qtype == dns.TypeIXFR) {
		timeout := 3 * time.Second
		conn, err := net.DialTimeout("tcp", backend, timeout)

		if err != nil {
			return fmt.Errorf("connect to TCP backend: %w", err)
		}
		defer conn.Close()

		bundle := make([]byte, 0)
		bundle = append(bundle, wireLength...)
		bundle = append(bundle, wireQuery...)

		binary.BigEndian.PutUint16(bundle[2:], uint16(id))
		_, err = conn.Write(bundle)
		if err != nil {
			return fmt.Errorf("send query to TCP backend: %w", err)
		}

		conn.SetReadDeadline(time.Now().Add(timeout))

		for {
			var length uint16
			if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
				// Ignore timeout related errors as that is how we close the connection for now
				if errors.Is(err, os.ErrDeadlineExceeded) {
					return nil
				}
				return fmt.Errorf("read length from TCP backend: %w", err)
			}

			buf := make([]byte, length)
			_, err := io.ReadFull(conn, buf)
			if err != nil {
				return fmt.Errorf("read response from TCP backend: %w", err)
			}

			bundle := make([]byte, 2+length)
			binary.BigEndian.PutUint16(bundle, uint16(length))
			copy(bundle[2:], buf)
			binary.BigEndian.PutUint16(bundle[2:], uint16(0))
			_, err = stream.Write(bundle)
			if err != nil {
				return fmt.Errorf("send response: %w", err)
			}
		}

	} else {
		conn, err := net.Dial("udp", backend)
		if err != nil {
			return fmt.Errorf("connect to UDP backend: %w", err)
		}

		binary.BigEndian.PutUint16(wireQuery, uint16(id))
		_, err = conn.Write(wireQuery)
		if err != nil {
			return fmt.Errorf("send query to UDP backend: %w", err)
		}

		buf := make([]byte, 4096)
		size, err := conn.Read(buf)
		if err != nil {
			return fmt.Errorf("read response from UDP backend: %w", err)
		}
		buf = buf[:size]

		bundle := make([]byte, 2+len(buf))
		binary.BigEndian.PutUint16(bundle, uint16(len(buf)))
		copy(bundle[2:], buf)
		binary.BigEndian.PutUint16(bundle[2:], uint16(0))

		_, err = stream.Write(bundle)
		if err != nil {
			return fmt.Errorf("send response: %w", err)
		}
	}
	return nil
}

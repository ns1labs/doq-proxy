package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/go-kit/kit/log"
	quic "github.com/lucas-clemente/quic-go"
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
	)

	flag.StringVar(&addr, "listen", "127.0.0.1:853", "UDP address to listen on.")
	flag.StringVar(&tlsCert, "cert", "cert.pem", "TLS certificate path.")
	flag.StringVar(&tlsKey, "key", "key.pem", "TLS key path.")

	flag.Parse()

	cert, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
	if err != nil {
		return fmt.Errorf("load certificate: %w", err)
	}

	tls := tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"doq"},
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
			handleClient(l, ctx, session)
			wg.Done()
		}()
	}

}

func handleClient(l log.Logger, ctx context.Context, session quic.Connection) {
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

			if err := handleStream(stream); err != nil {
				l.Log("msg", "stream failure", "err", err)
			}
		}()
	}

	wg.Wait()
}

func handleStream(stream quic.Stream) error {
	defer stream.Close()

	data, err := io.ReadAll(stream)
	if err != nil {
		return fmt.Errorf("read all: %w", err)
	}

	_, err = stream.Write(data)
	if err != nil {
		return fmt.Errorf("send response: %w", err)
	}
	return nil
}

package server

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/go-kit/log"
	quic "github.com/quic-go/quic-go"
	"github.com/oklog/run"
)

// Adds specific flags for the server type - e.g. proxy takes a string parameter
// containing the backend address. baton is the memory into which the parameters
// are to be stored - the result is then passed to the corresponding
// StreamHandler.
type FlagsGenerator[T any] func(baton *T)

// Handles data for the QUIC stream. The baton parameter is of a server-specific
// type.
type StreamHandler[T any] func(l log.Logger, stream quic.Stream, baton T) error

// Starts the DNS-over-QUIC server. T is the type of parameters for the specific
// server - e.g. proxy has a string parameter containing the backend address.
func Main[T any](flagsGenerator FlagsGenerator[T], sh StreamHandler[T]) {
	l := log.NewLogfmtLogger(log.NewSyncWriter(os.Stdout))
	l = log.WithPrefix(l, "ts", log.DefaultTimestampUTC)

	var group run.Group

	// proxy code loop
	{
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		group.Add(func() error {
			var (
				addr string
				tlsCert string
				tlsKey string
				keyLog string
				baton T
			)

			flag.StringVar(&addr, "listen", "127.0.0.1:853",
				"UDP address to listen on.")
			flag.StringVar(&tlsCert, "cert", "cert.pem",
				"TLS certificate path.")
			flag.StringVar(&tlsKey, "key", "key.pem",
				"TLS key path.")
			flag.StringVar(&keyLog, "keylog", "",
				"TLS key log file (e.g. for Wireshark analysis) - none if empty")
			if flagsGenerator != nil {
				flagsGenerator(&baton)
			}
			flag.Parse()

			return loop(l, ctx, sh, addr, tlsCert, tlsKey, keyLog, baton)
		}, func(error) {
			cancel()
		})
	}

	// signal termination
	{
		sigterm := make(chan os.Signal, 1)
		group.Add(func() error {
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

	err := group.Run()
	if err != nil {
		l.Log("msg", "terminating after error", "err", err)
		os.Exit(1)
	}
}

func loop[T any](l log.Logger, ctx context.Context, sh StreamHandler[T],
                 addr string, tlsCert string, tlsKey string, keyLog string,
                 baton T) error {

	cert, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
	if err != nil {
		return fmt.Errorf("load certificate: %w", err)
	}

	tls := tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"doq"},
		MinVersion:   tls.VersionTLS13,
	}

	if keyLog != "" {
		keyLogFile, err := os.OpenFile(keyLog, os.O_APPEND | os.O_CREATE | os.O_WRONLY, 0755)
		if err != nil {
			return fmt.Errorf("open keylog file: %w", err)
		}
		defer keyLogFile.Close()
		tls.KeyLogWriter = keyLogFile
	}


	quic_conf := quic.Config{
		MaxIdleTimeout: 10 * time.Second,
		Allow0RTT: true,
	}

	listener, err := quic.ListenAddrEarly(addr, &tls, &quic_conf)
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
			handleClient(l, ctx, session, sh, baton)
			wg.Done()
		}()
	}
}

func handleClient[T any](l log.Logger, ctx context.Context,
                         session quic.Connection, sh StreamHandler[T],
                         baton T) {
	l.Log("msg", "session accepted")

	var (
		err error
		wg  sync.WaitGroup = sync.WaitGroup{}
	)

	defer func() {
		msg := ""
		if err != nil {
			msg = err.Error()
			l.Log("msg", "session failure", "err", err)
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

			if err := sh(l, stream, baton); err != nil {
				l.Log("msg", "stream failure", "err", err)
			}
		}()
	}

	wg.Wait()
}

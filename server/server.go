package server

import (
	"context"
	"crypto/tls"
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

type Params struct {
	Addr string
	TlsCert string
	TlsKey string
	Baton any
}

type ParamsGenerator func() Params
type StreamHandler func(l log.Logger, stream quic.Stream, baton any) error

func Main(pg ParamsGenerator, sh StreamHandler) {
	l := log.NewLogfmtLogger(log.NewSyncWriter(os.Stdout))
	l = log.WithPrefix(l, "ts", log.DefaultTimestampUTC)

	var g run.Group

	// proxy code loop
	{
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		g.Add(func() error {
			params := pg()
			return loop(l, ctx, sh, params.Addr, params.TlsCert,
					params.TlsKey, params.Baton)
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

func loop(l log.Logger, ctx context.Context, sh StreamHandler,
          addr string, tlsCert string, tlsKey string,
          baton any) error {

	cert, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
	if err != nil {
		return fmt.Errorf("load certificate: %w", err)
	}

	tls := tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"doq"},
		MinVersion:   tls.VersionTLS13,
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

func handleClient(l log.Logger, ctx context.Context, session quic.Connection,
                  sh StreamHandler, baton any) {

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

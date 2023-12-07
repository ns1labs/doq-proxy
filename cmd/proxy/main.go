package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/go-kit/log"
	quic "github.com/quic-go/quic-go"
	"github.com/miekg/dns"

	"github.com/ns1/doq-proxy/server"
)

func main() {
	server.Main(genFlags, handleStream)
}

func genFlags(backend *string) {
	flag.StringVar(backend, "backend", "8.8.4.4:53", "IP of backend server.")
}

func handleStream(l log.Logger, stream quic.Stream, backend string) error {
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

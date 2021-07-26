package main

import (
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"sync"

	"github.com/lucas-clemente/quic-go"
	"github.com/miekg/dns"
)

type Query struct {
	Name string
	Type uint16
}

func main() {
	var (
		server    string
		dnssec    bool
		recursion bool
		queries   []Query
	)

	flag.Usage = func() {
		fmt.Printf("usage: %s <options> (<qname> <qtype>)...\n\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.StringVar(&server, "server", "127.0.0.1:8853", "DNS-over-QUIC server to use.")
	flag.BoolVar(&dnssec, "dnssec", true, "Send DNSSEC OK flag.")
	flag.BoolVar(&recursion, "recursion", true, "Send RD flag.")
	flag.Parse()

	if flag.NArg() == 0 || flag.NArg()%2 != 0 {
		flag.Usage()
		os.Exit(1)
	}

	for i := 0; (i + 1) < flag.NArg(); i += 2 {
		qname := dns.Fqdn(flag.Arg(i))
		qtype, ok := dns.StringToType[flag.Arg(i+1)]
		if !ok {
			fmt.Fprintf(os.Stderr, "invalid qtype: %s\n", flag.Arg(i+1))
			os.Exit(1)
		}

		queries = append(queries, Query{qname, qtype})
	}

	// TODO: make user explicitly request this!!!
	w, err := os.OpenFile("tls-secrets.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)

	tls := tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"doq-i03"},
		KeyLogWriter:       w,
	}
	session, err := quic.DialAddr(server, &tls, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to connect to the server: %s\n", err)
		os.Exit(1)
	}
	defer session.CloseWithError(0, "") // TODO: Is this how the session should be closed?

	print := make(chan string)

	wg := sync.WaitGroup{}
	wg.Add(len(queries))

	for _, query := range queries {
		go func(query Query) {
			resp, err := SendQuery(session, &query, dnssec, recursion)
			if err != nil {
				print <- fmt.Sprintf("failed to send query: %s\n", err)
			} else {
				print <- resp.String()
			}
			wg.Done()
		}(query)
	}

	go func() {
		wg.Wait()
		close(print)
	}()

	for p := range print {
		fmt.Println(p)
	}
}

func SendQuery(session quic.Session, query *Query, dnssec, recursion bool) (*dns.Msg, error) {
	stream, err := session.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("open stream: %w", err)
	}

	msg := dns.Msg{}
	msg.SetQuestion(query.Name, query.Type)
	msg.RecursionDesired = recursion
	msg.SetEdns0(4096, dnssec)
	msg.Id = 0
	wire, err := msg.Pack()
	if err != nil {
		stream.Close()
		return nil, fmt.Errorf("pack query: %w", err)
	}

	bundle := make([]byte, 2+len(wire))
	binary.BigEndian.PutUint16(bundle, uint16(len(wire)))
	copy(bundle[2:], wire)
	_, err = stream.Write(bundle)
	stream.Close()
	if err != nil {
		return nil, fmt.Errorf("send query: %w", err)
	}

	rwire, err := ioutil.ReadAll(stream)
	if err != nil {
		return nil, fmt.Errorf("receive response: %w", err)
	}

	len := binary.BigEndian.Uint16(rwire)
	rmsg := make([]byte, len)
	copy(rmsg, rwire[2:])

	err = msg.Unpack(rmsg)
	if err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &msg, nil
}

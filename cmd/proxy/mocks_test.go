package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/miekg/dns"
)

var ErrUnimplementedMock error = errors.New("unimplemented")

// MockQUICStream satisfies the quic.Stream interface
type MockQUICStream struct {
	ID quic.StreamID

	// InBuf holds the packed msg bytes coming in from the client
	InBuf []byte
	// OutBuf holds the packed msg bytes coming in from the backend (and out to client)
	OutBuf []byte

	Recursion bool

	msg *dns.Msg
}

func NewMockQUICStream(id int, name, qType string, recursion bool, dnssec bool) *MockQUICStream {
	qt, ok := dns.StringToType[qType]
	if !ok {
		panic("invalid qtype: " + qType)
	}

	msg := &dns.Msg{}
	msg.SetQuestion(dns.Fqdn(name), qt)
	msg.RecursionDesired = recursion
	msg.SetEdns0(4096, dnssec)

	wire, err := msg.Pack()
	if err != nil {
		panic(fmt.Errorf("pack query: %w", err))
	}

	return &MockQUICStream{
		ID:     quic.StreamID(id),
		InBuf:  wire,
		OutBuf: make([]byte, 4096),

		msg: msg,
	}
}

func (mqs *MockQUICStream) GetMsg() *dns.Msg {
	return mqs.msg
}

// ************************************
// quic.ReceiveStream interface methods
// ************************************

// StreamID returns the stream ID.
func (mqs *MockQUICStream) StreamID() quic.StreamID {
	return mqs.ID
}

// Read reads data from the stream.
// Read can be made to time out and return a net.Error with Timeout() == true
// after a fixed time limit; see SetDeadline and SetReadDeadline.
// If the stream was canceled by the peer, the error implements the StreamError
// interface, and Canceled() == true.
// If the session was closed due to a timeout, the error satisfies
// the net.Error interface, and Timeout() will be true.
func (mqs *MockQUICStream) Read(buf []byte) (int, error) {
	if mqs.InBuf == nil {
		return 0, io.EOF
	}

	return copy(buf, mqs.InBuf), io.EOF
}

// CancelRead aborts receiving on this stream.
// It will ask the peer to stop transmitting stream data.
// Read will unblock immediately, and future Read calls will fail.
// When called multiple times or after reading the io.EOF it is a no-op.
func (mqs *MockQUICStream) CancelRead(quic.ErrorCode) {}

func (mqs *MockQUICStream) SetReadDeadline(t time.Time) error {
	return ErrUnimplementedMock
}

// *********************************
// quic.SendStream interface methods
// *********************************

// Write writes data to the stream.
// Write can be made to time out and return a net.Error with Timeout() == true
// after a fixed time limit; see SetDeadline and SetWriteDeadline.
// If the stream was canceled by the peer, the error implements the StreamError
// interface, and Canceled() == true.
// If the session was closed due to a timeout, the error satisfies
// the net.Error interface, and Timeout() will be true.
func (mqs *MockQUICStream) Write(p []byte) (int, error) {
	mqs.OutBuf = make([]byte, len(p))

	return copy(mqs.OutBuf, p), nil
}

// Close closes the write-direction of the stream.
// Future calls to Write are not permitted after calling Close.
// It must not be called concurrently with Write.
// It must not be called after calling CancelWrite.
func (mqs *MockQUICStream) Close() error {
	return nil
}

// The context is canceled as soon as the write-side of the stream is closed.
// This happens when Close() or CancelWrite() is called, or when the peer
// cancels the read-side of their stream.
// Warning: This API should not be considered stable and might change soon.
func (mqs *MockQUICStream) Context() context.Context {
	panic(ErrUnimplementedMock)
}

// CancelWrite aborts sending on this stream.
// Data already written, but not yet delivered to the peer is not guaranteed to be delivered reliably.
// Write will unblock immediately, and future calls to Write will fail.
// When called multiple times or after closing the stream it is a no-op.
func (mqs *MockQUICStream) CancelWrite(quic.ErrorCode) {}

// SetWriteDeadline sets the deadline for future Write calls
// and any currently-blocked Write call.
// Even if write times out, it may return n > 0, indicating that
// some of the data was successfully written.
// A zero value for t means Write will not time out.
func (mqs *MockQUICStream) SetWriteDeadline(t time.Time) error {
	return ErrUnimplementedMock
}

// *****************************
// quic.Stream interface methods
// *****************************

// SetDeadline sets the read and write deadlines associated
// with the connection. It is equivalent to calling both
// SetReadDeadline and SetWriteDeadline.
func (mqs *MockQUICStream) SetDeadline(t time.Time) error {
	return ErrUnimplementedMock
}

// MockQUICSession satisfies the quic.Session interface
type MockQUICSession struct {
	Streams []*MockQUICStream

	accepted int

	closingErrorCode   quic.ErrorCode
	closingErrorString string
}

// ******************************
// quic.Session interface methods
// ******************************

// AcceptStream returns the next stream opened by the peer, blocking until one is available.
// If the session was closed due to a timeout, the error satisfies
// the net.Error interface, and Timeout() will be true.
func (mqs *MockQUICSession) AcceptStream(context.Context) (quic.Stream, error) {
	if len(mqs.Streams) <= mqs.accepted {
		return nil, errors.New("no more streams")
	}

	defer func() {
		mqs.accepted++
	}()

	return mqs.Streams[mqs.accepted], nil
}

// AcceptUniStream returns the next unidirectional stream opened by the peer, blocking until one is available.
// If the session was closed due to a timeout, the error satisfies
// the net.Error interface, and Timeout() will be true.
func (mqs *MockQUICSession) AcceptUniStream(context.Context) (quic.ReceiveStream, error) {
	return nil, ErrUnimplementedMock
}

// OpenStream opens a new bidirectional QUIC stream.
// There is no signaling to the peer about new streams:
// The peer can only accept the stream after data has been sent on the stream.
// If the error is non-nil, it satisfies the net.Error interface.
// When reaching the peer's stream limit, err.Temporary() will be true.
// If the session was closed due to a timeout, Timeout() will be true.
func (mqs *MockQUICSession) OpenStream() (quic.Stream, error) {
	return nil, ErrUnimplementedMock
}

// OpenStreamSync opens a new bidirectional QUIC stream.
// If the error is non-nil, it satisfies the net.Error interface.
// If the session was closed due to a timeout, Timeout() will be true.
// It blocks until a new stream can be opened.
func (mqs *MockQUICSession) OpenStreamSync(context.Context) (quic.Stream, error) {
	return nil, ErrUnimplementedMock
}

// OpenUniStream opens a new outgoing unidirectional QUIC stream.
// If the error is non-nil, it satisfies the net.Error interface.
// When reaching the peer's stream limit, Temporary() will be true.
// If the session was closed due to a timeout, Timeout() will be true.
func (mqs *MockQUICSession) OpenUniStream() (quic.SendStream, error) {
	return nil, ErrUnimplementedMock
}

// OpenUniStreamSync opens a new outgoing unidirectional QUIC stream.
// It blocks until a new stream can be opened.
// If the error is non-nil, it satisfies the net.Error interface.
// If the session was closed due to a timeout, Timeout() will be true.
func (mqs *MockQUICSession) OpenUniStreamSync(context.Context) (quic.SendStream, error) {
	return nil, ErrUnimplementedMock
}

// LocalAddr returns the local address.
func (mqs *MockQUICSession) LocalAddr() net.Addr {
	return nil
}

// RemoteAddr returns the address of the peer.
func (mqs *MockQUICSession) RemoteAddr() net.Addr {
	return nil
}

// Close the connection with an error.
// The error string will be sent to the peer.
func (mqs *MockQUICSession) CloseWithError(code quic.ErrorCode, msg string) error {
	mqs.closingErrorCode = code
	mqs.closingErrorString = msg

	return nil
}

// The context is cancelled when the session is closed.
// Warning: This API should not be considered stable and might change soon.
func (mqs *MockQUICSession) Context() context.Context {
	return nil
}

// ConnectionState returns basic details about the QUIC connection.
// It blocks until the handshake completes.
// Warning: This API should not be considered stable and might change soon.
func (mqs *MockQUICSession) ConnectionState() quic.ConnectionState {
	return quic.ConnectionState{}
}

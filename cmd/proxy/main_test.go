package main

import (
	"context"
	"os"
	"testing"

	"github.com/go-kit/kit/log"
)

func TestHandleClient_Positive(t *testing.T) {
	type subtest struct {
		name    string
		backend string

		// One stream per query
		streams []*MockQUICStream
	}

	subtests := []*subtest{
		{
			name:    "recursive_A",
			backend: "8.8.4.4:53",
			streams: []*MockQUICStream{
				NewMockQUICStream(0, "ns1.com", "A", true, false),
			},
		},
	}

	for _, st := range subtests {
		t.Run(st.name, func(tt *testing.T) {
			ms := &MockQUICSession{
				Streams: st.streams,
			}

			ctx := context.Background()
			l := log.NewLogfmtLogger(log.NewSyncWriter(os.Stdout))
			l = log.WithPrefix(l, "ts", log.DefaultTimestampUTC)

			handleClient(l, ctx, ms, st.backend)

			for _, stream := range ms.Streams {
				if len(stream.OutBuf) == 0 {
					t.Errorf("received empty response")
				}

				msg := stream.GetMsg()

				if err := msg.Unpack(stream.OutBuf); err != nil {
					t.Error(err)
				}

				if len(msg.Answer) == 0 {
					t.Errorf("received no answers: %s", msg)
				}
			}
		})
	}
}

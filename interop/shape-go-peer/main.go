// Command shape-go-peer is the Go side of tests/test_shaping_interop.py, with
// the contract of tests/shape_peer.py:
//
//	shape-go-peer server        listens on 127.0.0.1:0, prints "LISTEN addr"
//	shape-go-peer client ADDR   opens 8 streams, each echoed back
//
// SHAPE_DEF names a shaping definition (JSON) applied to the session's
// outbound pipes. At the end each side prints
// "STATS padding=.. injected=.. dropped=.. clamped=.. faults=.." and "OK"; a
// shaped side fails unless it added wire bytes and recorded no fault.
package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"sync"
	"time"

	zmux "github.com/zmuxio/zmux-go"
	"github.com/zmuxio/zmux-go/shaping/machine"
)

const streams = 8

func die(f string, a ...any) {
	fmt.Fprintf(os.Stderr, f+"\n", a...)
	os.Exit(1)
}

func payload(i int) []byte {
	b := make([]byte, 200_000+i*7919)
	rand.New(rand.NewSource(int64(i))).Read(b)
	return b
}

func shape(c *zmux.Conn) {
	p := os.Getenv("SHAPE_DEF")
	if p == "" {
		return
	}
	b, err := os.ReadFile(p)
	if err != nil {
		die("%v", err)
	}
	f, err := machine.NewFactory(b, machine.Options{})
	if err != nil {
		die("def: %v", err)
	}
	c.SetShaper(f, nil)
}

func report(c *zmux.Conn) {
	st := c.ShapingStats()
	fmt.Printf("STATS padding=%d injected=%d dropped=%d clamped=%d faults=%d\n",
		st.WireSpent, st.Injected, st.InjectDropped, st.Clamped, st.Faults)
	if os.Getenv("SHAPE_DEF") != "" && (st.WireSpent == 0 || st.Faults != 0) {
		die("not shaped")
	}
}

func server(ctx context.Context) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		die("%v", err)
	}
	fmt.Println("LISTEN", ln.Addr())
	nc, err := ln.Accept()
	if err != nil {
		die("%v", err)
	}
	c, err := zmux.Server(ctx, nc, &zmux.Config{})
	if err != nil {
		die("%v", err)
	}
	shape(c)
	var wg sync.WaitGroup
	for range streams {
		s, err := c.AcceptStream(ctx)
		if err != nil {
			die("accept: %v", err)
		}
		wg.Go(func() {
			b, err := io.ReadAll(s)
			if err != nil {
				die("read: %v", err)
			}
			if _, err := s.Write(b); err != nil {
				die("write: %v", err)
			}
			s.Close()
		})
	}
	wg.Wait()
	<-c.Context().Done()
	report(c)
	fmt.Println("OK")
}

func client(ctx context.Context, addr string) {
	nc, err := net.Dial("tcp", addr)
	if err != nil {
		die("%v", err)
	}
	c, err := zmux.Client(ctx, nc, &zmux.Config{})
	if err != nil {
		die("%v", err)
	}
	shape(c)
	var wg sync.WaitGroup
	for i := range streams {
		wg.Go(func() {
			s, err := c.OpenStreamSync(ctx)
			if err != nil {
				die("open: %v", err)
			}
			p := payload(i)
			go func() {
				s.Write(p)
				s.Close()
			}()
			b, err := io.ReadAll(s)
			if err != nil || !bytes.Equal(b, p) {
				die("stream %d: %v, %d of %d bytes", i, err, len(b), len(p))
			}
		})
	}
	wg.Wait()
	time.Sleep(300 * time.Millisecond) // injections run on a timer
	report(c)
	c.Close()
	fmt.Println("OK")
}

func main() {
	time.AfterFunc(60*time.Second, func() { die("deadline") })
	ctx := context.Background()
	switch {
	case len(os.Args) == 2 && os.Args[1] == "server":
		server(ctx)
	case len(os.Args) == 3 && os.Args[1] == "client":
		client(ctx, os.Args[2])
	default:
		die("usage: shape-go-peer server | client ADDR")
	}
}

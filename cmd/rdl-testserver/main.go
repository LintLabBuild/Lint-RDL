// Command rdl-testserver runs the misbehaving test server by hand, e.g.
//
//	rdl-testserver -size 100MB -cut 5MB
//	rdl allow-private add 127.0.0.1   # at the PC, for local testing only
//	rdl get http://127.0.0.1:PORT/file.bin
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/lintlabbuild/lint-rdl/internal/config"
	"github.com/lintlabbuild/lint-rdl/testserver"
)

func main() {
	size := flag.String("size", "64MB", "file size")
	var o testserver.Options
	cut := flag.String("cut", "0", "close the connection after this many bytes per request")
	stall := flag.String("stall", "0", "hang after this many bytes per request")
	flag.BoolVar(&o.IgnoreRange, "ignore-range", false, "answer 200 to range requests")
	flag.BoolVar(&o.WrongContentRange, "wrong-range", false, "send a wrong Content-Range start")
	flag.IntVar(&o.ChangeAfter, "change-after", 0, "change the file after N GETs")
	flag.BoolVar(&o.Gzip, "gzip", false, "gzip the body regardless of Accept-Encoding")
	flag.BoolVar(&o.NoLength, "no-length", false, "stream without Content-Length")
	flag.BoolVar(&o.NoValidators, "no-validators", false, "send no ETag/Last-Modified")
	flag.IntVar(&o.BusyFirst, "busy", 0, "first N GETs answer 429")
	flag.BoolVar(&o.HTMLError, "html", false, "answer with an HTML page")
	flag.Parse()
	n, err := config.ParseSize(*size)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	o.CutEvery, _ = config.ParseSize(*cut)
	o.StallAfter, _ = config.ParseSize(*stall)
	content := testserver.Content(int(n), 1)
	s := testserver.New(content, o)
	defer s.Close()
	fmt.Printf("serving %d bytes at %s (also /redirect, /sign)\nsha256 %s\n", n, s.FileURL(), testserver.SHA256(content))
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
}

package worker

import (
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dwnGnL/testHandler/pkg/pretty"
)

// Job convert function to param
type Job func()

// Start worker scedule. Every dur seconds it will request
// new payment from db. Receive as param db - database
// job - function
func Start(job Job, dur int64) {
	var q chan os.Signal
	q = make(chan os.Signal, 1)
	signal.Notify(q, syscall.SIGINT, syscall.SIGTERM)
	for {
		select {
		case sig := <-q:
			pretty.Logln("received exit worker signal:", sig)
			return
		default:
			job()
			time.Sleep(time.Duration(dur) * time.Second)
		}

	}
}

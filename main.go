package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/dwnGnL/testHandler/db"
	"github.com/dwnGnL/testHandler/pkg/logging"
	"github.com/dwnGnL/testHandler/pkg/pretty"
	"github.com/dwnGnL/testHandler/pkg/setting"
	"github.com/dwnGnL/testHandler/routes"
)

var wg sync.WaitGroup

func init() {
	setting.Setup("config/config.json")
	logging.Setup()
	db.Setup()
	routes.Setup(&wg)
}

func startJobs() {
	// go worker.Start(routes.RetryPayments, setting.Config.AppConf.RetryTimeout)  //TODO: После запуска запустить умершие платежи
}

func main() {
	pretty.Logln("[MAIN] Work has started!")
	defer deferFunc()
	routers := routes.Init()
	endPoint := fmt.Sprintf(":%d", setting.Config.AppConf.Port)
	maxHeaderBytes := 1 << 20

	server := &http.Server{
		Addr:           endPoint,
		Handler:        routers,
		ReadTimeout:    time.Duration(30) * time.Second,
		WriteTimeout:   time.Duration(30) * time.Second,
		MaxHeaderBytes: maxHeaderBytes,
	}

	pretty.Logf("start http -testHandler- server listening %s", endPoint)

	go func() {
		// service connections
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			pretty.LoglnFatal("listen:", err)
		}
	}()

	quit := make(chan os.Signal, 1)

	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	fmt.Println("Shutdown Server ...")
	pretty.Logln("Shutdown Server ...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

	if err := server.Shutdown(ctx); err != nil {
		pretty.LoglnFatal("Server Shutdown:", err)
	}

	// catching ctx.Done(). timeout of 5 seconds.
	<-ctx.Done()

	cancel()
	wg.Wait()
}

func deferFunc() {
	pretty.Logln("[MAIN] Work has stopped!")
	db.CloseDB()
}

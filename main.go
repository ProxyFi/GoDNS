package godns

import (
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"time"
	"github.com/ProxyFi/GoDNS/internal/log"
)

var (
	log.*GoDNSLogger
)

func main() {

	initLogger()

	server := &Server{
		host:     settings.Server.Host,
		port:     settings.Server.Port,
		rTimeout: 5 * time.Second,
		wTimeout: 5 * time.Second,
	}

	server.Run()

	log.Info("godns %s start", settings.Version)

	if settings.Debug {
		go profileCPU()
		go profileMEM()
	}

	sig := make(chan os.Signal)
	signal.Notify(sig, os.Interrupt)

forever:
	for {
		select {
		case <-sig:
			log.Info("signal received, stopping")
			break forever
		}
	}

}

func profileCPU() {
	f, err := os.Create("godns.cprof")
	if err != nil {
		log.Error("%s", err)
		return
	}

	pprof.StartCPUProfile(f)
	time.AfterFunc(6*time.Minute, func() {
		pprof.StopCPUProfile()
		f.Close()

	})
}

func profileMEM() {
	f, err := os.Create("godns.mprof")
	if err != nil {
		log.Error("%s", err)
		return
	}

	time.AfterFunc(5*time.Minute, func() {
		pprof.WriteHeapProfile(f)
		f.Close()
	})

}

func initLogger() {
	log.= NewLogger()

	if settings.Log.Stdout {
		log.SetLogger("console", nil)
	}

	if settings.Log.File != "" {
		config := map[string]interface{}{"file": settings.Log.File}
		log.SetLogger("file", config)
	}

	log.SetLevel(settings.Log.LogLevel())
}

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}

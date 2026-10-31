package log

import (
	"fmt"
	"os"
	"sync/atomic"

	"github.com/metacubex/mihomo/common/observable"
	"github.com/metacubex/mihomo/constant/features"

	log "github.com/sirupsen/logrus"
)

var (
	logCh  = make(chan Event)
	source = observable.NewObservable[Event](logCh)
	level  = INFO
)

func init() {
	log.SetOutput(os.Stdout)
	log.SetLevel(log.DebugLevel)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:             true,
		TimestampFormat:           "2006-01-02T15:04:05.000000000Z07:00",
		EnvironmentOverrideColors: true,
	})
}

type Event struct {
	LogLevel LogLevel
	Payload  string
}

func (e *Event) Type() string {
	return e.LogLevel.String()
}

func Infoln(format string, v ...any) {
	if !enabled(INFO) {
		return
	}
	event := newLog(INFO, format, v...)
	logCh <- event
	print(event)
}

func Warnln(format string, v ...any) {
	if !enabled(WARNING) {
		return
	}
	event := newLog(WARNING, format, v...)
	logCh <- event
	print(event)
}

func Errorln(format string, v ...any) {
	if !enabled(ERROR) {
		return
	}
	event := newLog(ERROR, format, v...)
	logCh <- event
	print(event)
}

func Debugln(format string, v ...any) {
	if !enabled(DEBUG) {
		return
	}
	event := newLog(DEBUG, format, v...)
	logCh <- event
	print(event)
}

func Fatalln(format string, v ...any) {
	log.Fatalf(format, v...)
}

func Subscribe() observable.Subscription[Event] {
	sub, _ := source.Subscribe()
	return sub
}

func UnSubscribe(sub observable.Subscription[Event]) {
	source.UnSubscribe(sub)
}

func Level() LogLevel {
	return level
}

func SetLevel(newLevel LogLevel) {
	level = newLevel
}

// gated, wanted: see SetGated.
var (
	gated  atomic.Bool
	wanted [SILENT]atomic.Int32
)

// SetGated makes events below the level nobody reads skip formatting and
// delivery altogether, in a core built with the with_powersave tag. Off by
// default, as every event has always reached every subscriber whatever the
// level, and a subscriber may rely on that (a log file that records debug
// while the config says info). A host turning it
// on promises that its own subscribers only read from Level() up, or ask
// for more with Want; the controller's /logs does.
//
// It matters on a phone: at debug, as some subscriptions ship, every
// connection is formatted a few times over, and the formatting alone is most
// of the logging cost even when no one reads it.
func SetGated(on bool) {
	gated.Store(on && features.WithPowerSave)
}

// Want makes events from l up be produced while the returned release is not
// called, whatever the level and the gate.
func Want(l LogLevel) (release func()) {
	if l < DEBUG || l >= SILENT {
		return func() {}
	}
	wanted[l].Add(1)
	var once atomic.Bool
	return func() {
		if once.CompareAndSwap(false, true) {
			wanted[l].Add(-1)
		}
	}
}

func enabled(l LogLevel) bool {
	if l >= level || !gated.Load() {
		return true
	}
	for w := DEBUG; w <= l; w++ {
		if wanted[w].Load() > 0 {
			return true
		}
	}
	return false
}

func print(data Event) {
	if data.LogLevel < level {
		return
	}

	switch data.LogLevel {
	case INFO:
		log.Infoln(data.Payload)
	case WARNING:
		log.Warnln(data.Payload)
	case ERROR:
		log.Errorln(data.Payload)
	case DEBUG:
		log.Debugln(data.Payload)
	}
}

func newLog(logLevel LogLevel, format string, v ...any) Event {
	return Event{
		LogLevel: logLevel,
		Payload:  fmt.Sprintf(format, v...),
	}
}

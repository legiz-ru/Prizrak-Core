package log

import (
	"context"
	"fmt"

	L "github.com/metacubex/sing/common/logger"
)

type singLogger struct{}

func (l singLogger) TraceContext(ctx context.Context, args ...any) {
	if !enabled(DEBUG) {
		return
	}
	Debugln(fmt.Sprint(args...))
}

func (l singLogger) DebugContext(ctx context.Context, args ...any) {
	if !enabled(DEBUG) {
		return
	}
	Debugln(fmt.Sprint(args...))
}

func (l singLogger) InfoContext(ctx context.Context, args ...any) {
	if !enabled(INFO) {
		return
	}
	Infoln(fmt.Sprint(args...))
}

func (l singLogger) WarnContext(ctx context.Context, args ...any) {
	if !enabled(WARNING) {
		return
	}
	Warnln(fmt.Sprint(args...))
}

func (l singLogger) ErrorContext(ctx context.Context, args ...any) {
	if !enabled(ERROR) {
		return
	}
	Errorln(fmt.Sprint(args...))
}

func (l singLogger) FatalContext(ctx context.Context, args ...any) {
	Fatalln(fmt.Sprint(args...))
}

func (l singLogger) PanicContext(ctx context.Context, args ...any) {
	Fatalln(fmt.Sprint(args...))
}

func (l singLogger) Trace(args ...any) {
	if !enabled(DEBUG) {
		return
	}
	Debugln(fmt.Sprint(args...))
}

func (l singLogger) Debug(args ...any) {
	if !enabled(DEBUG) {
		return
	}
	Debugln(fmt.Sprint(args...))
}

func (l singLogger) Info(args ...any) {
	if !enabled(INFO) {
		return
	}
	Infoln(fmt.Sprint(args...))
}

func (l singLogger) Warn(args ...any) {
	if !enabled(WARNING) {
		return
	}
	Warnln(fmt.Sprint(args...))
}

func (l singLogger) Error(args ...any) {
	if !enabled(ERROR) {
		return
	}
	Errorln(fmt.Sprint(args...))
}

func (l singLogger) Fatal(args ...any) {
	Fatalln(fmt.Sprint(args...))
}

func (l singLogger) Panic(args ...any) {
	Fatalln(fmt.Sprint(args...))
}

type singInfoToDebugLogger struct {
	singLogger
}

func (l singInfoToDebugLogger) InfoContext(ctx context.Context, args ...any) {
	if !enabled(DEBUG) {
		return
	}
	Debugln(fmt.Sprint(args...))
}

func (l singInfoToDebugLogger) Info(args ...any) {
	if !enabled(DEBUG) {
		return
	}
	Debugln(fmt.Sprint(args...))
}

var SingLogger L.ContextLogger = singLogger{}
var SingInfoToDebugLogger L.ContextLogger = singInfoToDebugLogger{}

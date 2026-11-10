package xdrive

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/metacubex/mihomo/log"
)

// xerror keeps the shape of the errors of Xray-core's common/errors, which
// the transport is ported from: a message and an optional cause.
type xerror struct {
	msg  string
	base error
}

func newError(parts ...interface{}) *xerror {
	return &xerror{msg: concat(parts)}
}

func (e *xerror) Base(err error) *xerror {
	e.base = err
	return e
}

func (e *xerror) Error() string {
	if e.base != nil {
		return e.msg + " > " + e.base.Error()
	}
	return e.msg
}

func (e *xerror) Unwrap() error {
	return e.base
}

func concat(parts []interface{}) string {
	var b strings.Builder
	for _, part := range parts {
		fmt.Fprint(&b, part)
	}
	return b.String()
}

// sanitize drops the URL out of a url.Error: a template can carry a secret in
// its query or path, and the error of a request reaches the logs.
func sanitize(err error) error {
	if urlErr, ok := err.(*url.Error); ok && urlErr.Err != nil {
		return urlErr.Err
	}
	return err
}

func logInfo(_ context.Context, parts ...interface{}) {
	log.Infoln("[XDRIVE] %s", concat(parts))
}

func logDebug(_ context.Context, parts ...interface{}) {
	log.Debugln("[XDRIVE] %s", concat(parts))
}

func logWarning(_ context.Context, parts ...interface{}) {
	log.Warnln("[XDRIVE] %s", concat(parts))
}

func logWarningInner(_ context.Context, err error, parts ...interface{}) {
	log.Warnln("[XDRIVE] %s > %v", concat(parts), sanitize(err))
}

func logError(_ context.Context, err error) {
	log.Errorln("[XDRIVE] %v", sanitize(err))
}

package zhttp

import (
	"context"
	"fmt"
	stdlog "log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/sassoftware/relic/v7/internal/logrotate"
)

type ctxKey int

var (
	ctxAccessCallbacks ctxKey = 1
	ctxDontLog         ctxKey = 2
)

const rfc3339Milli = "2006-01-02T15:04:05.000Z07:00" // RFC3339 with 3 decimal places, padded

// SetupLogging initializes zerolog with reasonable defaults
func SetupLogging(levelName, logFile string) error {
	zerolog.TimeFieldFormat = rfc3339Milli
	zerolog.DurationFieldInteger = true
	switch logFile {
	case "-":
		// write JSON to stderr
	case "":
		// write pretty text to stderr
		log.Logger = log.Logger.Output(zerolog.ConsoleWriter{
			Out:        os.Stderr,
			TimeFormat: "15:04:05",
		})
	default:
		// write JSON to file
		w, err := logrotate.NewWriter(logFile)
		if err != nil {
			return fmt.Errorf("log_file: %w", err)
		}
		log.Logger = log.Logger.Output(w)
	}
	// set default log level
	if levelName == "" {
		levelName = zerolog.InfoLevel.String()
	}
	level, err := zerolog.ParseLevel(levelName)
	if err != nil {
		return fmt.Errorf("log_level: %w", err)
	}
	log.Logger = log.Logger.Level(level)
	// pass stdlib logger through
	stdlog.SetFlags(0)
	stdlog.SetOutput(log.Logger)
	return nil
}

// LoggingMiddleware creates a logging context for each request, and emits an
// access log entry at the completion of the request.
func LoggingMiddleware(opts ...LoggingOption) func(http.Handler) http.Handler {
	cfg := loggingConfig{
		logger: log.Logger,
		now:    time.Now,
	}
	for _, o := range opts {
		o(&cfg)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			// Make a new log context for the scope of the request with basic
			// request metadata suitable for every log entry
			lc := cfg.logger.With().
				Str("ip", StripPort(req.RemoteAddr)).
				Str("req_id", req.Header.Get("X-Request-Id"))
			// build request context and execute the next handler
			baseLogger := lc.Logger()
			ctx := req.Context()
			ctx = baseLogger.WithContext(ctx)
			var callbacks []AccessLogCallback
			var dontLog bool
			ctx = context.WithValue(ctx, ctxAccessCallbacks, &callbacks)
			ctx = context.WithValue(ctx, ctxDontLog, &dontLog)
			start := cfg.now()
			lw := &Logger{
				ResponseWriter: rw,
				Now:            cfg.now,
			}
			req = req.WithContext(ctx)
			next.ServeHTTP(lw, req)
			// emit the access log entry
			if !dontLog {
				// Logger.WithContext makes a copy of the logger to put into
				// ctx, so make sure we use that as a base to get the effects of
				// any UpdateContext calls from inside the view funcs.
				logger := zerolog.Ctx(ctx)
				ev := logger.Info().
					Str("method", req.Method).
					Stringer("url", req.URL).
					Int("status", lw.Status()).
					Int64("len", lw.Length()).
					Dur("dur", cfg.now().Sub(start)).
					Dur("ttfb", lw.Started().Sub(start)).
					Str("ua", req.UserAgent())
				for _, cb := range callbacks {
					cb(ev)
				}
				ev.Send()
			}
		})
	}
}

type AccessLogCallback func(*zerolog.Event)

// AppendAccessLog adds a callback function which will be invoked to amend the
// access log with additional fields.
func AppendAccessLog(req *http.Request, f AccessLogCallback) {
	AppendAccessLogContext(req.Context(), f)
}

// AppendAccessLog adds a callback function which will be invoked to amend the
// access log with additional fields.
func AppendAccessLogContext(ctx context.Context, f AccessLogCallback) {
	callbacks, _ := ctx.Value(ctxAccessCallbacks).(*[]AccessLogCallback)
	if callbacks != nil {
		*callbacks = append(*callbacks, f)
	}
}

// DontLog marks that the current request should not generate an access log
// entry
func DontLog(req *http.Request) {
	dontLog, _ := req.Context().Value(ctxDontLog).(*bool)
	if dontLog != nil {
		*dontLog = true
	}
}

type loggingConfig struct {
	logger zerolog.Logger
	now    func() time.Time
}

type LoggingOption func(*loggingConfig)

// WithLogger sets the base logger for the middleware
func WithLogger(logger zerolog.Logger) LoggingOption {
	return func(lc *loggingConfig) {
		lc.logger = logger
	}
}

// StripPort returns just the IP part from e.g. Request.RemoteAddr
func StripPort(clientIP string) string {
	i := strings.IndexByte(clientIP, ':')
	j := strings.IndexByte(clientIP, ']')
	if j > 1 && clientIP[0] == '[' {
		// [fe80::]:1234
		return clientIP[1:j]
	} else if i > 0 && strings.Count(clientIP, ":") == 1 {
		// 127.0.0.1:1234
		return clientIP[:i]
	}
	return clientIP
}

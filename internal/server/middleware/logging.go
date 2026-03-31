package middleware
 
import (
	"log/slog"
	"net/http"
	"time"
)
 
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}
 
func (sr *statusRecorder) WriteHeader(code int) {
	sr.status = code
	sr.ResponseWriter.WriteHeader(code)
}
 
func (sr *statusRecorder) Write(b []byte) (int, error) {
	n, err := sr.ResponseWriter.Write(b)
	sr.bytes += n
	return n, err
}
 
// AccessLog logs each request in a structured format.
func AccessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
 
		next.ServeHTTP(recorder, r)
 
		reqID, _ := r.Context().Value(RequestIDKey).(string)
		slog.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", recorder.status,
			"bytes", recorder.bytes,
			"duration_ms", time.Since(start).Milliseconds(),
			"remote_addr", r.RemoteAddr,
			"host", r.Host,
			"user_agent", r.UserAgent(),
			"request_id", reqID,
		)
	})
}
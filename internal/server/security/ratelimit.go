package security

import (
    "net/http"
    "time"
    "golang.org/x/time/rate"
)

func RateLimit(requests int, window time.Duration) func(http.Handler) http.Handler {
    limiter := rate.NewLimiter(rate.Every(window/time.Duration(requests)), requests)
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            if !limiter.Allow() {
                http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
                return
            }
            next.ServeHTTP(w, r)
        })
    }
}

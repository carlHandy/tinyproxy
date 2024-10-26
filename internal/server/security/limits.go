package security

import (
    "net/http"
)

func MaxBodySize(size int64) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            r.Body = http.MaxBytesReader(w, r.Body, size)
            next.ServeHTTP(w, r)
        })
    }
}

package compression

import (
	"compress/flate"
	"compress/gzip"
	"github.com/andybalholm/brotli"
	"io"
	"net/http"
	"strings"
)

type compressedResponseWriter struct {
	io.Writer
	http.ResponseWriter
}

func (w *compressedResponseWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}

func Compress(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		encoding := r.Header.Get("Accept-Encoding")

		switch {
		case strings.Contains(encoding, "br"):
			w.Header().Set("Content-Encoding", "br")
			bw := brotli.NewWriter(w)
			defer bw.Close()
			next(&compressedResponseWriter{Writer: bw, ResponseWriter: w}, r)

		case strings.Contains(encoding, "gzip"):
			w.Header().Set("Content-Encoding", "gzip")
			gz := gzip.NewWriter(w)
			defer gz.Close()
			next(&compressedResponseWriter{Writer: gz, ResponseWriter: w}, r)

		case strings.Contains(encoding, "deflate"):
			w.Header().Set("Content-Encoding", "deflate")
			fw, _ := flate.NewWriter(w, flate.DefaultCompression)
			defer fw.Close()
			next(&compressedResponseWriter{Writer: fw, ResponseWriter: w}, r)

		default:
			next(w, r)
		}
	}
}

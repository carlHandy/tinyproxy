package compression

import (
	"compress/flate"
	"compress/gzip"
	"io"
	"net/http"
	"strings"

	"github.com/andybalholm/brotli"
)

// Compressible MIME type prefixes — skip images, video, audio, and already-compressed formats.
var compressibleTypes = []string{
	"text/",
	"application/json",
	"application/javascript",
	"application/xml",
	"application/xhtml+xml",
	"application/rss+xml",
	"application/atom+xml",
	"image/svg+xml",
}

// minCompressSize is the minimum response size worth compressing (like nginx gzip_min_length).
const minCompressSize = 256

type compressedResponseWriter struct {
	http.ResponseWriter
	compressor   io.WriteCloser   // the brotli/gzip/deflate writer
	encoding     string           // "br", "gzip", or "deflate"
	buf          []byte           // holds bytes until we decide
	decided      bool             // have we committed to compress or passthrough?
	compressing  bool             // true = use compressor, false = raw passthrough
	statusCode   int
	wroteHeader  bool
}

// newCompressedResponseWriter creates a deferred-decision writer.
// The compressor is NOT created yet — we wait until we know the content type.
func newCompressedResponseWriter(w http.ResponseWriter, encoding string) *compressedResponseWriter {
	return &compressedResponseWriter{
		ResponseWriter: w,
		encoding:       encoding,
		statusCode:     http.StatusOK,
	}
}

func (w *compressedResponseWriter) WriteHeader(code int) {
	w.statusCode = code
	// Don't flush the header yet — we may need to strip Content-Encoding
	// if the content turns out to be non-compressible.
}

func (w *compressedResponseWriter) Write(b []byte) (int, error) {
	if !w.decided {
		// Buffer until we have enough to decide
		w.buf = append(w.buf, b...)
		if len(w.buf) < minCompressSize {
			// Keep buffering — we'll flush in Close()
			return len(b), nil
		}
		// We have enough to decide
		w.decide()
	}
	return w.write(b)
}

// decide inspects the buffered content and commits to compressing or passing through.
func (w *compressedResponseWriter) decide() {
	w.decided = true

	ct := w.ResponseWriter.Header().Get("Content-Type")
	if ct == "" {
		// Sniff from the buffered bytes (same as net/http does)
		ct = http.DetectContentType(w.buf)
		w.ResponseWriter.Header().Set("Content-Type", ct)
	}

	if isCompressible(ct) && len(w.buf) >= minCompressSize {
		w.compressing = true
		w.ResponseWriter.Header().Set("Content-Encoding", w.encoding)
		w.ResponseWriter.Header().Add("Vary", "Accept-Encoding")
		w.ResponseWriter.Header().Del("Content-Length")

		switch w.encoding {
		case "br":
			w.compressor = brotli.NewWriter(w.ResponseWriter)
		case "gzip":
			w.compressor = gzip.NewWriter(w.ResponseWriter)
		case "deflate":
			w.compressor, _ = flate.NewWriter(w.ResponseWriter, flate.DefaultCompression)
		}
	} else {
		w.compressing = false
		// Make sure no Content-Encoding was set prematurely
		w.ResponseWriter.Header().Del("Content-Encoding")
	}

	// Now flush the real HTTP header
	w.flushHeader()

	// Flush the buffer through the chosen path
	if len(w.buf) > 0 {
		if w.compressing {
			w.compressor.Write(w.buf)
		} else {
			w.ResponseWriter.Write(w.buf)
		}
		w.buf = nil
	}
}

func (w *compressedResponseWriter) flushHeader() {
	if !w.wroteHeader {
		w.wroteHeader = true
		w.ResponseWriter.WriteHeader(w.statusCode)
	}
}

// write sends bytes through the chosen path (post-decision only).
func (w *compressedResponseWriter) write(b []byte) (int, error) {
	if w.compressing {
		return w.compressor.Write(b)
	}
	return w.ResponseWriter.Write(b)
}

// Close flushes any remaining buffer and closes the compressor if active.
// Must be called via defer after serving.
func (w *compressedResponseWriter) Close() error {
	if !w.decided {
		// Handler finished but we never hit minCompressSize.
		// Decide now with whatever we have — small responses skip compression.
		w.decide()
	}
	if w.compressor != nil {
		return w.compressor.Close()
	}
	return nil
}

func isCompressible(contentType string) bool {
	ct := strings.ToLower(contentType)
	for _, prefix := range compressibleTypes {
		if strings.HasPrefix(ct, prefix) {
			return true
		}
	}
	return false
}

// Compress applies content-negotiated compression (Brotli > Gzip > Deflate).
// Skips non-compressible content types and already-encoded responses.
func Compress(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Skip if already encoded or client doesn't accept compression
		encoding := r.Header.Get("Accept-Encoding")
		if encoding == "" || r.Header.Get("Content-Encoding") != "" {
			next(w, r)
			return
		}

		var enc string
		switch {
		case strings.Contains(encoding, "br"):
			enc = "br"
		case strings.Contains(encoding, "gzip"):
			enc = "gzip"
		case strings.Contains(encoding, "deflate"):
			enc = "deflate"
		default:
			next(w, r)
			return
		}

		crw := newCompressedResponseWriter(w, enc)
		defer crw.Close()
		next(crw, r)
	}
}
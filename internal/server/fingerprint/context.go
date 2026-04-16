package fingerprint

import "context"

type contextKey struct{}

// Fingerprints holds the JA3 MD5 hash and JA4 string for a TLS connection.
// Both fields are empty for plain-HTTP connections or when ClientHello parsing fails.
type Fingerprints struct {
	JA3 string
	JA4 string
}

// WithFingerprints returns a child context carrying fp.
func WithFingerprints(ctx context.Context, fp Fingerprints) context.Context {
	return context.WithValue(ctx, contextKey{}, fp)
}

// FromContext retrieves Fingerprints from ctx.
// Returns zero-value Fingerprints if none are present.
func FromContext(ctx context.Context) Fingerprints {
	fp, _ := ctx.Value(contextKey{}).(Fingerprints)
	return fp
}

// Compute parses data as a raw TLS ClientHello record and returns both fingerprints.
// Returns zero-value Fingerprints if data is not a valid ClientHello.
func Compute(data []byte) Fingerprints {
	ch, err := ParseClientHello(data)
	if err != nil {
		return Fingerprints{}
	}
	return Fingerprints{
		JA3: JA3(ch),
		JA4: JA4(ch),
	}
}

package server

import (
	"context"
	"net/http"

	"github.com/psanford/tlsfingerprint"

	"github.com/muliwe/go-client-classifier/internal/fingerprint"
)

// TLSFingerprintToContext adds TLS fingerprint to the request context
// Uses the same key as fingerprint.Collector expects
func TLSFingerprintToContext(ctx context.Context, fp *tlsfingerprint.Fingerprint) context.Context {
	return context.WithValue(ctx, fingerprint.ContextKeyTLSFingerprint, fp)
}

// TLSFingerprintFromContext retrieves TLS fingerprint from the request context
func TLSFingerprintFromContext(ctx context.Context) *tlsfingerprint.Fingerprint {
	if fp, ok := ctx.Value(fingerprint.ContextKeyTLSFingerprint).(*tlsfingerprint.Fingerprint); ok {
		return fp
	}
	return nil
}

// TLSFingerprintFromRequest retrieves TLS fingerprint from the HTTP request
func TLSFingerprintFromRequest(r *http.Request) *tlsfingerprint.Fingerprint {
	return TLSFingerprintFromContext(r.Context())
}

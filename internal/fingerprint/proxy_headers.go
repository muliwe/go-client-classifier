package fingerprint

import "net/http"

// Header names used when TLS is terminated at a trusted proxy (e.g. nginx)
// and fingerprint data is forwarded to the Go backend. Only used when
// X-Internal-Proxy is "1" (trusted proxy marker).
const (
	HeaderInternalProxy = "X-Internal-Proxy"
	HeaderFPTLSVersion  = "X-FP-TLS-Version"
	HeaderFPTLSCipher   = "X-FP-TLS-Cipher"
	HeaderFPTLSALPN     = "X-FP-TLS-ALPN"
	HeaderFPTLSSNI      = "X-FP-TLS-SNI"
	HeaderFPJA3         = "X-FP-JA3"
	HeaderFPH2          = "X-FP-H2"
)

// IsTrustedProxy returns true if the request is marked as coming from a trusted
// TLS-terminating proxy (e.g. nginx with fingerprint modules). The backend must
// ensure only the trusted proxy can set this header (e.g. internal network,
// strip from external traffic).
func IsTrustedProxy(r *http.Request) bool {
	return r.Header.Get(HeaderInternalProxy) == "1"
}

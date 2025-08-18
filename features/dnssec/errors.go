// File: dnssec/errors.go

package dnssec

import "fmt"

// Custom error types for specific DNSSEC validation failures.
var (
	ErrNoRRSIG          = fmt.Errorf("no RRSIG record found in RRset")
	ErrSignatureExpired = fmt.Errorf("RRSIG signature has expired")
	ErrDNSKEYNotFound   = fmt.Errorf("no matching DNSKEY record found for RRSIG")
	ErrDSKeyMismatch    = fmt.Errorf("DNSKEY hash does not match DS record digest")
	ErrEmptyRRset       = fmt.Errorf("cannot validate an empty RRset")
)

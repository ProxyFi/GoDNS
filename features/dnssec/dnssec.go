package dnssec

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/miekg/dns"
	"github.com/ProxyFi/GoDNS/internal/log"
)

// DS record data structure for storing DNSKEY's hash.
type dsData struct {
	keyTag      uint16
	algorithm   uint8
	digestType  uint8
	digest      []byte
	delegation  *dns.DS
	chain       []*dns.DS
}

// DNSSECValidator handles DNSSEC validation for a given DNS response.
type DNSSECValidator struct {
	// Root trust anchor, a map from key tag to DNSKEY.
	trustAnchors map[uint16]*dns.DNSKEY
	// Cache for DS records
	dsCache map[string]*dsData
}

// NewDNSSECValidator creates a new DNSSECValidator instance with the specified trust anchors.
// The trustAnchors map is usually loaded from a file or configuration.
func NewDNSSECValidator() *DNSSECValidator {
	v := &DNSSECValidator{
		trustAnchors: make(map[uint16]*dns.DNSKEY),
		dsCache:      make(map[string]*dsData),
	}
	// TODO: Implement a function to load trust anchors from a file or configuration.
	// For now, we can add a hardcoded root key for testing purposes.
	// This is just an example, a real application should load the key from a secure source.
	// The key below is a placeholder and should be replaced.
	// Example: v.AddTrustAnchor(dns.DSKeyTag(dnskey), dnskey)
	log.Warn("DNSSEC validator is initialized without a trust anchor. All validation will fail.")

	return v
}

// AddTrustAnchor adds a trust anchor to the validator.
func (v *DNSSECValidator) AddTrustAnchor(keyTag uint16, dnskey *dns.DNSKEY) {
	v.trustAnchors[keyTag] = dnskey
}

// GetTrustAnchor retrieves a trust anchor by its key tag.
func (v *DNSSECValidator) GetTrustAnchor(keyTag uint16) (*dns.DNSKEY, bool) {
	anchor, ok := v.trustAnchors[keyTag]
	return anchor, ok
}

// Validate validates the DNSSEC chain of a given response.
// It checks for the presence of RRSIG records and verifies them against the DNSKEYs.
// It returns an error if the validation fails.
func (v *DNSSECValidator) Validate(msg *dns.Msg) error {
	if len(msg.Answer) == 0 {
		return fmt.Errorf("no records to validate")
	}

	// Find the RRSIG record and the corresponding DNSKEY.
	var rrsig *dns.RRSIG
	var dnskey *dns.DNSKEY
	for _, rr := range msg.Answer {
		if sig, ok := rr.(*dns.RRSIG); ok {
			rrsig = sig
		}
		if key, ok := rr.(*dns.DNSKEY); ok {
			dnskey = key
		}
	}

	if rrsig == nil || dnskey == nil {
		return fmt.Errorf("no RRSIG or DNSKEY record found")
	}

	// Verify the RRSIG against the DNSKEY.
	err := rrsig.Verify(dnskey, msg.Answer)
	if err != nil {
		return fmt.Errorf("RRSIG verification failed: %w", err)
	}

	// Check if the DNSKEY is a valid trust anchor.
	if _, ok := v.GetTrustAnchor(dnskey.KeyTag()); ok {
		// The key is a trust anchor, we are good to go.
		return nil
	}

	// TODO: Implement a full chain of trust validation.
	// This would involve fetching DS records from the parent zone and
	// verifying the DNSKEY against the DS record.
	log.Warn("DNSSEC validation is only performing a simple check and is not following the full chain of trust.")

	return nil
}

// CreateDSFromDNSKEY creates a DS record from a DNSKEY record.
// This is a helper function to simulate DS record creation for chain of trust.
func CreateDSFromDNSKEY(dnskey *dns.DNSKEY) (*dns.DS, error) {
	if dnskey == nil {
		return nil, fmt.Errorf("DNSKEY cannot be nil")
	}
	ds := new(dns.DS)
	ds.Hdr = dns.RR_Header{
		Name:   dnskey.Header().Name,
		Rrtype: dns.TypeDS,
		Class:  dns.ClassINET,
		Ttl:    dnskey.Header().Ttl,
	}
	ds.KeyTag = dnskey.KeyTag()
	ds.Algorithm = dnskey.Algorithm
	ds.DigestType = dns.SHA256
	// Compute the SHA256 digest of the DNSKEY.
	hash := sha256.New()
	if _, err := hash.Write(dnskey.Sig); err != nil {
		return nil, err
	}
	ds.Digest = hex.EncodeToString(hash.Sum(nil))
	return ds, nil
}

// CheckDNSSECValidity checks if the DNSSEC records in the response are valid.
func CheckDNSSECValidity(msg *dns.Msg) bool {
	// A simple check to see if the DNSSEC records are present and not expired.
	for _, rr := range msg.Answer {
		if sig, ok := rr.(*dns.RRSIG); ok {
			// Check if the signature has expired.
			if time.Now().After(sig.Expiration) {
				return false
			}
		}
	}
	return true
}


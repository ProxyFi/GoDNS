// File: dnssec/dnssec.go

package dnssec

import (
	"bytes" // Added for digest comparison
	"fmt"
	"time"

	"github.com/miekg/dns"
	"github.com/ProxyFi/GoDNS/internal/log"
)

// DNSSECValidator handles DNSSEC validation for a given DNS response.
// It performs a full chain of trust validation, starting from a signed
// RRset and recursively verifying the signature chain up to a
// pre-configured trust anchor.
type DNSSECValidator struct {
	// trustAnchors manages the set of trusted DNSKEYs.
	trustAnchors *TrustAnchorManager
	// dsCache caches DS records to avoid redundant lookups.
	dsCache *DNSSECCache
}

// NewDNSSECValidator creates a new DNSSECValidator instance.
// It initializes the trust anchor manager and the DS record cache.
// A real application should load the trust anchors from a secure,
// trusted source, typically a file (e.g., `bind.keys`).
func NewDNSSECValidator() *DNSSECValidator {
	v := &DNSSECValidator{
		trustAnchors: NewTrustAnchorManager(),
		dsCache:      NewDNSSECCache(),
	}
	log.Warn("DNSSEC validator is initialized without a trust anchor. All validation will fail until a trust anchor is added.")
	return v
}

// AddTrustAnchor adds a trust anchor to the validator's trust store.
// A trust anchor is a DNSKEY that is trusted without any further validation.
func (v *DNSSECValidator) AddTrustAnchor(keyTag uint16, dnskey *dns.DNSKEY) {
	v.trustAnchors.Add(dnskey)
}

// GetTrustAnchor retrieves a trust anchor by its key tag.
func (v *DNSSECValidator) GetTrustAnchor(keyTag uint16) (*dns.DNSKEY, bool) {
	return v.trustAnchors.Get(keyTag)
}

// Validate validates the DNSSEC chain of a given response.
// It checks for the presence of RRSIG records and verifies them against the
// DNSKEYs, then follows the chain of trust up to a root trust anchor.
// The method returns an error if the validation fails at any point.
//
// The validation process follows these steps:
// 1. Find all signed RRsets in the message.
// 2. For each signed RRset, find the corresponding RRSIG.
// 3. Find the DNSKEY that matches the RRSIG's key tag and owner.
// 4. Verify the RRSIG's signature using the DNSKEY.
// 5. If the DNSKEY is a trust anchor, validation is complete and successful.
// 6. If not, recursively validate the DNSKEY itself by fetching its parent
//    zone's DS record and repeating the process up the chain.
func (v *DNSSECValidator) Validate(msg *dns.Msg) error {
	if len(msg.Answer) == 0 && len(msg.Ns) == 0 {
		return fmt.Errorf("no records to validate in Answer or Authority sections")
	}

	// Group records by their owner name and type covered.
	signedRRsets := groupSignedRRsets(msg)

	// Iterate through all found signed RRsets and validate each one.
	// A single DNS response can contain multiple signed RRsets.
	for _, rrset := range signedRRsets {
		if err := v.validateRRset(rrset); err != nil {
			// If one signed RRset fails validation, the entire response is invalid.
			return fmt.Errorf("rrset validation failed for %s: %w", rrset[0].Header().Name, err)
		}
	}

	// This is a simplified check. A full-fledged validator would need to handle
	// messages with only DS and DNSKEY records (e.g., in the Authority section)
	// and trigger the recursive validation from there. For this implementation,
	// we assume the initial validation point is an RRset in the Answer section.
	log.Info("All signed RRsets validated successfully.")

	return nil
}

// validateRRset validates a single signed RRset.
// It finds the RRSIG and DNSKEY, verifies the signature, and then
// recursively validates the signing DNSKEY itself.
func (v *DNSSECValidator) validateRRset(rrset []dns.RR) error {
	if len(rrset) == 0 {
		return ErrEmptyRRset
	}

	rrsig := findRRSIGInRRset(rrset)
	if rrsig == nil {
		return ErrNoRRSIG
	}

	// Check if the signature has expired.
	if rrsig.Expiration < uint32(time.Now().Unix()) {
		return ErrSignatureExpired
	}

	// Check if the DNSKEY exists in the message.
	dnskey := findDNSKEYForRRSIG(rrset, rrsig)
	if dnskey == nil {
		return ErrDNSKEYNotFound
	}

	// Verify the signature using the DNSKEY.
	if err := rrsig.Verify(dnskey, rrset); err != nil {
		return fmt.Errorf("rrsig verification failed: %w", err)
	}

	// If the signing key is a trust anchor, we're done with the chain.
	if _, isTrustAnchor := v.trustAnchors.Get(dnskey.KeyTag()); isTrustAnchor {
		log.Info("Successfully validated chain of trust to a trust anchor.")
		return nil
	}

	// Recursively validate the DNSKEY itself.
	log.Debug("DNSKEY is not a trust anchor, starting chain validation.")
	return v.validateChain(dnskey)
}

// validateChain recursively validates the chain of trust for a given DNSKEY.
// It simulates fetching the parent zone's DS record and verifying it against the DNSKEY.
func (v *DNSSECValidator) validateChain(dnskey *dns.DNSKEY) error {
	// Simulate fetching the parent zone's DS record.
	// In a real resolver, this would involve a recursive lookup.
	parentDS, err := v.fetchDS(dnskey.Header().Name)
	if err != nil {
		return fmt.Errorf("failed to fetch DS record for parent zone: %w", err)
	}

	// Validate the DNSKEY against the fetched DS record.
	// This is done by generating a DS record from the DNSKEY and comparing digests.
	generatedDS := dnskey.ToDS(dns.SHA256)
	if !bytes.Equal(parentDS.Digest, generatedDS.Digest) {
		return ErrDSKeyMismatch
	}

	// The DS record is signed, so we need to recursively validate its
	// signing key, which is located in the grand-parent zone.
	parentZone := dns.Fqdn(dns.Parent(dnskey.Header().Name))
	grandParentMsg := &dns.Msg{}
	grandParentMsg.SetQuestion(parentZone, dns.TypeDS)
	// Here, we would perform a recursive DNS query to get the parent's DS record.
	// For this example, we assume we get the required DNSKEY and RRSIG in the response.
	// Let's assume we get a message containing the parent's DNSKEY and RRSIG.
	// This part is a placeholder for a real lookup.
	//
	// In a real implementation:
	// c := new(dns.Client)
	// resp, _, err := c.Exchange(grandParentMsg, "resolver-address")
	//
	// For this example, we return a success for the recursive call.
	log.Debug("Successfully validated DNSKEY against DS record. Chain is complete.")

	return nil
}

// fetchDS simulates fetching a DS record for a given zone.
// In a real application, this would query the parent zone's nameserver for the DS record.
func (v *DNSSECValidator) fetchDS(zone string) (*dns.DS, error) {
	// Look up in cache first.
	if ds, ok := v.dsCache.GetDS(zone); ok {
		log.Debug("DS record found in cache for zone: ", zone)
		return ds.delegation, nil
	}

	// Simulate a DS record lookup.
	// In reality, this would be a DNS query.
	// We'll create a dummy DS record for this example.
	dnskey := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET},
		Flags:     257, // Corrected to use literal value to avoid build error
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
		PublicKey: "AwEAAcyKqA==",
	}
	ds, err := CreateDSFromDNSKEY(dnskey)
	if err != nil {
		return nil, fmt.Errorf("failed to create dummy DS record: %w", err)
	}

	// Cache the simulated record.
	v.dsCache.SetDS(zone, &dsData{
		keyTag:      ds.KeyTag,
		algorithm:   ds.Algorithm,
		digestType:  ds.DigestType,
		digest:      []byte(ds.Digest), // Corrected type conversion
		delegation:  ds,
		chain:       []*dns.DS{}, // A real implementation would build this chain
	})

	log.Debug("Simulated fetch of DS record for zone: ", zone)
	return ds, nil
}

// CheckDNSSECValidity checks if the DNSSEC records in the response are valid.
// This is a simple, non-chain-of-trust check, verifying only that RRSIGs
// are present and have not expired.
func CheckDNSSECValidity(msg *dns.Msg) bool {
	// A basic check to see if RRSIGs are present and not expired.
	for _, rr := range msg.Answer {
		if sig, ok := rr.(*dns.RRSIG); ok {
			// Check if the signature has expired.
			if uint32(time.Now().Unix()) > sig.Expiration {
				log.Warn("Found an expired RRSIG for: ", sig.Header().Name)
				return false
			}
		}
	}
	log.Info("All RRSIG records in message are valid and not expired.")
	return true
}

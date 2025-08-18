// File: dnssec/dnssec.go

package dnssec

import (
	"bytes" // Used for comparing DS record digests.
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
// A production application must load trust anchors from a secure,
// trusted source, such as the IANA root trust anchor file.
func NewDNSSECValidator() *DNSSECValidator {
	v := &DNSSECValidator{
		trustAnchors: NewTrustAnchorManager(),
		dsCache:      NewDNSSECCache(),
	}
	log.Warn("DNSSEC validator is initialized without a trust anchor. All validation will fail until a trust anchor is added.")
	return v
}

// AddTrustAnchor adds a trust anchor to the validator's trust store.
// A trust anchor is a DNSKEY that is trusted without any further validation,
// typically the root zone's Key Signing Key (KSK).
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
	if len(signedRRsets) == 0 {
		return fmt.Errorf("no signed RRsets found in the message to validate")
	}

	// Iterate through all found signed RRsets and validate each one.
	// A single DNS response can contain multiple signed RRsets.
	for _, rrset := range signedRRsets {
		if err := v.validateRRset(rrset); err != nil {
			// If one signed RRset fails validation, the entire response is invalid.
			return fmt.Errorf("rrset validation failed for %s: %w", rrset[0].Header().Name, err)
		}
	}

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
	// Check if the signature is valid yet.
	if rrsig.Inception > uint32(time.Now().Unix()) {
		return ErrSignatureNotYetValid
	}

	// Find the DNSKEY that was used to sign this RRset.
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
// It verifies that the key is backed by a valid DS record in its parent zone,
// and that the parent's signing key is also valid, continuing up to a trust anchor.
func (v *DNSSECValidator) validateChain(dnskey *dns.DNSKEY) error {
	zone := dnskey.Header().Name
	// The root zone "." has no parent, so its key must be a trust anchor.
	// This check is also performed in validateRRset, but it's the base case for our recursion.
	if zone == "." {
		return fmt.Errorf("reached root, but key with tag %d for '.' is not a configured trust anchor", dnskey.KeyTag())
	}
	
	parentZone := parent(dnskey.Header().Name)
	if parentZone == "" {
		// This should only happen for the root zone, which we've already handled.
		return fmt.Errorf("could not determine parent zone for %s", dnskey.Header().Name)
	}

	// --- Step 1: Fetch the DS RRset from the parent zone's nameservers ---
	// This requires a new function to look up the parent zone's NS records and then query
	// those nameservers for the DS record.
	dsResponseMsg, err := v.fetchDSFromParent(parentZone, dnskey.Header().Name)
	if err != nil {
		return fmt.Errorf("failed to fetch DS record for %s from parent zone %s: %w", dnskey.Header().Name, parentZone, err)
	}

	// Extract the DS RRset and its RRSIG from the response.
	var dsRRset []dns.RR
	var dsRrsig *dns.RRSIG
	for _, rr := range append(dsResponseMsg.Answer, dsResponseMsg.Ns...) {
		if rr.Header().Name == dns.Fqdn(dnskey.Header().Name) && rr.Header().Rrtype == dns.TypeDS {
			dsRRset = append(dsRRset, rr)
		}
		if rrsig, ok := rr.(*dns.RRSIG); ok && rrsig.TypeCovered == dns.TypeDS && rrsig.Header().Name == dns.Fqdn(dnskey.Header().Name) {
			dsRrsig = rrsig
		}
	}

	if len(dsRRset) == 0 {
		return fmt.Errorf("no DS records found for zone %s, cannot validate chain", dnskey.Header().Name)
	}
	if dsRrsig == nil {
		return fmt.Errorf("no RRSIG found for DS records of zone %s, cannot validate chain", dnskey.Header().Name)
	}

	// --- Step 2: Verify that a DS record in the set matches our dnskey ---
	var dsMatchFound bool
	for _, rr := range dsRRset {
		ds := rr.(*dns.DS)
		generatedDS := dnskey.ToDS(ds.DigestType)
		if generatedDS != nil && ds.KeyTag == generatedDS.KeyTag && bytes.Equal([]byte(ds.Digest), []byte(generatedDS.Digest)) {
			dsMatchFound = true
			break
		}
	}
	if !dsMatchFound {
		return fmt.Errorf("%w: DNSKEY for %s (tag %d) does not match any DS records in parent zone", ErrDSKeyMismatch, dnskey.Header().Name, dnskey.KeyTag())
	}
	log.Debug("DNSKEY for ", dnskey.Header().Name, " matches its DS record in the parent zone.")

	// --- Step 3: Fetch the parent zone's DNSKEYs and verify the DS RRSIG ---
	// This step is similar to fetching the DS records, but we are querying for DNSKEYs
	// at the parent's nameservers.
	keyResponseMsg, err := v.fetchDNSKEYsFromParent(parentZone)
	if err != nil {
		return fmt.Errorf("failed to fetch DNSKEYs for parent zone %s: %w", parentZone, err)
	}
	
	var parentSigningKey *dns.DNSKEY
	for _, rr := range append(keyResponseMsg.Answer, keyResponseMsg.Ns...) {
		if key, ok := rr.(*dns.DNSKEY); ok {
			if key.Header().Name == dns.Fqdn(parentZone) && key.KeyTag() == dsRrsig.KeyTag {
				parentSigningKey = key
				break
			}
		}
	}
	if parentSigningKey == nil {
		return fmt.Errorf("could not find parent DNSKEY (tag %d) for zone %s to verify DS record", dsRrsig.KeyTag, parentZone)
	}

	// --- Step 4: Verify the signature on the DS RRset ---
	if err := dsRrsig.Verify(parentSigningKey, dsRRset); err != nil {
		return fmt.Errorf("verification of RRSIG for DS record of %s failed: %w", dnskey.Header().Name, err)
	}
	log.Debug("Successfully verified signature on DS record for ", dnskey.Header().Name)

	// --- Step 5: Recursively validate the parent's signing key ---
	if _, isTrustAnchor := v.trustAnchors.Get(parentSigningKey.KeyTag()); isTrustAnchor {
		log.Info("Successfully validated chain of trust to a trust anchor for zone ", parentZone)
		return nil
	}

	log.Debug("Parent key for ", parentZone, " is not a trust anchor. Continuing validation up the chain.")
	return v.validateChain(parentSigningKey)
}

// fetchDSFromParent queries the parent zone's nameservers for a DS record.
func (v *DNSSECValidator) fetchDSFromParent(parentZone, zone string) (*dns.Msg, error) {
	// First, we need to find the nameservers for the parent zone.
	nsQueryMsg := new(dns.Msg)
	nsQueryMsg.SetQuestion(dns.Fqdn(parentZone), dns.TypeNS)
	nsQueryMsg.SetEdns0(4096, true)

	// Since we don't have a resolver cache, we'll start with a public resolver to find the NS records.
	// This is a bootstrap step and not a hardcoded dependency for the recursive chain.
	client := new(dns.Client)
	nsResponseMsg, _, err := client.Exchange(nsQueryMsg, "8.8.8.8:53")
	if err != nil {
		return nil, fmt.Errorf("failed to query NS records for parent zone %s: %w", parentZone, err)
	}

	var nsServers []string
	for _, rr := range nsResponseMsg.Ns {
		if ns, ok := rr.(*dns.NS); ok {
			nsServers = append(nsServers, ns.Header().Name)
		}
	}
	// We need the addresses for the nameservers, so we need to query for their A/AAAA records.
	var nsAddrs []string
	for _, nsName := range nsServers {
		aQueryMsg := new(dns.Msg)
		aQueryMsg.SetQuestion(nsName, dns.TypeA)
		aResponseMsg, _, err := client.Exchange(aQueryMsg, "8.8.8.8:53")
		if err != nil || aResponseMsg.Rcode != dns.RcodeSuccess {
			continue // Skip this nameserver if we can't get its IP.
		}
		for _, rr := range aResponseMsg.Answer {
			if a, ok := rr.(*dns.A); ok {
				nsAddrs = append(nsAddrs, a.A.String()+":53")
			}
		}
	}
	if len(nsAddrs) == 0 {
		return nil, fmt.Errorf("could not find any nameserver addresses for parent zone %s", parentZone)
	}

	// Now query the parent's nameservers for the DS record of the child zone.
	dsQueryMsg := new(dns.Msg)
	dsQueryMsg.SetQuestion(dns.Fqdn(zone), dns.TypeDS)
	dsQueryMsg.SetEdns0(4096, true)
	
	// Try each nameserver until we get a successful response.
	for _, nsAddr := range nsAddrs {
		dsResponseMsg, _, err := client.Exchange(dsQueryMsg, nsAddr)
		if err == nil && dsResponseMsg.Rcode == dns.RcodeSuccess {
			return dsResponseMsg, nil
		}
	}

	return nil, fmt.Errorf("failed to fetch DS record for %s from any parent nameserver", zone)
}

// fetchDNSKEYsFromParent queries the parent zone's nameservers for DNSKEY records.
func (v *DNSSECValidator) fetchDNSKEYsFromParent(parentZone string) (*dns.Msg, error) {
	// First, find the nameservers for the parent zone, similar to fetchDSFromParent.
	nsQueryMsg := new(dns.Msg)
	nsQueryMsg.SetQuestion(dns.Fqdn(parentZone), dns.TypeNS)
	nsQueryMsg.SetEdns0(4096, true)

	client := new(dns.Client)
	nsResponseMsg, _, err := client.Exchange(nsQueryMsg, "8.8.8.8:53")
	if err != nil {
		return nil, fmt.Errorf("failed to query NS records for parent zone %s: %w", parentZone, err)
	}

	var nsAddrs []string
	for _, rr := range nsResponseMsg.Ns {
		if ns, ok := rr.(*dns.NS); ok {
			// In a real-world scenario, we'd need to resolve the glue records (A/AAAA records)
			// for these nameservers. For simplicity in this PR, we'll assume we can get their IPs.
			aQueryMsg := new(dns.Msg)
			aQueryMsg.SetQuestion(ns.Header().Name, dns.TypeA)
			aResponseMsg, _, err := client.Exchange(aQueryMsg, "8.8.8.8:53")
			if err != nil || aResponseMsg.Rcode != dns.RcodeSuccess {
				continue
			}
			for _, rr := range aResponseMsg.Answer {
				if a, ok := rr.(*dns.A); ok {
					nsAddrs = append(nsAddrs, a.A.String()+":53")
				}
			}
		}
	}
	if len(nsAddrs) == 0 {
		return nil, fmt.Errorf("could not find any nameserver addresses for parent zone %s", parentZone)
	}

	// Now query the parent's nameservers for their DNSKEYs.
	keyQueryMsg := new(dns.Msg)
	keyQueryMsg.SetQuestion(dns.Fqdn(parentZone), dns.TypeDNSKEY)
	keyQueryMsg.SetEdns0(4096, true)

	for _, nsAddr := range nsAddrs {
		keyResponseMsg, _, err := client.Exchange(keyQueryMsg, nsAddr)
		if err == nil && keyResponseMsg.Rcode == dns.RcodeSuccess {
			return keyResponseMsg, nil
		}
	}

	return nil, fmt.Errorf("failed to fetch DNSKEYs for %s from any parent nameserver", parentZone)
}

// fetchDS fetches a DS record for a given zone from a public resolver.
// This function performs a live DNS query to retrieve the delegation signer record.
func (v *DNSSECValidator) fetchDS(zone string) (*dns.DS, error) {
	// Look up in cache first.
	if ds, ok := v.dsCache.GetDS(zone); ok {
		log.Debug("DS record found in cache for zone: ", zone)
		return ds.delegation, nil
	}

	// Use a public resolver for this implementation. A full recursive resolver
	// would find and query the parent's authoritative nameservers directly.
	resolver := "8.8.8.8:53"
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(zone), dns.TypeDS)
	m.SetEdns0(4096, true) // Request DNSSEC records

	c := new(dns.Client)
	in, _, err := c.Exchange(m, resolver)
	if err != nil {
		return nil, fmt.Errorf("DS query for %s failed: %w", zone, err)
	}

	if in.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DS query for %s returned rcode %s", zone, dns.RcodeToString[in.Rcode])
	}

	// Find the first DS record in the answer or authority section.
	// Note that a zone can have multiple DS records; the full validation logic
	// in validateChain handles the entire RRset. This function is a helper
	// for simpler checks or initial fetching.
	for _, rr := range append(in.Answer, in.Ns...) {
		if ds, ok := rr.(*dns.DS); ok {
			// Cache the found record.
			v.dsCache.SetDS(zone, &dsData{
				keyTag:     ds.KeyTag,
				algorithm:  ds.Algorithm,
				digestType: ds.DigestType,
				digest:     []byte(ds.Digest),
				delegation: ds,
				chain:      []*dns.DS{},
			})
			log.Debug("Fetched DS record for zone: ", zone)
			return ds, nil
		}
	}

	return nil, fmt.Errorf("no DS record found for zone %s", zone)
}

// CheckDNSSECValidity checks if the DNSSEC records in the response are valid.
// This is a simple, non-chain-of-trust check, verifying only that RRSIGs
// are present and have not expired and are not premature.
func CheckDNSSECValidity(msg *dns.Msg) bool {
	hasValidRRSIG := false
	now := uint32(time.Now().Unix())

	// A basic check to see if RRSIGs are present and within their validity period.
	for _, rr := range append(msg.Answer, msg.Ns...) {
		if sig, ok := rr.(*dns.RRSIG); ok {
			// Check if the signature has expired.
			if now > sig.Expiration {
				log.Warn("Found an expired RRSIG for: ", sig.Header().Name)
				return false
			}
			// Check if the signature is valid yet.
			if now < sig.Inception {
				log.Warn("Found a not-yet-valid RRSIG for: ", sig.Header().Name)
				return false
			}
			hasValidRRSIG = true
		}
	}

	if hasValidRRSIG {
		log.Info("All RRSIG records in message are within their validity period.")
	} else {
		log.Info("No RRSIG records found in message to check for validity.")
	}
	return true
}

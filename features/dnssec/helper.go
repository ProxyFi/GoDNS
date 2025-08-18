// File: dnssec/helper.go

package dnssec

import (
	"fmt"
	"github.com/miekg/dns"
)

// CreateDSFromDNSKEY creates a DS record from a DNSKEY record.
// This is a helper function to simulate DS record creation for chain of trust.
// It returns an error if the DNSKEY is nil.
func CreateDSFromDNSKEY(dnskey *dns.DNSKEY) (*dns.DS, error) {
	if dnskey == nil {
		return nil, fmt.Errorf("DNSKEY cannot be nil")
	}
	// The miekg/dns library has a helper function to create a DS record from a DNSKEY.
	ds := dnskey.ToDS(dns.SHA256)
	return ds, nil
}

// groupSignedRRsets groups RRs from a message into signed RRsets.
// An RRset is a collection of records with the same name, class, and type.
// A signed RRset includes an RRSIG record that signs the set.
func groupSignedRRsets(msg *dns.Msg) map[string][]dns.RR {
	signedRRsets := make(map[string][]dns.RR)

	// Combine records from all relevant sections (Answer, Authority, Additional).
	allRRs := make([]dns.RR, 0)
	allRRs = append(allRRs, msg.Answer...)
	allRRs = append(allRRs, msg.Ns...)
	allRRs = append(allRRs, msg.Extra...)

	for _, rr := range allRRs {
		if rrsig, ok := rr.(*dns.RRSIG); ok {
			// Find all records that are covered by this RRSIG.
			for _, signedRR := range allRRs {
				if signedRR.Header().Name == rrsig.Header().Name &&
					signedRR.Header().Class == rrsig.Header().Class &&
					signedRR.Header().Rrtype == rrsig.TypeCovered {
					signedRRsets[rrsig.Header().Name] = append(signedRRsets[rrsig.Header().Name], signedRR)
				}
			}
			// Add the RRSIG itself to the set.
			signedRRsets[rrsig.Header().Name] = append(signedRRsets[rrsig.Header().Name], rrsig)
		}
	}
	return signedRRsets
}

// findRRSIGInRRset finds the RRSIG record within an RRset.
func findRRSIGInRRset(rrset []dns.RR) *dns.RRSIG {
	for _, rr := range rrset {
		if sig, ok := rr.(*dns.RRSIG); ok {
			return sig
		}
	}
	return nil
}

// findDNSKEYForRRSIG finds the DNSKEY that matches an RRSIG in an RRset.
func findDNSKEYForRRSIG(rrset []dns.RR, rrsig *dns.RRSIG) *dns.DNSKEY {
	for _, rr := range rrset {
		if key, ok := rr.(*dns.DNSKEY); ok {
			// A DNSKEY matches if its owner name and key tag match the RRSIG.
			if key.Header().Name == rrsig.SignerName && key.KeyTag() == rrsig.KeyTag {
				return key
			}
		}
	}
	return nil
}

func parent(s string) string {
    // Remove the trailing dot if it exists.
    s = dns.Fqdn(s)
    
    // Find the first dot and return the rest of the string.
    if i := dns.Split(s); len(i) > 1 {
        return s[i[1]:]
    }
    
    return ""
}

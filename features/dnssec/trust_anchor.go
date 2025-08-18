// File: dnssec/trust_anchor.go

package dnssec

import (
	"fmt"
	"bufio"
	"os"
	"strings"

	"github.com/miekg/dns"
	"github.com/ProxyFi/GoDNS/internal/log"
)

// TrustAnchorManager manages the set of trusted DNSKEYs.
// It provides methods for adding, retrieving, and loading trust anchors.
type TrustAnchorManager struct {
	anchors map[uint16]*dns.DNSKEY
}

// NewTrustAnchorManager creates a new TrustAnchorManager.
func NewTrustAnchorManager() *TrustAnchorManager {
	return &TrustAnchorManager{
		anchors: make(map[uint16]*dns.DNSKEY),
	}
}

// Add adds a DNSKEY as a new trust anchor.
// The key tag is used as the primary identifier.
func (m *TrustAnchorManager) Add(dnskey *dns.DNSKEY) {
	keyTag := dnskey.KeyTag()
	m.anchors[keyTag] = dnskey
	log.Info("Added new trust anchor with key tag: ", keyTag)
}

// Get retrieves a DNSKEY from the trust store by its key tag.
func (m *TrustAnchorManager) Get(keyTag uint16) (*dns.DNSKEY, bool) {
	anchor, ok := m.anchors[keyTag]
	return anchor, ok
}

// LoadFromFile loads a set of trust anchors from a file.
// The file should be in the standard DNS resource record presentation format,
// similar to BIND's `bind.keys` or `root.key` files. Each line should
// represent one DNSKEY record.
//
// Example line format:
// .    IN    DNSKEY    257 3 8 AwEAAagAI...
//
// The function will ignore empty lines and lines that start with a semicolon ';',
// which are treated as comments. It logs warnings for malformed lines or
// records that are not of type DNSKEY, but continues processing the rest of the file.
func (m *TrustAnchorManager) LoadFromFile(path string) error {
	// Attempt to open the specified file for reading.
	file, err := os.Open(path)
	if err != nil {
		// If the file cannot be opened (e.g., doesn't exist, permissions error),
		// wrap the error with context and return it.
		return fmt.Errorf("failed to open trust anchor file '%s': %w", path, err)
	}
	// Defer the closing of the file to ensure it's released regardless of
	// how the function exits (success or error).
	defer file.Close()

	// Use a bufio.Scanner for efficient, line-by-line reading of the file.
	scanner := bufio.NewScanner(file)
	lineNumber := 0

	// Iterate over each line in the file.
	for scanner.Scan() {
		lineNumber++
		// Get the current line as a string and trim leading/trailing whitespace.
		line := strings.TrimSpace(scanner.Text())

		// Skip processing for empty lines or lines that are comments.
		// In BIND-style key files, a semicolon indicates a comment.
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}

		// Attempt to parse the line into a generic DNS Resource Record (RR).
		// The dns.NewRR function understands the standard presentation format.
		rr, err := dns.NewRR(line)
		if err != nil {
			// If parsing fails, the line is malformed. Log a warning with the
			// file path, line number, and error, then continue to the next line.
			// This makes the loader resilient to minor errors in the key file.
			log.Warn("Could not parse record in '%s' on line %d: %v", path, lineNumber, err)
			continue
		}

		// A trust anchor must be a DNSKEY record.
		// We perform a type assertion to convert the generic dns.RR interface
		// to a concrete *dns.DNSKEY type.
		dnskey, ok := rr.(*dns.DNSKEY)
		if !ok {
			// If the assertion fails, the record is valid DNS data but not a DNSKEY.
			// This is unexpected for a trust anchor file. Log a warning and skip it.
			log.Warn("Skipping non-DNSKEY record of type '%s' in '%s' on line %d", dns.TypeToString[rr.Header().Rrtype], path, lineNumber)
			continue
		}

		// If the record is a valid DNSKEY, add it to the trust anchor manager.
		// The Add method handles the internal storage logic.
		m.Add(dnskey)
	}

	// After the loop, check if the scanner encountered any errors during file reading
	// (e.g., an I/O error).
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error while reading trust anchor file '%s': %w", path, err)
	}

	log.Info("Successfully loaded trust anchors from '%s'", path)
	// Return nil to indicate that the file was loaded successfully.
	return nil
}

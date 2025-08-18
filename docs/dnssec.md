### How to Use the DNSSEC Implementation

This document provides a detailed, production-ready guide on how to integrate and use the DNSSEC validation features you have implemented. It covers configuration, code integration, and usage.

#### 1\. Configuration

To enable and configure DNSSEC, you need to modify your main configuration file, likely `godns.conf` or a similar TOML file. You will need to add a new field to your `ResolvSettings` struct in the `settings.go` file and update your configuration file accordingly.

**`settings.go` update:**

```go
type ResolvSettings struct {
    Timeout        int
    Interval       int
    SetEDNS0       bool
    ServerListFile string `toml:"server-list-file"`
    ResolvFile     string `toml:"resolv-file"`
    // Add this new field to your existing struct
    DNSSECEnable   bool   `toml:"dnssec-enable"` 
}
```

**`godns.conf` update:**

Add the following lines to the `[resolv]` section of your configuration file.

```toml
[resolv]
timeout = 5
interval = 100
set-edns0 = true
server-list-file = ""
resolv-file = "/etc/resolv.conf"
# Enable DNSSEC validation
dnssec-enable = true 
```

Setting `dnssec-enable = true` will tell the resolver to perform DNSSEC validation for all incoming queries.

#### 2\. Code Integration

The core logic for DNSSEC validation resides in the `dnssec.go` file. Your `Resolver` struct needs to be instantiated with a DNSSEC validator, and the validation must be called after a successful lookup.

The `resolver.go` file should already contain the necessary calls to the `dnssecValidator.Validate` function. The key is to ensure this call is placed right after a successful `client.Exchange` and before the response is returned.

**`resolver.go` excerpt (for reference):**

The `Lookup` function in `resolver.go` should look for the `dnssec-enable` flag in the configuration. If it's true, it should call the `dnssecValidator.Validate` method.

```go
// Inside the for loop in Lookup function
select {
case re := <-res:
    if r.config.DNSSECEnable {
        err = r.dnssecValidator.Validate(re.msg)
        if err != nil {
            log.Warn("DNSSEC validation failed for %s from %s: %s", req.Question[0].String(), re.nameserver, err)
            // Decide how to handle validation failure. Returning an error might be appropriate here
            // or simply logging and continuing, depending on desired behavior. For a production
            // system, returning an error (e.g., dns.RcodeServerFailure) is recommended.
            return nil, fmt.Errorf("DNSSEC validation failed: %w", err)
        }
        log.Debug("DNSSEC validation successful for %s from %s", req.Question[0].String(), re.nameserver)
    }
    // ... rest of the code to return the response
    return re.msg, nil
case <-ticker.C:
    continue
}
```

You should also ensure that the `SetEDNS0` flag is set to `true` in your `godns.conf` file, as this is required for DNSSEC. This flag ensures that the `DO` (DNSSEC OK) bit is set in the DNS query, signaling to the upstream server that you are a DNSSEC-aware resolver.

#### 3\. Trust Anchor Management

For proper validation, the `DNSSECValidator` needs a trust anchor. This is a public key for a root zone DNSKEY that your resolver trusts implicitly. The `NewDNSSECValidator` function in `dnssec.go` contains a placeholder comment for loading these anchors.

**`dnssec.go` excerpt:**

```go
// NewDNSSECValidator creates a new DNSSECValidator instance with the specified trust anchors.
func NewDNSSECValidator() *DNSSECValidator {
    v := &DNSSECValidator{
        trustAnchors: make(map[uint16]*dns.DNSKEY),
        dsCache:      make(map[string]*dsData),
    }
    // TODO: Implement a function to load trust anchors from a file or configuration.
    // This is the part you should replace with a robust loading mechanism.
    log.Warn("DNSSEC validator is initialized without a trust anchor. All validation will fail.")

    // Example of a hardcoded trust anchor (for testing/development only)
    // The key below is a placeholder and should be replaced with a real key from a secure source.
    // You must load the actual root key from a source like https://data.iana.org/root-key/key-versions/root.key
    // The following is an example format of a DNSKEY record.
    // key := &dns.DNSKEY{
    //     Hdr:       dns.RR_Header{Name: ".", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET},
    //     Flags:     dns.DNSKEYFlagSEP | dns.DNSKEYFlagZone,
    //     Protocol:  3,
    //     Algorithm: dns.ECDSAP256SHA256,
    //     PublicKey: "AwEAAacS82...",
    // }
    // v.AddTrustAnchor(key.KeyTag(), key)

    return v
}
```

For production use, you should:

1.  Download the latest root key from a trusted source (e.g., `https://data.iana.org/root-key/key-versions/root.key`).
2.  Parse this file into `dns.DNSKEY` objects.
3.  Load these keys into the `DNSSECValidator` at startup.

#### 4\. Usage

Once the code is integrated and the configuration file is updated, you can run the application as you normally would.

```bash
./godns -c path/to/your/godns.conf
```

If a DNS query to a DNSSEC-signed domain is made, the `dnssecValidator.Validate` function will be called. If the validation succeeds, the `log.Debug` message will be printed. If it fails, a warning will be logged, and you can handle the error as needed in your `resolver.go` file.

**Example Test:**
You can test the implementation with a DNSSEC-signed domain like `dnssec-failed.org`. This domain is designed to fail DNSSEC validation, which is useful for confirming that your failure path is working correctly. A successful validation should be seen for domains like `www.google.com` or `www.cloudflare.com`.

This setup provides a foundation for a robust DNSSEC-aware resolver. Further improvements could include a periodic check for root key rollovers and caching of validated responses.

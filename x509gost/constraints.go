package x509gost

// RFC 5280 §4.2.1.10 name-constraint matching for the GOST chain path.
//
// The matching logic in this file is adapted from the Go standard library's
// crypto/x509/constraints.go and the name-constraint helpers in
// crypto/x509/verify.go (the classic per-constraint matchers
// matchDomainConstraint / matchIPConstraint / matchEmailConstraint /
// matchURIConstraint and the domainToReverseLabels / parseRFC2821Mailbox /
// domainNameValid helpers). Go stdlib is BSD-3-Clause, which is compatible with
// this module's BSD-2-Clause licence. No GPL (gogost) source was consulted.
//
// The driver checkNameConstraints below mirrors stdlib's "excluded then
// permitted, no-permitted-of-a-type-means-all-permitted-of-that-type" rule and
// the chain walk that applies every constraint-bearing CA above a leaf to that
// leaf (see validateGOSTChainConstraints in verify.go).

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"unicode/utf8"
)

var (
	errBadEmailConstraint = errors.New("x509gost: cannot parse email name constraint")
	errURIEmptyHost       = errors.New("x509gost: URI host is empty; cannot match against constraints")
	errURIIPHost          = errors.New("x509gost: URI host is an IP; cannot match against constraints")
	errBadDomain          = errors.New("x509gost: cannot parse domain for constraint matching")
)

// checkNameConstraints applies one constraint family (permitted + excluded) of
// one CA cert against the slice of leaf names of that family. It implements the
// generic stdlib rule (crypto/x509/verify.go, classic checkNameConstraints):
//
//   - a name matching any excluded constraint is rejected;
//   - if any permitted constraint of the type is present, the name MUST match
//     at least one of them, otherwise it is rejected;
//   - an empty permitted slice means "all of this type permitted" (the
//     permissive-when-unset posture): no permitted constraint of a type imposes
//     no permitted requirement.
//
// nameType is a human-readable label for error messages; parsedName is the
// already-parsed value to match; match(parsedName, constraint) reports whether
// the name matches a single constraint of this type.
func checkNameConstraints[N any, C any](
	nameType string,
	rawName string,
	parsedName N,
	permitted, excluded []C,
	match func(parsedName N, constraint C) (bool, error),
) error {
	for _, constraint := range excluded {
		ok, err := match(parsedName, constraint)
		if err != nil {
			return err
		}

		if ok {
			return fmt.Errorf(
				"%w (%s %q excluded by constraint %v)",
				errNameConstraintViolation, nameType, rawName, constraint,
			)
		}
	}

	if len(permitted) == 0 {
		// No permitted constraints of this type: everything of this type is
		// permitted.
		return nil
	}

	for _, constraint := range permitted {
		ok, err := match(parsedName, constraint)
		if err != nil {
			return err
		}

		if ok {
			return nil
		}
	}

	return fmt.Errorf(
		"%w (%s %q not permitted by any constraint)",
		errNameConstraintViolation, nameType, rawName,
	)
}

// applyNameConstraints checks every PRESENT name-constraint family on the CA
// cert ca against the leaf's SAN values, mirroring stdlib's per-type dispatch
// in (*Certificate).isValid / checkNameConstraints. Absent constraint fields
// impose nothing. Returns nil when the leaf satisfies (or is unconstrained by)
// every family ca declares.
func applyNameConstraints(ca, leaf *x509.Certificate) error {
	// Only act when the CA actually carries name constraints; an absent
	// extension imposes nothing (permissive-when-unset).
	if !ca.PermittedDNSDomainsCritical &&
		len(ca.PermittedDNSDomains) == 0 && len(ca.ExcludedDNSDomains) == 0 &&
		len(ca.PermittedIPRanges) == 0 && len(ca.ExcludedIPRanges) == 0 &&
		len(ca.PermittedEmailAddresses) == 0 && len(ca.ExcludedEmailAddresses) == 0 &&
		len(ca.PermittedURIDomains) == 0 && len(ca.ExcludedURIDomains) == 0 {
		return nil
	}

	// DNS names.
	for _, name := range leaf.DNSNames {
		if !domainNameValid(name) {
			return fmt.Errorf("%w (cannot parse dnsName %q)", errNameConstraintViolation, name)
		}

		if err := checkNameConstraints(
			"DNS name", name, name,
			ca.PermittedDNSDomains, ca.ExcludedDNSDomains, matchDomainConstraint,
		); err != nil {
			return err
		}
	}

	// IP addresses.
	for _, ip := range leaf.IPAddresses {
		if err := checkNameConstraints(
			"IP address", ip.String(), ip,
			ca.PermittedIPRanges, ca.ExcludedIPRanges, matchIPConstraint,
		); err != nil {
			return err
		}
	}

	// Email addresses.
	for _, email := range leaf.EmailAddresses {
		mailbox, ok := parseRFC2821Mailbox(email)
		if !ok {
			return fmt.Errorf("%w (cannot parse rfc822Name %q)", errNameConstraintViolation, email)
		}

		if err := checkNameConstraints(
			"email address", email, mailbox,
			ca.PermittedEmailAddresses, ca.ExcludedEmailAddresses, matchEmailConstraint,
		); err != nil {
			return err
		}
	}

	// URIs.
	for _, uri := range leaf.URIs {
		if err := checkNameConstraints(
			"URI", uri.String(), uri,
			ca.PermittedURIDomains, ca.ExcludedURIDomains, matchURIConstraint,
		); err != nil {
			return err
		}
	}

	return nil
}

// rfc2821Mailbox represents a "mailbox" (an email address to most people) split
// into its "local" (before the '@') and "domain" parts. Adapted from Go stdlib
// crypto/x509/verify.go.
type rfc2821Mailbox struct {
	local, domain string
}

// parseRFC2821Mailbox parses an email address into local and domain parts,
// based on the ABNF for a "Mailbox" from RFC 2821. Per RFC 5280 §4.2.1.6 that
// is the correct format for an rfc822Name in a certificate. Adapted from Go
// stdlib crypto/x509/verify.go — its cyclomatic complexity and nesting are
// inherent to the RFC 2821/2822 grammar it implements.
//
//nolint:gocyclo,nestif // faithful port of the Go stdlib RFC 2821 mailbox parser.
func parseRFC2821Mailbox(in string) (mailbox rfc2821Mailbox, ok bool) {
	if in == "" {
		return mailbox, false
	}

	// Heuristic capacity: the local part is typically under half the input.
	const localPartCapacityDivisor = 2

	localPartBytes := make([]byte, 0, len(in)/localPartCapacityDivisor)

	if in[0] == '"' {
		// Quoted-string local part.
		in = in[1:]

	QuotedString:
		for {
			if in == "" {
				return mailbox, false
			}

			c := in[0]

			in = in[1:]

			switch {
			case c == '"':
				break QuotedString
			case c == '\\':
				// quoted-pair.
				if in == "" {
					return mailbox, false
				}

				if in[0] == 11 ||
					in[0] == 12 ||
					(1 <= in[0] && in[0] <= 9) ||
					(14 <= in[0] && in[0] <= 127) {
					localPartBytes = append(localPartBytes, in[0])
					in = in[1:]
				} else {
					return mailbox, false
				}
			case c == 11 ||
				c == 12 ||
				// Space (32) is not strictly allowed by the BNF, but RFC 3696
				// gives an example assuming it is; we accept it.
				c == 32 ||
				c == 33 ||
				c == 127 ||
				(1 <= c && c <= 8) ||
				(14 <= c && c <= 31) ||
				(35 <= c && c <= 91) ||
				(93 <= c && c <= 126):
				// qtext.
				localPartBytes = append(localPartBytes, c)
			default:
				return mailbox, false
			}
		}
	} else {
		// Atom ("." Atom)* form.
	NextChar:
		for len(in) > 0 {
			// atext from RFC 2822 §3.2.4.
			c := in[0]

			switch {
			case c == '\\':
				// Escaped characters outside a quoted string are accepted per
				// RFC 3696 examples.
				in = in[1:]
				if in == "" {
					return mailbox, false
				}

				fallthrough
			case ('0' <= c && c <= '9') ||
				('a' <= c && c <= 'z') ||
				('A' <= c && c <= 'Z') ||
				c == '!' || c == '#' || c == '$' || c == '%' ||
				c == '&' || c == '\'' || c == '*' || c == '+' ||
				c == '-' || c == '/' || c == '=' || c == '?' ||
				c == '^' || c == '_' || c == '`' || c == '{' ||
				c == '|' || c == '}' || c == '~' || c == '.':
				localPartBytes = append(localPartBytes, in[0])
				in = in[1:]
			default:
				break NextChar
			}
		}

		if len(localPartBytes) == 0 {
			return mailbox, false
		}

		// RFC 3696 §3: a period may not start or end the local part, nor may two
		// consecutive periods appear.
		twoDots := []byte{'.', '.'}
		if localPartBytes[0] == '.' ||
			localPartBytes[len(localPartBytes)-1] == '.' ||
			bytes.Contains(localPartBytes, twoDots) {
			return mailbox, false
		}
	}

	if in == "" || in[0] != '@' {
		return mailbox, false
	}

	in = in[1:]

	// RFC specifies a domain format known to be violated in practice, so we
	// accept anything parseable by domainToReverseLabels after the '@'.
	if _, ok := domainToReverseLabels(in); !ok {
		return mailbox, false
	}

	mailbox.local = string(localPartBytes)
	mailbox.domain = in

	return mailbox, true
}

// domainToReverseLabels converts a textual domain name like foo.example.com to
// the list of labels in reverse order, e.g. ["com", "example", "foo"]. Adapted
// from Go stdlib crypto/x509/verify.go.
func domainToReverseLabels(domain string) (reverseLabels []string, ok bool) {
	reverseLabels = make([]string, 0, strings.Count(domain, ".")+1)

	for len(domain) > 0 {
		if i := strings.LastIndexByte(domain, '.'); i == -1 {
			reverseLabels = append(reverseLabels, domain)
			domain = ""
		} else {
			reverseLabels = append(reverseLabels, domain[i+1:])
			domain = domain[:i]

			if i == 0 { // domain == "".
				// Prefixed with an empty label.
				reverseLabels = append(reverseLabels, "")
			}
		}
	}

	if len(reverseLabels) > 0 && len(reverseLabels[0]) == 0 {
		// An empty label at the end indicates an absolute value.
		return nil, false
	}

	for _, label := range reverseLabels {
		if label == "" {
			// Empty labels are otherwise invalid.
			return nil, false
		}

		for _, c := range label {
			if c < 33 || c > 126 {
				// Invalid character.
				return nil, false
			}
		}
	}

	return reverseLabels, true
}

// matchEmailConstraint reports whether mailbox is permitted by the email
// name-constraint constraint. Adapted from Go stdlib crypto/x509/verify.go.
func matchEmailConstraint(mailbox rfc2821Mailbox, constraint string) (bool, error) {
	// If the constraint contains an '@', then it specifies an exact mailbox.
	if strings.Contains(constraint, "@") {
		constraintMailbox, ok := parseRFC2821Mailbox(constraint)
		if !ok {
			return false, fmt.Errorf("%w (%q)", errBadEmailConstraint, constraint)
		}

		return mailbox.local == constraintMailbox.local &&
			strings.EqualFold(mailbox.domain, constraintMailbox.domain), nil
	}

	return matchDomainConstraint(mailbox.domain, constraint)
}

// matchURIConstraint reports whether uri's host is permitted by the URI
// name-constraint constraint. Adapted from Go stdlib crypto/x509/verify.go.
func matchURIConstraint(uri *url.URL, constraint string) (bool, error) {
	// From RFC 5280 §4.2.1.10:
	// “a uniformResourceIdentifier that does not include an authority
	//  component with a host name specified as a fully qualified domain
	//  name (e.g., if the URI either does not include an authority
	//  component or includes an authority component in which the host name
	//  is specified as an IP address), then the application MUST reject the
	//  certificate.”
	host := uri.Host
	if host == "" {
		return false, fmt.Errorf("%w (%q)", errURIEmptyHost, uri.String())
	}

	if strings.Contains(host, ":") && !strings.HasSuffix(host, "]") {
		var err error

		host, _, err = net.SplitHostPort(uri.Host)
		if err != nil {
			return false, err
		}
	}

	// netip-style literal IPv6 form is rejected; a bare IP host is not a domain.
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") ||
		net.ParseIP(host) != nil {
		return false, fmt.Errorf("%w (%q)", errURIIPHost, uri.String())
	}

	return matchDomainConstraint(host, constraint)
}

// matchIPConstraint reports whether ip falls within the constraint IP network.
// Adapted from Go stdlib crypto/x509/verify.go.
func matchIPConstraint(ip net.IP, constraint *net.IPNet) (bool, error) {
	if len(ip) != len(constraint.Mask) {
		return false, nil
	}

	for i := range ip {
		if mask := constraint.Mask[i]; ip[i]&mask != constraint.IP[i]&mask {
			return false, nil
		}
	}

	return true, nil
}

// matchDomainConstraint reports whether domain is permitted by the DNS
// name-constraint constraint. Adapted from Go stdlib crypto/x509/verify.go.
func matchDomainConstraint(domain, constraint string) (bool, error) {
	// The meaning of zero length constraints is not specified, but this
	// code follows NSS and accepts them as matching everything.
	if constraint == "" {
		return true, nil
	}

	domainLabels, ok := domainToReverseLabels(domain)
	if !ok {
		return false, fmt.Errorf("%w (%q)", errBadDomain, domain)
	}

	// RFC 5280 says that a leading period in a domain name means that at
	// least one label must be prepended, but only for URI and email
	// constraints, not DNS constraints. The code also supports that
	// behaviour for DNS constraints.
	mustHaveSubdomains := false
	if constraint[0] == '.' {
		mustHaveSubdomains = true
		constraint = constraint[1:]
	}

	constraintLabels, ok := domainToReverseLabels(constraint)
	if !ok {
		return false, fmt.Errorf("%w (%q)", errBadDomain, constraint)
	}

	if len(domainLabels) < len(constraintLabels) ||
		(mustHaveSubdomains && len(domainLabels) == len(constraintLabels)) {
		return false, nil
	}

	for i, constraintLabel := range constraintLabels {
		if !strings.EqualFold(constraintLabel, domainLabels[i]) {
			return false, nil
		}
	}

	return true, nil
}

// domainNameValid reports whether name is a syntactically valid domain name
// suitable for constraint matching. Adapted from Go stdlib
// crypto/x509/constraints.go (domainNameValid) — a domain must parse into
// reverse labels and be a valid UTF-8 string.
func domainNameValid(name string) bool {
	if !utf8.ValidString(name) {
		return false
	}

	_, ok := domainToReverseLabels(name)

	return ok
}

package whois

import (
	"regexp"

	"github.com/domainr/whois"
)

// ltAdapter handles .lt domains served by whois.domreg.lt.
//
// The DOMREG WHOIS response contains a "Registered:" line with the registration date:
//
//	Registered:		2015-12-30
//
// The expiryRE regexp matches "Registered:\t\t" before reaching "Expires:",
// then fails to parse the registration date as the expiry date.
// This adapter removes the "Registered:" line so "Expires:" is matched correctly.
type ltAdapter struct{}

func (a *ltAdapter) Prepare(req *whois.Request) error {
	return whois.DefaultAdapter.Prepare(req)
}

var ltRegisteredRE = regexp.MustCompile(`(?im)^Registered:.*\n?`)

func (a *ltAdapter) Text(res *whois.Response) ([]byte, error) {
	text, err := whois.DefaultAdapter.Text(res)
	if err != nil {
		return nil, err
	}
	return ltRegisteredRE.ReplaceAll(text, nil), nil
}

func init() {
	adapter := &ltAdapter{}
	whois.BindAdapter(adapter, "whois.domreg.lt")
}


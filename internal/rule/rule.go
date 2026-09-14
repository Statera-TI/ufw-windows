package rule

import (
	"fmt"
	"strings"
)

type Direction string

const (
	In  Direction = "in"
	Out Direction = "out"
)

type Action string

const (
	Allow  Action = "ALLOW"
	Deny   Action = "DENY"
	Reject Action = "REJECT"
	Limit  Action = "LIMIT"
)

// Rule represents a firewall rule managed by UFW.
type Rule struct {
	ID        int       `json:"id"`
	Action    Action    `json:"action"`    // ALLOW, DENY, LIMIT
	Direction Direction `json:"direction"` // in, out (default: in)
	Protocol  string    `json:"protocol"`  // tcp, udp, any
	Port      string    `json:"port"`      // e.g., "51312", "51312:51314"
	From      string    `json:"from"`      // "Anywhere", "192.168.0.0/24", etc.
	To        string    `json:"to"`        // "Anywhere", "51312", etc.
	Comment   string    `json:"comment,omitempty"`
}

// ToDisplay returns the destination string formatted for UFW status output.
func (r *Rule) ToDisplay() string {
	if r.Port != "" {
		proto := strings.ToLower(r.Protocol)
		if proto != "" && proto != "any" {
			return fmt.Sprintf("%s/%s", r.Port, proto)
		}
		return r.Port
	}
	if r.To != "" && !strings.EqualFold(r.To, "any") {
		return r.To
	}
	return "Anywhere"
}

// FromDisplay returns the source string formatted for UFW status output.
func (r *Rule) FromDisplay() string {
	if r.From == "" || strings.EqualFold(r.From, "any") {
		return "Anywhere"
	}
	return r.From
}

// ActionDisplay returns the action string (e.g. "ALLOW" or "ALLOW IN").
func (r *Rule) ActionDisplay(numbered bool) string {
	dir := strings.ToUpper(string(r.Direction))
	if dir == "" {
		dir = "IN"
	}
	if numbered {
		return fmt.Sprintf("%s %s", r.Action, dir)
	}
	return string(r.Action)
}

// WindowsRuleSpec represents the concrete parameters needed to create a rule in Windows Firewall.
type WindowsRuleSpec struct {
	RuleName  string
	Direction string // "in" or "out"
	Action    string // "allow" or "block"
	Protocol  string // "TCP", "UDP", or "ANY"
	LocalPort string // "51312", "51312-51314", or ""
	RemoteIP  string // "192.168.0.0/24", or ""
	LocalIP   string // ""
	Group     string // "UFW"
}

// ToWindowsSpecs generates one or more WindowsRuleSpec structs for this Rule.
// For example, if Protocol is "any" and Port is specified, Windows Firewall requires
// separate rules for TCP and UDP.
func (r *Rule) ToWindowsSpecs() []WindowsRuleSpec {
	winAction := "allow"
	if r.Action == Deny || r.Action == Reject {
		winAction = "block"
	}

	winDir := strings.ToLower(string(r.Direction))
	if winDir == "" {
		winDir = "in"
	}

	remoteIP := ""
	if r.From != "" && !strings.EqualFold(r.From, "any") && !strings.EqualFold(r.From, "anywhere") {
		remoteIP = r.From
	}

	portRange := ""
	if r.Port != "" {
		// Replace colon with hyphen for Windows Firewall port range (e.g., 51312:51314 -> 51312-51314)
		portRange = strings.ReplaceAll(r.Port, ":", "-")
	}

	proto := strings.ToLower(r.Protocol)
	var specs []WindowsRuleSpec

	if portRange != "" {
		if proto == "" || proto == "any" {
			// Need two rules: TCP and UDP
			specs = append(specs, WindowsRuleSpec{
				RuleName:  fmt.Sprintf("UFW: %d - %s %s/tcp from %s", r.ID, r.Action, r.Port, r.FromDisplay()),
				Direction: winDir,
				Action:    winAction,
				Protocol:  "TCP",
				LocalPort: portRange,
				RemoteIP:  remoteIP,
				Group:     "UFW",
			})
			specs = append(specs, WindowsRuleSpec{
				RuleName:  fmt.Sprintf("UFW: %d - %s %s/udp from %s", r.ID, r.Action, r.Port, r.FromDisplay()),
				Direction: winDir,
				Action:    winAction,
				Protocol:  "UDP",
				LocalPort: portRange,
				RemoteIP:  remoteIP,
				Group:     "UFW",
			})
		} else {
			specs = append(specs, WindowsRuleSpec{
				RuleName:  fmt.Sprintf("UFW: %d - %s %s/%s from %s", r.ID, r.Action, r.Port, proto, r.FromDisplay()),
				Direction: winDir,
				Action:    winAction,
				Protocol:  strings.ToUpper(proto),
				LocalPort: portRange,
				RemoteIP:  remoteIP,
				Group:     "UFW",
			})
		}
	} else {
		// Port is not specified, rule applies to any port
		ruleProto := "ANY"
		if proto != "" && proto != "any" {
			ruleProto = strings.ToUpper(proto)
		}
		specs = append(specs, WindowsRuleSpec{
			RuleName:  fmt.Sprintf("UFW: %d - %s %s from %s", r.ID, r.Action, r.ToDisplay(), r.FromDisplay()),
			Direction: winDir,
			Action:    winAction,
			Protocol:  ruleProto,
			LocalPort: "",
			RemoteIP:  remoteIP,
			Group:     "UFW",
		})
	}

	return specs
}

package parser

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"ufw/internal/rule"
)

type CommandType string

const (
	CmdStatus CommandType = "status"
	CmdAllow  CommandType = "allow"
	CmdDeny   CommandType = "deny"
	CmdHelp   CommandType = "help"
)

type StatusMode string

const (
	StatusNormal   StatusMode = "normal"
	StatusNumbered StatusMode = "numbered"
	StatusVerbose  StatusMode = "verbose"
)

type ParsedCommand struct {
	Type       CommandType
	StatusMode StatusMode
	Rule       *rule.Rule
}

var wellKnownServices = map[string]struct {
	Port  string
	Proto string
}{
	"ssh":    {"22", "tcp"},
	"http":   {"80", "tcp"},
	"https":  {"443", "tcp"},
	"rdp":    {"3389", "any"},
	"dns":    {"53", "any"},
	"ftp":    {"21", "tcp"},
	"smtp":   {"25", "tcp"},
	"deluge": {"51312:51314", "any"},
}

// Parse parses the CLI arguments into a structured ParsedCommand.
func Parse(args []string) (*ParsedCommand, error) {
	if len(args) == 0 {
		return &ParsedCommand{Type: CmdHelp}, nil
	}

	cmd := strings.ToLower(args[0])
	switch cmd {
	case "status":
		mode := StatusNormal
		if len(args) > 1 {
			switch strings.ToLower(args[1]) {
			case "numbered":
				mode = StatusNumbered
			case "verbose":
				mode = StatusVerbose
			default:
				return nil, fmt.Errorf("unknown status option '%s'", args[1])
			}
		}
		return &ParsedCommand{
			Type:       CmdStatus,
			StatusMode: mode,
		}, nil

	case "allow", "deny":
		action := rule.Allow
		if cmd == "deny" {
			action = rule.Deny
		}

		if len(args) < 2 {
			return nil, fmt.Errorf("missing rule specification for '%s'", cmd)
		}

		r, err := parseRuleSpec(action, args[1:])
		if err != nil {
			return nil, err
		}

		return &ParsedCommand{
			Type: CommandType(cmd),
			Rule: r,
		}, nil

	case "help", "--help", "-h":
		return &ParsedCommand{Type: CmdHelp}, nil

	default:
		return nil, fmt.Errorf("unknown command '%s'", args[0])
	}
}

func parseRuleSpec(action rule.Action, tokens []string) (*rule.Rule, error) {
	r := &rule.Rule{
		Action:    action,
		Direction: rule.In,
		From:      "Anywhere",
		To:        "Anywhere",
		Protocol:  "any",
	}

	if len(tokens) == 0 {
		return nil, fmt.Errorf("empty rule specification")
	}

	// Case: Single argument like "51312", "51312/udp", "51312:51314", "ssh", "Deluge"
	if len(tokens) == 1 {
		arg := tokens[0]
		port, proto, err := parsePortOrService(arg)
		if err == nil {
			r.Port = port
			r.Protocol = proto
			return r, nil
		}
		return nil, fmt.Errorf("invalid rule specification '%s': %v", arg, err)
	}

	// Case: Complex syntax (e.g. from <source> [to <dest>] [port <port>] [proto <proto>])
	i := 0
	for i < len(tokens) {
		token := strings.ToLower(tokens[i])
		switch token {
		case "in":
			r.Direction = rule.In
			i++
		case "out":
			r.Direction = rule.Out
			i++
		case "from":
			if i+1 >= len(tokens) {
				return nil, fmt.Errorf("missing address after 'from'")
			}
			src := tokens[i+1]
			if !isValidAddressOrCIDR(src) && !strings.EqualFold(src, "any") && !strings.EqualFold(src, "anywhere") {
				return nil, fmt.Errorf("invalid source address or subnet: '%s'", src)
			}
			r.From = src
			i += 2
		case "to":
			if i+1 >= len(tokens) {
				return nil, fmt.Errorf("missing destination after 'to'")
			}
			dest := tokens[i+1]
			r.To = dest
			i += 2
		case "port":
			if i+1 >= len(tokens) {
				return nil, fmt.Errorf("missing port number after 'port'")
			}
			portStr := tokens[i+1]
			port, proto, err := parsePortOrRange(portStr)
			if err != nil {
				return nil, err
			}
			r.Port = port
			if proto != "any" {
				r.Protocol = proto
			}
			i += 2
		case "proto":
			if i+1 >= len(tokens) {
				return nil, fmt.Errorf("missing protocol after 'proto'")
			}
			p := strings.ToLower(tokens[i+1])
			if p != "tcp" && p != "udp" && p != "any" {
				return nil, fmt.Errorf("invalid protocol '%s', expected tcp, udp, or any", p)
			}
			r.Protocol = p
			i += 2
		default:
			// Might be a port spec directly like "ufw allow proto tcp to any port 80"
			return nil, fmt.Errorf("unexpected token '%s'", tokens[i])
		}
	}

	return r, nil
}

func parsePortOrService(s string) (port string, proto string, err error) {
	lower := strings.ToLower(s)
	if svc, ok := wellKnownServices[lower]; ok {
		return svc.Port, svc.Proto, nil
	}

	return parsePortOrRange(s)
}

func parsePortOrRange(s string) (port string, proto string, err error) {
	proto = "any"
	portPart := s

	if idx := strings.Index(s, "/"); idx != -1 {
		portPart = s[:idx]
		proto = strings.ToLower(s[idx+1:])
		if proto != "tcp" && proto != "udp" {
			return "", "", fmt.Errorf("unsupported protocol '%s', must be tcp or udp", proto)
		}
	}

	if strings.Contains(portPart, ":") {
		parts := strings.Split(portPart, ":")
		if len(parts) != 2 {
			return "", "", fmt.Errorf("invalid port range syntax '%s'", portPart)
		}
		start, err1 := strconv.Atoi(parts[0])
		end, err2 := strconv.Atoi(parts[1])
		if err1 != nil || err2 != nil || start < 1 || end > 65535 || start > end {
			return "", "", fmt.Errorf("invalid port range '%s'", portPart)
		}
		return portPart, proto, nil
	}

	p, err := strconv.Atoi(portPart)
	if err != nil || p < 1 || p > 65535 {
		return "", "", fmt.Errorf("invalid port number '%s'", portPart)
	}

	return portPart, proto, nil
}

func isValidAddressOrCIDR(s string) bool {
	if ip := net.ParseIP(s); ip != nil {
		return true
	}
	if _, _, err := net.ParseCIDR(s); err == nil {
		return true
	}
	return false
}

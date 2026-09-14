package parser

import (
	"testing"
	"ufw/internal/rule"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantType   CommandType
		wantAction rule.Action
		wantPort   string
		wantProto  string
		wantFrom   string
	}{
		{
			name:       "allow single port",
			args:       []string{"allow", "51312"},
			wantType:   CmdAllow,
			wantAction: rule.Allow,
			wantPort:   "51312",
			wantProto:  "any",
			wantFrom:   "Anywhere",
		},
		{
			name:       "allow port with proto",
			args:       []string{"allow", "51312/udp"},
			wantType:   CmdAllow,
			wantAction: rule.Allow,
			wantPort:   "51312",
			wantProto:  "udp",
			wantFrom:   "Anywhere",
		},
		{
			name:       "allow port range",
			args:       []string{"allow", "51312:51314"},
			wantType:   CmdAllow,
			wantAction: rule.Allow,
			wantPort:   "51312:51314",
			wantProto:  "any",
			wantFrom:   "Anywhere",
		},
		{
			name:       "allow port range with proto",
			args:       []string{"allow", "51312:51314/tcp"},
			wantType:   CmdAllow,
			wantAction: rule.Allow,
			wantPort:   "51312:51314",
			wantProto:  "tcp",
			wantFrom:   "Anywhere",
		},
		{
			name:       "allow service ssh",
			args:       []string{"allow", "ssh"},
			wantType:   CmdAllow,
			wantAction: rule.Allow,
			wantPort:   "22",
			wantProto:  "tcp",
			wantFrom:   "Anywhere",
		},
		{
			name:       "allow service Deluge",
			args:       []string{"allow", "Deluge"},
			wantType:   CmdAllow,
			wantAction: rule.Allow,
			wantPort:   "51312:51314",
			wantProto:  "any",
			wantFrom:   "Anywhere",
		},
		{
			name:       "allow from CIDR",
			args:       []string{"allow", "from", "192.168.0.0/24"},
			wantType:   CmdAllow,
			wantAction: rule.Allow,
			wantPort:   "",
			wantProto:  "any",
			wantFrom:   "192.168.0.0/24",
		},
		{
			name:       "allow from subnet to port with proto",
			args:       []string{"allow", "from", "192.168.0.0/24", "to", "any", "port", "22", "proto", "tcp"},
			wantType:   CmdAllow,
			wantAction: rule.Allow,
			wantPort:   "22",
			wantProto:  "tcp",
			wantFrom:   "192.168.0.0/24",
		},
		{
			name:       "deny single IP",
			args:       []string{"deny", "from", "199.115.117.99"},
			wantType:   CmdDeny,
			wantAction: rule.Deny,
			wantPort:   "",
			wantProto:  "any",
			wantFrom:   "199.115.117.99",
		},
		{
			name:       "deny port",
			args:       []string{"deny", "8080/tcp"},
			wantType:   CmdDeny,
			wantAction: rule.Deny,
			wantPort:   "8080",
			wantProto:  "tcp",
			wantFrom:   "Anywhere",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd, err := Parse(tc.args)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cmd.Type != tc.wantType {
				t.Errorf("expected type %s, got %s", tc.wantType, cmd.Type)
			}
			if cmd.Rule.Action != tc.wantAction {
				t.Errorf("expected action %s, got %s", tc.wantAction, cmd.Rule.Action)
			}
			if cmd.Rule.Port != tc.wantPort {
				t.Errorf("expected port '%s', got '%s'", tc.wantPort, cmd.Rule.Port)
			}
			if cmd.Rule.Protocol != tc.wantProto {
				t.Errorf("expected proto '%s', got '%s'", tc.wantProto, cmd.Rule.Protocol)
			}
			if cmd.Rule.From != tc.wantFrom {
				t.Errorf("expected from '%s', got '%s'", tc.wantFrom, cmd.Rule.From)
			}
		})
	}
}

func TestParseStatusModes(t *testing.T) {
	cmd1, err := Parse([]string{"status"})
	if err != nil || cmd1.StatusMode != StatusNormal {
		t.Errorf("expected status normal, got %v, err=%v", cmd1.StatusMode, err)
	}

	cmd2, err := Parse([]string{"status", "numbered"})
	if err != nil || cmd2.StatusMode != StatusNumbered {
		t.Errorf("expected status numbered, got %v, err=%v", cmd2.StatusMode, err)
	}

	cmd3, err := Parse([]string{"status", "verbose"})
	if err != nil || cmd3.StatusMode != StatusVerbose {
		t.Errorf("expected status verbose, got %v, err=%v", cmd3.StatusMode, err)
	}
}

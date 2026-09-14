package backend

import (
	"fmt"
	"os/exec"
	"strings"
	"ufw/internal/rule"

	"golang.org/x/sys/windows/registry"
)

type FirewallStatus struct {
	Active          bool
	Logging         string
	DefaultInbound  string
	DefaultOutbound string
}

type Backend interface {
	GetStatus() (*FirewallStatus, error)
	ApplyRule(r *rule.Rule) error
	DeleteRule(r *rule.Rule) error
}

type WindowsBackend struct{}

func New() *WindowsBackend {
	return &WindowsBackend{}
}

// GetStatus retrieves the firewall status and default policies from the Windows Registry.
func (b *WindowsBackend) GetStatus() (*FirewallStatus, error) {
	status := &FirewallStatus{
		Active:          true, // Default to true on Windows unless explicitly disabled
		Logging:         "off",
		DefaultInbound:  "deny (incoming)",
		DefaultOutbound: "allow (outgoing)",
	}

	profiles := []string{"PublicProfile", "StandardProfile", "DomainProfile"}
	activeCount := 0

	for _, profile := range profiles {
		keyPath := fmt.Sprintf(`SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\%s`, profile)
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		defer k.Close()

		if val, _, err := k.GetIntegerValue("EnableFirewall"); err == nil {
			if val == 1 {
				activeCount++
			}
		}

		if val, _, err := k.GetIntegerValue("DefaultInboundAction"); err == nil {
			if val == 0 {
				status.DefaultInbound = "allow (incoming)"
			} else {
				status.DefaultInbound = "deny (incoming)"
			}
		}

		if val, _, err := k.GetIntegerValue("DefaultOutboundAction"); err == nil {
			if val == 1 {
				status.DefaultOutbound = "deny (outgoing)"
			} else {
				status.DefaultOutbound = "allow (outgoing)"
			}
		}

		if val, _, err := k.GetIntegerValue("LogDroppedPackets"); err == nil && val == 1 {
			status.Logging = "on (low)"
		}
	}

	if activeCount == 0 {
		status.Active = false
	}

	return status, nil
}

// ApplyRule creates the required rule(s) in Windows Defender Firewall via netsh.
func (b *WindowsBackend) ApplyRule(r *rule.Rule) error {
	specs := r.ToWindowsSpecs()
	for _, spec := range specs {
		args := []string{
			"advfirewall", "firewall", "add", "rule",
			"name=" + spec.RuleName,
			"dir=" + spec.Direction,
			"action=" + spec.Action,
			"enable=yes",
			"description=Managed by UFW for Windows",
		}

		if spec.Protocol != "" {
			args = append(args, "protocol="+spec.Protocol)
		}
		if spec.LocalPort != "" {
			args = append(args, "localport="+spec.LocalPort)
		}
		if spec.RemoteIP != "" {
			args = append(args, "remoteip="+spec.RemoteIP)
		}

		cmd := exec.Command("netsh", args...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to add firewall rule '%s': %v (output: %s)", spec.RuleName, err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// DeleteRule removes the matching rule(s) from Windows Defender Firewall via netsh.
func (b *WindowsBackend) DeleteRule(r *rule.Rule) error {
	specs := r.ToWindowsSpecs()
	for _, spec := range specs {
		cmd := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+spec.RuleName)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to delete firewall rule '%s': %v (output: %s)", spec.RuleName, err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

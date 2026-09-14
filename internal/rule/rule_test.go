package rule

import (
	"testing"
)

func TestRuleToWindowsSpecs(t *testing.T) {
	// Test port without protocol -> expands to TCP and UDP specs
	r1 := &Rule{
		ID:        1,
		Action:    Allow,
		Direction: In,
		Port:      "51312",
		From:      "Anywhere",
	}
	specs1 := r1.ToWindowsSpecs()
	if len(specs1) != 2 {
		t.Fatalf("expected 2 specs, got %d", len(specs1))
	}
	if specs1[0].Protocol != "TCP" || specs1[1].Protocol != "UDP" {
		t.Errorf("expected TCP and UDP protocols, got %s and %s", specs1[0].Protocol, specs1[1].Protocol)
	}

	// Test port range with proto
	r2 := &Rule{
		ID:        2,
		Action:    Allow,
		Direction: In,
		Protocol:  "tcp",
		Port:      "51312:51314",
		From:      "192.168.0.0/24",
	}
	specs2 := r2.ToWindowsSpecs()
	if len(specs2) != 1 {
		t.Fatalf("expected 1 spec, got %d", len(specs2))
	}
	if specs2[0].LocalPort != "51312-51314" {
		t.Errorf("expected 51312-51314, got %s", specs2[0].LocalPort)
	}
	if specs2[0].RemoteIP != "192.168.0.0/24" {
		t.Errorf("expected 192.168.0.0/24, got %s", specs2[0].RemoteIP)
	}

	// Test IP block rule
	r3 := &Rule{
		ID:        3,
		Action:    Deny,
		Direction: In,
		From:      "199.115.117.99",
	}
	specs3 := r3.ToWindowsSpecs()
	if len(specs3) != 1 {
		t.Fatalf("expected 1 spec, got %d", len(specs3))
	}
	if specs3[0].Action != "block" {
		t.Errorf("expected block, got %s", specs3[0].Action)
	}
	if specs3[0].RemoteIP != "199.115.117.99" {
		t.Errorf("expected 199.115.117.99, got %s", specs3[0].RemoteIP)
	}
}

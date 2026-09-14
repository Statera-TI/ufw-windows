package backend

import (
	"testing"
)

func TestGetStatus(t *testing.T) {
	b := New()
	status, err := b.GetStatus()
	if err != nil {
		t.Fatalf("GetStatus failed: %v", err)
	}
	t.Logf("Active: %v, Logging: %s, Inbound: %s, Outbound: %s",
		status.Active, status.Logging, status.DefaultInbound, status.DefaultOutbound)
}

package util

import (
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestElevationChecks(t *testing.T) {
	// Method 1: shell32 IsUserAnAdmin
	shell32 := syscall.NewLazyDLL("shell32.dll")
	procIsUserAnAdmin := shell32.NewProc("IsUserAnAdmin")
	ret, _, _ := procIsUserAnAdmin.Call()
	t.Logf("IsUserAnAdmin: %v", ret != 0)

	// Method 2: TokenElevation
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)
	if err != nil {
		t.Fatalf("OpenProcessToken error: %v", err)
	}
	defer token.Close()

	var elevation uint32
	var returnedLen uint32
	err = windows.GetTokenInformation(
		token,
		windows.TokenElevation,
		(*byte)(unsafe.Pointer(&elevation)),
		uint32(unsafe.Sizeof(elevation)),
		&returnedLen,
	)
	if err != nil {
		t.Fatalf("GetTokenInformation error: %v", err)
	}
	t.Logf("TokenElevation: %v", elevation != 0)
}

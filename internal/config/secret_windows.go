//go:build windows

package config

// Windows DPAPI-backed secret storage.
//
// The secret (64 hex chars) is encrypted with CryptProtectData (DPAPI) using
// CRYPTPROTECT_LOCAL_MACHINE so that only processes running on this specific
// machine (not user-specific) can decrypt it. The encrypted blob is stored
// in SecretFile().
//
// This uses the Windows crypt32.dll APIs via golang.org/x/sys/windows.

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	crypt32 = windows.NewLazySystemDLL("crypt32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procCryptProtectData   = crypt32.NewProc("CryptProtectData")
	procCryptUnprotectData = crypt32.NewProc("CryptUnprotectData")
	procLocalFree          = kernel32.NewProc("LocalFree")
)

type dataBlob struct {
	cbData uint32
	pbData *byte
}

func newBlob(d []byte) *dataBlob {
	if len(d) == 0 {
		return &dataBlob{}
	}
	return &dataBlob{
		cbData: uint32(len(d)),
		pbData: &d[0],
	}
}

func (b *dataBlob) toByteArray() []byte {
	if b.cbData == 0 {
		return nil
	}
	d := make([]byte, b.cbData)
	copy(d, unsafe.Slice(b.pbData, b.cbData))
	return d
}

const cryptProtectLocalMachine = 0x4

func protect(in []byte) ([]byte, error) {
	inBlob := newBlob(in)
	var outBlob dataBlob
	r, _, err := procCryptProtectData.Call(
		uintptr(unsafe.Pointer(inBlob)),
		0, 0, 0, 0,
		cryptProtectLocalMachine,
		uintptr(unsafe.Pointer(&outBlob)),
	)
	if r == 0 {
		return nil, fmt.Errorf("CryptProtectData: %w", err)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outBlob.pbData)))
	return outBlob.toByteArray(), nil
}

func unprotect(in []byte) ([]byte, error) {
	inBlob := newBlob(in)
	var outBlob dataBlob
	r, _, err := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(inBlob)),
		0, 0, 0, 0,
		cryptProtectLocalMachine,
		uintptr(unsafe.Pointer(&outBlob)),
	)
	if r == 0 {
		return nil, fmt.Errorf("CryptUnprotectData: %w", err)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outBlob.pbData)))
	return outBlob.toByteArray(), nil
}

func storeSecretPlatform(hexKey string) error {
	encrypted, err := protect([]byte(hexKey))
	if err != nil {
		return fmt.Errorf("dpapi encrypt: %w", err)
	}
	if err := os.WriteFile(SecretFile(), encrypted, 0600); err != nil {
		return fmt.Errorf("write secret: %w", err)
	}
	return nil
}

func loadSecretPlatform() (string, error) {
	data, err := os.ReadFile(SecretFile())
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("secret not set — run 'local-agent set-secret --key <64-hex-chars>'")
		}
		return "", fmt.Errorf("read secret: %w", err)
	}
	decrypted, err := unprotect(data)
	if err != nil {
		return "", fmt.Errorf("dpapi decrypt: %w (this usually means the secret was stored on a different machine)", err)
	}
	return string(decrypted), nil
}

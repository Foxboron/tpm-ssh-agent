package key_test

import (
	"crypto"
	"fmt"
	"io"
	"testing"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/foxboron/ssh-tpm-agent/internal/keyring"
	"github.com/foxboron/ssh-tpm-agent/key"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

func TestHierKey(t *testing.T) {
	tpm, err := transport.OpenTPM()
	if err != nil {
		t.Fatalf("%v", err)
	}

	hkey, err := key.CreateHierarchyKey(tpm, tpm2.TPMAlgECC, tpm2.TPMRHOwner, "")
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer hkey.FlushHandle(tpm)

	if hkey.Fingerprint() != "SHA256:PmEsMeh/DwFP04iUaWLNeX4maMR6r1vfqw1BbbdFjIg" {
		t.Fatalf("ssh key fingerprint does not match")
	}
}

func TestHierKeySigning(t *testing.T) {
	tpm, err := transport.OpenTPM()
	if err != nil {
		t.Fatalf("%v", err)
	}

	hkey, err := key.CreateHierarchyKey(tpm, tpm2.TPMAlgECC, tpm2.TPMRHOwner, "")
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer hkey.FlushHandle(tpm)

	h := crypto.SHA256.New()
	h.Write([]byte("message"))
	b := h.Sum(nil)

	sig, err := hkey.Sign(tpm, []byte(nil), []byte(nil), b[:], tpm2.TPMAlgSHA256)
	if err != nil {
		t.Fatalf("%v", err)
	}
	fmt.Println(sig)
}

func TestHierKeySigner(t *testing.T) {
	tpm, err := transport.OpenTPM()
	if err != nil {
		t.Fatalf("%v", err)
	}

	hkey, err := key.CreateHierarchyKey(tpm, tpm2.TPMAlgECC, tpm2.TPMRHOwner, "")
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer hkey.FlushHandle(tpm)
	signer := hkey.Signer(&keyring.ThreadKeyring{},
		func() ([]byte, error) { return []byte(nil), nil },
		func() transport.TPMCloser { return tpm },
		func(_ *keyfile.TPMKey) ([]byte, error) { return []byte(nil), nil },
	)
	h := crypto.SHA256.New()
	h.Write([]byte("message"))
	b := h.Sum(nil)
	sig, err := signer.Sign((io.Reader)(nil), b[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("message")
	}
	fmt.Println(sig)
}

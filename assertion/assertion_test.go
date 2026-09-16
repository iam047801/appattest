package assertion

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/bas-d/appattest/authenticator"
)

const publicKey = "0437c404fa2bbf8fbcf4ee7080573d5fa80c4f6cc3a22f7db43af92c394e7cd1c880c95ab422972625e8e673af1bda2b096654e9b602895601f925bb5941c53082"
const assertion = `{ 
	"assertion": "omlzaWduYXR1cmVYRzBFAiEAyC5S3pcvtSpmTfNSd8aJRJCQ6PbN7Dnv_oPkZNMLeIwCIBmxCHXKYyGswzp_LwOxoL18puHooxudXWqDgtTvRomdcWF1dGhlbnRpY2F0b3JEYXRhWCV87ytV2nJBCLqRJ5b2df8AvnHVLa4mj6aI00ym0n9wdEAAAAAD",
	"clientData": "eyJjaGFsbGVuZ2UiOiJhc3NlcnRpb24tdGVzdCJ9"
}`

func TestAssertionVerififcation(t *testing.T) {
	t.Run("Testing assertion", func(t *testing.T) {
		aar := AuthenticatorAssertionResponse{}
		if err := json.Unmarshal([]byte(assertion), &aar); err != nil {
			t.Fatal(err)
		}

		decodedPk, err := hex.DecodeString(publicKey)
		if err != nil {
			t.Fatalf("Could not decode public key: %+s", publicKey)
		}
		_, err = aar.Verify("assertion-test", "35MFYY2JY5.co.chiff.attestation-test", 0, decodedPk)
		if err != nil {
			t.Fatalf("Not valid: %+v", err)
		}
	})
}

// Built here around the iOS 27 authenticator data from appattest-swift PR #81
// (https://github.com/zunda-pixel/appattest-swift/pull/81). The signature is
// filler, so only parsing can be driven with it.
const ios27Assertion = `{
	"assertion": "omlzaWduYXR1cmVYSDBFAiEAqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqoCIQC7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u3FhdXRoZW50aWNhdG9yRGF0YVhj_3PQmDDZvKc1qrflz10gRrcebJM0xpafxRfN6ujU13_AAAAAAaJ3YXBwbGVfYnVuZGxlX3ZlcnNpb25fMDFhMXgcYXBwbGVfdmFsaWRhdGlvbl9jYXRlZ29yeV8wMUQDAAAA",
	"clientData": "eyJjaGFsbGVuZ2UiOiJpb3MyNy1hc3NlcnRpb24tdGVzdCJ9"
}`

// iOS 27.0 sets the AT flag on assertions, which never carry attested credential
// data. Reading the flags, or treating "longer than 37 bytes" as meaning attested
// credential data is present, reads this fixture's extension map as a 16 byte
// AAGUID plus a credential ID length of 25970, and slicing that out of 99 bytes
// panics.
//
// The signature is synthetic, so this drives parse() rather than Verify.
func TestParseIOS27Assertion(t *testing.T) {
	aar := AuthenticatorAssertionResponse{}
	if err := json.Unmarshal([]byte(ios27Assertion), &aar); err != nil {
		t.Fatal(err)
	}

	a, err := aar.parse()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if len(a.RawAuthenticatorData) != 99 {
		t.Errorf("authenticator data length = %d, want 99", len(a.RawAuthenticatorData))
	}
	if got := a.RawAuthenticatorData[32]; got != 0xc0 {
		t.Errorf("flags = %#02x, want 0xc0", got)
	}
	if !a.AuthenticatorData.Flags.HasAttestedCredentialData() {
		t.Error("expected the AT flag to be set, as iOS 27.0 sets it on assertions")
	}
	if len(a.AuthenticatorData.AttData.AAGUID) != 0 {
		t.Errorf("AAGUID = %q, want no attested credential data despite the AT flag",
			a.AuthenticatorData.AttData.AAGUID)
	}
	if a.AuthenticatorData.Counter != 1 {
		t.Errorf("counter = %d, want 1", a.AuthenticatorData.Counter)
	}

	ext := a.AuthenticatorData.Extensions
	if ext == nil {
		t.Fatal("extensions were not parsed")
	}
	if ext.ValidationCategory == nil {
		t.Fatal("validation category was not parsed")
	}
	if *ext.ValidationCategory != authenticator.ValidationCategoryDevelopment {
		t.Errorf("validation category = %v, want %v",
			*ext.ValidationCategory, authenticator.ValidationCategoryDevelopment)
	}
	if ext.BundleVersion == nil || *ext.BundleVersion != "1" {
		t.Errorf("bundle version = %v, want \"1\"", ext.BundleVersion)
	}
}

// The nonce has to be computed over the authenticator data exactly as received,
// extension bytes included, or the signature will never verify on iOS 27.
func TestAssertionNonceUsesTheAuthenticatorDataAsReceived(t *testing.T) {
	aar := AuthenticatorAssertionResponse{}
	if err := json.Unmarshal([]byte(ios27Assertion), &aar); err != nil {
		t.Fatal(err)
	}
	a, err := aar.parse()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	before := append([]byte(nil), a.RawAuthenticatorData...)
	extBefore := append([]byte(nil), a.AuthenticatorData.ExtData...)

	// Verify fails on the signature, which is expected: the point is what it does
	// to the buffers on the way there.
	if _, err := aar.Verify("ios27-assertion-test", "example.app", 0, make([]byte, 65)); err == nil {
		t.Fatal("expected verification to fail for this synthetic signature")
	}

	if !bytes.Equal(a.RawAuthenticatorData, before) {
		t.Errorf("authenticator data was modified: %x, want %x", a.RawAuthenticatorData, before)
	}
	if !bytes.Equal(a.AuthenticatorData.ExtData, extBefore) {
		t.Errorf("extension bytes were modified: %x, want %x", a.AuthenticatorData.ExtData, extBefore)
	}
}

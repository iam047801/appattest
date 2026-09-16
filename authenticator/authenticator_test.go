package authenticator

import (
	"bytes"
	"encoding/base64"
	"testing"
)

// All of the fixtures below reach this repository through appattest-swift PR #81,
// which added the same support upstream:
// https://github.com/zunda-pixel/appattest-swift/pull/81
//
// That PR quotes the sample attestation object from Apple's attestation object
// validation guide, and attributes the two iOS 27 captures to a device without
// evidence that can be checked from here. The sample needs no such trust: the
// nonce in its credCert is the SHA256 of these 226 bytes followed by
// "example_server_challenge", which the attestation package tests recompute.
// https://developer.apple.com/documentation/devicecheck/attestation-object-validation-guide

// Attestation authenticator data from Apple's sample. Its flags byte is 0x40, so
// AT is set and ED is clear, even though 62 bytes of extension data follow the
// credential public key.
const appleSampleAttestationAuthData = "9EZtaPketsEGIMt+Y8coMkRoXuHWRntUFg51MXIFfwNAAAAAAGFwcGF0dGVzdAAAAAAAAAAAIM4EmPWEg/u02g17LGOlpTj1UtSty5pPqRYZXElhPmVdpQECAyYgASFYIEMyVErPMj23dEQ8qvM59W5+lcck+sLBQlnzZeJEVlCyIlggtfsoW89Um8tgWUQS52gqJCfuran7Ut/tCxqxftCfqb2id2FwcGxlX2J1bmRsZV92ZXJzaW9uXzAxYTF4HGFwcGxlX3ZhbGlkYXRpb25fY2F0ZWdvcnlfMDFEAQAAAA=="

// Apple's sample truncated after the credential public key, which is what an OS
// older than iOS 27 emits.
const preIOS27AttestationAuthData = "9EZtaPketsEGIMt+Y8coMkRoXuHWRntUFg51MXIFfwNAAAAAAGFwcGF0dGVzdAAAAAAAAAAAIM4EmPWEg/u02g17LGOlpTj1UtSty5pPqRYZXElhPmVdpQECAyYgASFYIEMyVErPMj23dEQ8qvM59W5+lcck+sLBQlnzZeJEVlCyIlggtfsoW89Um8tgWUQS52gqJCfuran7Ut/tCxqxftCfqb0="

// An iOS 27 attestation. This one sets ED, so the two attestation fixtures
// together cover both spellings of the flags byte.
const ios27AttestationAuthData = "/3PQmDDZvKc1qrflz10gRrcebJM0xpafxRfN6ujU13/AAAAAAGFwcGF0dGVzdGRldmVsb3AAIEAAk2q9eHprerZmvx9QYVNe/TzH8t2tosuYiIs414s1pQECAyYgASFYIESVZHRrpydBHQg0wy/OjBC3Q2tSVZCfSQ3q3wrTI2kzIlggwd0u/mQpFQPijjFgX59bwG1WeRsULAb0CGuE6EgKtgKid2FwcGxlX2J1bmRsZV92ZXJzaW9uXzAxYTF4HGFwcGxlX3ZhbGlkYXRpb25fY2F0ZWdvcnlfMDFEAwAAAA=="

// Hand-built: the RP ID hash of Apple's sample, clear flags, counter 2, nothing
// after it.
const assertionAuthDataWithoutExtensions = "9EZtaPketsEGIMt+Y8coMkRoXuHWRntUFg51MXIFfwMAAAAAAg=="

// Read out of appleSampleAttestationAuthData.
const (
	appleSampleCredentialID = "zgSY9YSD+7TaDXssY6WlOPVS1K3Lmk+pFhlcSWE+ZV0="
	appleSampleRPIDHash     = "9EZtaPketsEGIMt+Y8coMkRoXuHWRntUFg51MXIFfwM="
)

func decodeFixture(t *testing.T, name, b64 string) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("could not decode fixture %s: %v", name, err)
	}
	return raw
}

func unmarshalFixture(t *testing.T, name, b64 string) *AuthenticatorData {
	t.Helper()
	var a AuthenticatorData
	if err := a.Unmarshal(decodeFixture(t, name, b64)); err != nil {
		t.Fatalf("could not unmarshal fixture %s: %v", name, err)
	}
	return &a
}

func requireExtensions(t *testing.T, a *AuthenticatorData) (ValidationCategory, string) {
	t.Helper()
	if a.Extensions == nil {
		t.Fatal("expected extensions to be present")
	}
	if a.Extensions.ValidationCategory == nil {
		t.Fatal("expected a validation category")
	}
	if a.Extensions.BundleVersion == nil {
		t.Fatal("expected a bundle version")
	}
	return *a.Extensions.ValidationCategory, *a.Extensions.BundleVersion
}

// The sample from Apple's validation guide leaves ED clear while still appending
// extensions, so the extensions have to be found without consulting the flags.
func TestUnmarshalAppleSampleAttestationAuthData(t *testing.T) {
	raw := decodeFixture(t, "appleSampleAttestationAuthData", appleSampleAttestationAuthData)
	if len(raw) != 226 {
		t.Fatalf("expected 226 bytes of authenticator data, got %d", len(raw))
	}

	var a AuthenticatorData
	if err := a.Unmarshal(raw); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if a.Flags.HasExtensions() {
		t.Error("expected the ED flag to be clear in Apple's sample")
	}
	if !a.Flags.HasAttestedCredentialData() {
		t.Error("expected the AT flag to be set")
	}
	if a.Counter != 0 {
		t.Errorf("expected counter 0, got %d", a.Counter)
	}

	if got := base64.StdEncoding.EncodeToString(a.RPIDHash); got != appleSampleRPIDHash {
		t.Errorf("RP ID hash = %s, want %s", got, appleSampleRPIDHash)
	}
	if !bytes.Equal(a.AttData.AAGUID, aaguidProduction) {
		t.Errorf("AAGUID = %q, want the production AAGUID", a.AttData.AAGUID)
	}
	if got := base64.StdEncoding.EncodeToString(a.AttData.CredentialID); got != appleSampleCredentialID {
		t.Errorf("credential ID = %s, want %s", got, appleSampleCredentialID)
	}

	if len(a.ExtData) != 62 {
		t.Errorf("expected 62 bytes of extension data, got %d", len(a.ExtData))
	}
	category, bundleVersion := requireExtensions(t, &a)
	if category != ValidationCategoryPlatform {
		t.Errorf("validation category = %v, want %v", category, ValidationCategoryPlatform)
	}
	if bundleVersion != "1" {
		t.Errorf("bundle version = %q, want %q", bundleVersion, "1")
	}
}

// The extension bytes are covered by the attestation nonce, so they have to stay
// in the authenticator data, and the caller's buffer has to survive the parse
// intact for the nonce to be recomputable from it.
func TestUnmarshalDoesNotDisturbTheNonceInput(t *testing.T) {
	raw := decodeFixture(t, "appleSampleAttestationAuthData", appleSampleAttestationAuthData)
	before := append([]byte(nil), raw...)

	var a AuthenticatorData
	if err := a.Unmarshal(raw); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if !bytes.Equal(raw, before) {
		t.Fatal("Unmarshal modified the authenticator data it was given")
	}
	if !bytes.Equal(a.ExtData, before[164:]) {
		t.Error("ExtData is not the trailing bytes of the authenticator data")
	}
}

func TestUnmarshalPreIOS27AttestationAuthData(t *testing.T) {
	a := unmarshalFixture(t, "preIOS27AttestationAuthData", preIOS27AttestationAuthData)

	if a.Extensions != nil {
		t.Errorf("expected no extensions, got %+v", a.Extensions)
	}
	if a.ExtData != nil {
		t.Errorf("expected no extension data, got %x", a.ExtData)
	}

	// This fixture is the sample truncated after the credential public key.
	full := unmarshalFixture(t, "appleSampleAttestationAuthData", appleSampleAttestationAuthData)
	if !bytes.Equal(a.AttData.AAGUID, full.AttData.AAGUID) {
		t.Error("AAGUID differs from the untruncated fixture")
	}
	if !bytes.Equal(a.AttData.CredentialID, full.AttData.CredentialID) {
		t.Error("credential ID differs from the untruncated fixture")
	}
	if !bytes.Equal(a.AttData.CredentialPublicKey, full.AttData.CredentialPublicKey) {
		t.Error("credential public key differs from the untruncated fixture")
	}
}

func TestUnmarshalIOS27AttestationAuthData(t *testing.T) {
	a := unmarshalFixture(t, "ios27AttestationAuthData", ios27AttestationAuthData)

	if !a.Flags.HasExtensions() {
		t.Error("expected the ED flag to be set in the iOS 27.0 capture")
	}
	if !bytes.Equal(a.AttData.AAGUID, aaguidDevelopment) {
		t.Errorf("AAGUID = %q, want the development AAGUID", a.AttData.AAGUID)
	}

	category, bundleVersion := requireExtensions(t, a)
	if category != ValidationCategoryDevelopment {
		t.Errorf("validation category = %v, want %v", category, ValidationCategoryDevelopment)
	}
	if bundleVersion != "1" {
		t.Errorf("bundle version = %q, want %q", bundleVersion, "1")
	}
}

// An extension map holding nothing this version recognises still reports as
// present, so that a future renaming does not read as a pre-iOS-27 device.
func TestUnmarshalUnrecognisedExtensionMap(t *testing.T) {
	raw := decodeFixture(t, "assertionAuthDataWithoutExtensions", assertionAuthDataWithoutExtensions)
	// CBOR: {"other": 1}
	raw = append(raw, 0xa1, 0x65, 'o', 't', 'h', 'e', 'r', 0x01)

	var a AuthenticatorData
	if err := a.Unmarshal(raw); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if a.Extensions == nil {
		t.Fatal("expected extensions to be reported as present")
	}
	if a.Extensions.ValidationCategory != nil {
		t.Errorf("expected no validation category, got %v", *a.Extensions.ValidationCategory)
	}
	if a.Extensions.BundleVersion != nil {
		t.Errorf("expected no bundle version, got %q", *a.Extensions.BundleVersion)
	}
	if _, ok := a.Extensions.Raw["other"]; !ok {
		t.Errorf("expected the unrecognised key to survive in Raw, got %+v", a.Extensions.Raw)
	}
}

// A known key carrying an unexpected value type is tolerated: the field reads as
// absent rather than failing an otherwise valid assertion. Apple documents the
// category as a UInt32 and devices send a four byte string, so a text string is
// neither.
func TestUnmarshalExtensionWithUnexpectedValueTypes(t *testing.T) {
	raw := decodeFixture(t, "assertionAuthDataWithoutExtensions", assertionAuthDataWithoutExtensions)
	// CBOR: {"apple_validation_category_01": "4", "apple_bundle_version_01": 1}
	raw = append(raw, 0xa2, 0x78, 0x1c)
	raw = append(raw, ExtensionKeyValidationCategory...)
	raw = append(raw, 0x61, '4')
	raw = append(raw, 0x77)
	raw = append(raw, ExtensionKeyBundleVersion...)
	raw = append(raw, 0x01)

	var a AuthenticatorData
	if err := a.Unmarshal(raw); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if a.Extensions == nil {
		t.Fatal("expected extensions to be reported as present")
	}
	if a.Extensions.ValidationCategory != nil {
		t.Errorf("expected a text category to read as absent, got %v", *a.Extensions.ValidationCategory)
	}
	if a.Extensions.BundleVersion != nil {
		t.Errorf("expected an integer bundle version to read as absent, got %q", *a.Extensions.BundleVersion)
	}
	if len(a.Extensions.Raw) != 2 {
		t.Errorf("expected both keys to survive in Raw, got %+v", a.Extensions.Raw)
	}
}

func TestUnmarshalRejectsMalformedTrailingBytes(t *testing.T) {
	base := decodeFixture(t, "assertionAuthDataWithoutExtensions", assertionAuthDataWithoutExtensions)

	trailing := map[string][]byte{
		"a CBOR text string rather than a map": {0x65, 'o', 't', 'h', 'e', 'r'},
		"a truncated map":                      {0xa1, 0x65, 'o', 't'},
		"a map followed by another item":       {0xa0, 0x01},
	}

	for name, suffix := range trailing {
		t.Run(name, func(t *testing.T) {
			raw := append(append([]byte(nil), base...), suffix...)
			var a AuthenticatorData
			if err := a.Unmarshal(raw); err == nil {
				t.Errorf("expected an error, got extensions %+v", a.Extensions)
			}
		})
	}
}

// The credential public key has to be handed back exactly as it arrived, and the
// same on every parse. Deriving it by re-encoding the decoded COSE map emits the
// entries in Go map iteration order, which shuffles them at random.
func TestUnmarshalCredentialPublicKeyIsTheOriginalBytes(t *testing.T) {
	raw := decodeFixture(t, "preIOS27AttestationAuthData", preIOS27AttestationAuthData)
	first := unmarshalFixture(t, "preIOS27AttestationAuthData", preIOS27AttestationAuthData)

	want := raw[credentialIDOffset+len(first.AttData.CredentialID):]
	if !bytes.Equal(first.AttData.CredentialPublicKey, want) {
		t.Errorf("credential public key = %x, want %x", first.AttData.CredentialPublicKey, want)
	}

	for i := 0; i < 50; i++ {
		var a AuthenticatorData
		if err := a.Unmarshal(raw); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		if !bytes.Equal(a.AttData.CredentialPublicKey, want) {
			t.Fatalf("credential public key is not stable across parses: got %x on parse %d, want %x",
				a.AttData.CredentialPublicKey, i+2, want)
		}
	}
}

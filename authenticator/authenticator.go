package authenticator

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/bas-d/appattest/utils"
	"github.com/ugorji/go/codec"
)

const (
	// minAuthDataLength is the size of the fixed portion of the authenticator
	// data: a 32 byte RP ID hash, a flags byte and a four byte counter.
	minAuthDataLength      = 37
	aaguidLength           = 16
	attestedCredDataOffset = minAuthDataLength
	credentialIDLenOffset  = attestedCredDataOffset + aaguidLength
	credentialIDOffset     = credentialIDLenOffset + 2
)

// The two AAGUIDs App Attest uses. Step 8 of Apple's validation procedure
// requires the attested credential data to carry one of them, depending on the
// environment the attestation was produced in.
//
// These are deliberately not exported. They are slices, so an exported one could
// be overwritten by any importer, and step 8 would then compare against whatever
// it had been changed to.
var (
	aaguidProduction  = appAttestAAGUID("appattest")
	aaguidDevelopment = appAttestAAGUID("appattestdevelop")
)

func appAttestAAGUID(name string) []byte {
	aaguid := make([]byte, aaguidLength)
	copy(aaguid, name)
	return aaguid
}

// Authenticators respond to Relying Party requests by returning an object derived from the
// AuthenticatorResponse interface. See §5.2. Authenticator Responses
// https://www.w3.org/TR/webauthn/#iface-authenticatorresponse
type AuthenticatorResponse struct {
	// From the spec https://www.w3.org/TR/webauthn/#dom-authenticatorresponse-clientdatajson
	// This attribute contains a JSON serialization of the client data passed to the authenticator
	// by the client in its call to either create() or get().
	ClientDataJSON utils.URLEncodedBase64 `json:"clientDataJSON"`
}

// AuthenticatorData From §6.1 of the spec.
// The authenticator data structure encodes contextual bindings made by the authenticator. These bindings
// are controlled by the authenticator itself, and derive their trust from the WebAuthn Relying Party's
// assessment of the security properties of the authenticator. In one extreme case, the authenticator
// may be embedded in the client, and its bindings may be no more trustworthy than the client data.
// At the other extreme, the authenticator may be a discrete entity with high-security hardware and
// software, connected to the client over a secure channel. In both cases, the Relying Party receives
// the authenticator data in the same format, and uses its knowledge of the authenticator to make
// trust decisions.
//
// The authenticator data, at least during attestation, contains the Public Key that the RP stores
// and will associate with the user attempting to register.
type AuthenticatorData struct {
	RPIDHash []byte                 `json:"rpid"`
	Flags    AuthenticatorFlags     `json:"flags"`
	Counter  uint32                 `json:"sign_count"`
	AttData  AttestedCredentialData `json:"att_data"`
	// ExtData holds the raw CBOR bytes of the extension map, as they appeared in
	// the authenticator data. It is nil when no extension data was present.
	ExtData []byte `json:"ext_data"`
	// Extensions holds the decoded extension map. It is nil when no extension
	// data was present, which is the case for every authenticator predating
	// iOS 27 and its sibling releases.
	Extensions *Extensions `json:"extensions,omitempty"`
}

type AttestedCredentialData struct {
	AAGUID       []byte `json:"aaguid"`
	CredentialID []byte `json:"credential_id"`
	// The raw credential public key bytes received from the attestation data
	CredentialPublicKey []byte `json:"public_key"`
}

// AuthenticatorAttachment https://www.w3.org/TR/webauthn/#platform-attachment
type AuthenticatorAttachment string

const (
	// Platform - A platform authenticator is attached using a client device-specific transport, called
	// platform attachment, and is usually not removable from the client device. A public key credential
	//  bound to a platform authenticator is called a platform credential.
	Platform AuthenticatorAttachment = "platform"
	// CrossPlatform A roaming authenticator is attached using cross-platform transports, called
	// cross-platform attachment. Authenticators of this class are removable from, and can "roam"
	// among, client devices. A public key credential bound to a roaming authenticator is called a
	// roaming credential.
	CrossPlatform AuthenticatorAttachment = "cross-platform"
)

// Authenticators may implement various transports for communicating with clients. This enumeration defines
// hints as to how clients might communicate with a particular authenticator in order to obtain an assertion
// for a specific credential. Note that these hints represent the WebAuthn Relying Party's best belief as to
// how an authenticator may be reached. A Relying Party may obtain a list of transports hints from some
// attestation statement formats or via some out-of-band mechanism; it is outside the scope of this
// specification to define that mechanism.
// See §5.10.4. Authenticator Transport https://www.w3.org/TR/webauthn/#transport
type AuthenticatorTransport string

const (
	// USB The authenticator should transport information over USB
	USB AuthenticatorTransport = "usb"
	// NFC The authenticator should transport information over Near Field Communication Protocol
	NFC AuthenticatorTransport = "nfc"
	// BLE The authenticator should transport information over Bluetooth
	BLE AuthenticatorTransport = "ble"
	// Internal the client should use an internal source like a TPM or SE
	Internal AuthenticatorTransport = "internal"
)

// A WebAuthn Relying Party may require user verification for some of its operations but not for others,
// and may use this type to express its needs.
// See §5.10.6. User Verification Requirement Enumeration https://www.w3.org/TR/webauthn/#userVerificationRequirement
type UserVerificationRequirement string

const (
	// VerificationRequired User verification is required to create/release a credential
	VerificationRequired UserVerificationRequirement = "required"
	// VerificationPreferred User verification is preferred to create/release a credential
	VerificationPreferred UserVerificationRequirement = "preferred" // This is the default
	// VerificationDiscouraged The authenticator should not verify the user for the credential
	VerificationDiscouraged UserVerificationRequirement = "discouraged"
)

// AuthenticatorFlags A byte of information returned during during ceremonies in the
// authenticatorData that contains bits that give us information about the
// whether the user was present and/or verified during authentication, and whether
// there is attestation or extension data present. Bit 0 is the least significant bit.
type AuthenticatorFlags byte

// The bits that do not have flags are reserved for future use.
const (
	// FlagUserPresent Bit 00000001 in the byte sequence. Tells us if user is present
	FlagUserPresent AuthenticatorFlags = 1 << iota // Referred to as UP
	_                                              // Reserved
	// FlagUserVerified Bit 00000100 in the byte sequence. Tells us if user is verified
	// by the authenticator using a biometric or PIN
	FlagUserVerified // Referred to as UV
	_                // Reserved
	_                // Reserved
	_                // Reserved
	// FlagAttestedCredentialData Bit 01000000 in the byte sequence. Indicates whether
	// the authenticator added attested credential data.
	FlagAttestedCredentialData // Referred to as AT
	// FlagHasExtension Bit 10000000 in the byte sequence. Indicates if the authenticator data has extensions.
	FlagHasExtensions //  Referred to as ED
)

// UserPresent returns if the UP flag was set
func (flag AuthenticatorFlags) UserPresent() bool {
	return (flag & FlagUserPresent) == FlagUserPresent
}

// UserVerified returns if the UV flag was set
func (flag AuthenticatorFlags) UserVerified() bool {
	return (flag & FlagUserVerified) == FlagUserVerified
}

// HasAttestedCredentialData returns if the AT flag was set
func (flag AuthenticatorFlags) HasAttestedCredentialData() bool {
	return (flag & FlagAttestedCredentialData) == FlagAttestedCredentialData
}

// HasExtensions returns if the ED flag was set
func (flag AuthenticatorFlags) HasExtensions() bool {
	return (flag & FlagHasExtensions) == FlagHasExtensions
}

// Unmarshal will take the raw Authenticator Data and marshalls it into AuthenticatorData for further validation.
// The authenticator data has a compact but extensible encoding. This is desired since authenticators can be
// devices with limited capabilities and low power requirements, with much simpler software stacks than the client platform.
// The authenticator data structure is a byte array of 37 bytes or more, and is laid out in this table:
// https://www.w3.org/TR/webauthn/#table-authData
func (a *AuthenticatorData) Unmarshal(rawAuthData []byte) error {
	if minAuthDataLength > len(rawAuthData) {
		err := utils.ErrBadRequest.WithDetails("Authenticator data length too short")
		info := fmt.Sprintf("Expected data greater than %d bytes. Got %d bytes\n", minAuthDataLength, len(rawAuthData))
		return err.WithDetails(info)
	}

	a.RPIDHash = rawAuthData[:32]
	a.Flags = AuthenticatorFlags(rawAuthData[32])
	a.Counter = binary.BigEndian.Uint32(rawAuthData[33:37])

	offset := minAuthDataLength

	// The flags byte cannot be used to work out what follows, in either direction:
	// Apple sets AT on assertions, which never carry attested credential data,
	// and leaves ED clear on the attestation in its own validation guide, which
	// does carry 62 bytes of extension data. The attested credential data is
	// therefore detected by the fixed AAGUID that App Attest is required to use,
	// which is the one unambiguous marker available.
	if isAppAttestAAGUID(rawAuthData[offset:]) {
		consumed, err := a.unmarshalAttestedData(rawAuthData)
		if err != nil {
			return err
		}
		offset = consumed
	}

	if offset < len(rawAuthData) {
		if err := a.unmarshalExtensions(rawAuthData[offset:]); err != nil {
			return err
		}
	}

	return nil
}

func isAppAttestAAGUID(b []byte) bool {
	if len(b) < aaguidLength {
		return false
	}
	return bytes.Equal(b[:aaguidLength], aaguidProduction) ||
		bytes.Equal(b[:aaguidLength], aaguidDevelopment)
}

// It returns the offset just past the attested credential data.
func (a *AuthenticatorData) unmarshalAttestedData(rawAuthData []byte) (int, error) {
	if len(rawAuthData) < credentialIDOffset {
		return 0, utils.ErrBadRequest.WithDetails(
			fmt.Sprintf("Authenticator data too short for attested credential data. Expected at least %d bytes. Got %d bytes\n", credentialIDOffset, len(rawAuthData)))
	}

	a.AttData.AAGUID = rawAuthData[attestedCredDataOffset:credentialIDLenOffset]

	idLength := int(binary.BigEndian.Uint16(rawAuthData[credentialIDLenOffset:credentialIDOffset]))
	if len(rawAuthData)-credentialIDOffset < idLength {
		return 0, utils.ErrBadRequest.WithDetails(
			fmt.Sprintf("Authenticator data too short for the announced credential ID length of %d bytes\n", idLength))
	}
	a.AttData.CredentialID = rawAuthData[credentialIDOffset : credentialIDOffset+idLength]

	keyOffset := credentialIDOffset + idLength
	key, consumed, err := unmarshalCredentialPublicKey(rawAuthData[keyOffset:])
	if err != nil {
		return 0, utils.ErrBadRequest.WithDetails(fmt.Sprintf("Error decoding the credential public key: %v\n", err))
	}
	a.AttData.CredentialPublicKey = key

	return keyOffset + consumed, nil
}

// It returns the key exactly as it appeared in keyBytes alongside its length,
// which is what any data following the key is located by.
func unmarshalCredentialPublicKey(keyBytes []byte) ([]byte, int, error) {
	var cborHandler codec.Handle = new(codec.CborHandle)

	// The key is decoded to validate it and, via the decoder's cursor, to measure
	// it. The bytes handed back are the original ones: re-encoding the decoded
	// value would emit the COSE map entries in Go map iteration order, so the
	// result would differ from the input, and from itself between parses.
	var m interface{}
	dec := codec.NewDecoderBytes(keyBytes, cborHandler)
	if err := dec.Decode(&m); err != nil {
		return nil, 0, err
	}
	consumed := dec.NumBytesRead()

	return keyBytes[:consumed], consumed, nil
}

// The extension map has to account for every remaining byte. Anything else means
// the authenticator data was not parsed the way its producer wrote it, and
// carrying on would mean reporting values read out of a structure that was not
// understood.
func (a *AuthenticatorData) unmarshalExtensions(extBytes []byte) error {
	var cborHandler codec.Handle = new(codec.CborHandle)

	var m map[string]interface{}
	dec := codec.NewDecoderBytes(extBytes, cborHandler)
	if err := dec.Decode(&m); err != nil {
		return utils.ErrBadRequest.WithDetails(
			fmt.Sprintf("Leftover bytes decoding AuthenticatorData: %d trailing bytes are neither an extension map nor a recognised AAGUID: %v\n", len(extBytes), err))
	}
	if consumed := int(dec.NumBytesRead()); consumed != len(extBytes) {
		return utils.ErrBadRequest.WithDetails(
			fmt.Sprintf("Leftover bytes decoding AuthenticatorData: extension map used %d of %d trailing bytes\n", consumed, len(extBytes)))
	}

	a.ExtData = extBytes
	a.Extensions = parseExtensions(m)

	return nil
}

// ResidentKeyRequired - Require that the key be private key resident to the client device
func ResidentKeyRequired() *bool {
	required := true
	return &required
}

// ResidentKeyUnrequired - Do not require that the private key be resident to the client device.
func ResidentKeyUnrequired() *bool {
	required := false
	return &required
}

func (a *AuthenticatorData) Verify(appIDHash []byte, credentialId []byte, production bool) error {

	// 6. Compute the SHA256 hash of your app’s App ID, and verify that this is the same as the authenticator data’s RP ID hash.
	if !bytes.Equal(a.RPIDHash[:], appIDHash) {
		return utils.ErrVerification.WithDetails(fmt.Sprintf("RP Hash mismatch. Expected %+s and Received %+s\n", a.RPIDHash, appIDHash))
	}

	// 7. Verify that the authenticator data’s counter field equals 0.
	if a.Counter != 0 {
		return utils.ErrVerification.WithDetails(fmt.Sprintf("Counter was not 0, but %d\n", a.Counter))
	}

	// 8. Verify that the authenticator data’s aaguid field is either appattestdevelop if operating in the development environment,
	// or appattest followed by seven 0x00 bytes if operating in the production environment.
	aaguid := aaguidDevelopment
	if production {
		aaguid = aaguidProduction
	}
	if !bytes.Equal(a.AttData.AAGUID, aaguid) {
		return utils.ErrVerification.WithDetails(fmt.Sprintf("AAGUID was not %s\n", bytes.TrimRight(aaguid, "\x00")))
	}

	// 9. Verify that the authenticator data’s credentialId field is the same as the key identifier.
	if !bytes.Equal(a.AttData.CredentialID, credentialId) {
		return utils.ErrVerification.WithDetails("Credential ID did not equal the provided key identifier\n")
	}

	return nil
}

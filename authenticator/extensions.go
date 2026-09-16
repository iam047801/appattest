package authenticator

import (
	"encoding/binary"
	"fmt"
	"math"
)

// Extension identifiers that Apple appends to the authenticator data as a CBOR
// map, starting with iOS 27, iPadOS 27, macOS 27, tvOS 27 and watchOS 27.
// See https://developer.apple.com/documentation/devicecheck/attestation-object-validation-guide
const (
	// ExtensionKeyValidationCategory maps to the code signing validation category
	// of the executable that requested the attestation or assertion.
	ExtensionKeyValidationCategory = "apple_validation_category_01"
	// ExtensionKeyBundleVersion maps to the CFBundleVersion of the requesting app.
	ExtensionKeyBundleVersion = "apple_bundle_version_01"
)

// ValidationCategory reports how the operating system validated the code that
// requested an attestation or assertion. The values mirror the
// CS_VALIDATION_CATEGORY_* constants used by the code signing subsystem.
type ValidationCategory uint32

const (
	// ValidationCategoryInvalid indicates the code has no valid validation category.
	ValidationCategoryInvalid ValidationCategory = 0
	// ValidationCategoryPlatform indicates code shipped as part of the OS.
	ValidationCategoryPlatform ValidationCategory = 1
	// ValidationCategoryTestFlight indicates a build distributed through TestFlight.
	ValidationCategoryTestFlight ValidationCategory = 2
	// ValidationCategoryDevelopment indicates a development-signed build.
	ValidationCategoryDevelopment ValidationCategory = 3
	// ValidationCategoryAppStore indicates a build distributed through the App Store.
	ValidationCategoryAppStore ValidationCategory = 4
	// ValidationCategoryEnterprise indicates an enterprise-signed build.
	ValidationCategoryEnterprise ValidationCategory = 5
	// ValidationCategoryDeveloperID indicates a Developer ID-signed build.
	ValidationCategoryDeveloperID ValidationCategory = 6
	// ValidationCategoryLocalSigning indicates locally (ad-hoc) signed code.
	ValidationCategoryLocalSigning ValidationCategory = 7
	// ValidationCategoryRosetta indicates code translated by Rosetta.
	ValidationCategoryRosetta ValidationCategory = 8
	// ValidationCategoryOOPJIT indicates out-of-process just-in-time compiled code.
	ValidationCategoryOOPJIT ValidationCategory = 9
	// ValidationCategoryNone indicates unsigned code.
	ValidationCategoryNone ValidationCategory = 10
)

func (c ValidationCategory) String() string {
	switch c {
	case ValidationCategoryInvalid:
		return "invalid"
	case ValidationCategoryPlatform:
		return "platform"
	case ValidationCategoryTestFlight:
		return "testflight"
	case ValidationCategoryDevelopment:
		return "development"
	case ValidationCategoryAppStore:
		return "app-store"
	case ValidationCategoryEnterprise:
		return "enterprise"
	case ValidationCategoryDeveloperID:
		return "developer-id"
	case ValidationCategoryLocalSigning:
		return "local-signing"
	case ValidationCategoryRosetta:
		return "rosetta"
	case ValidationCategoryOOPJIT:
		return "oop-jit"
	case ValidationCategoryNone:
		return "none"
	default:
		return fmt.Sprintf("unknown(%d)", uint32(c))
	}
}

// Extensions holds the App Attest authenticator extensions carried at the end of
// the authenticator data.
type Extensions struct {
	// ValidationCategory is the code signing validation category of the app that
	// requested the attestation or assertion.
	ValidationCategory *ValidationCategory `json:"apple_validation_category_01,omitempty"`
	// BundleVersion is the CFBundleVersion of the app that requested the
	// attestation or assertion.
	BundleVersion *string `json:"apple_bundle_version_01,omitempty"`
	// Raw is the decoded extension map exactly as it appeared on the wire,
	// including any keys this version does not recognise.
	Raw map[string]interface{} `json:"-"`
}

// validationCategoryFromCBOR decodes the validation category value.
//
// Apple's documentation describes the value as a UInt32, but devices encode it
// as a four byte little-endian CBOR byte string (for example h'03000000' for
// ValidationCategoryDevelopment). Both encodings are accepted. The second
// return value reports whether the value was understood.
func validationCategoryFromCBOR(v interface{}) (ValidationCategory, bool) {
	switch t := v.(type) {
	case []byte:
		if len(t) != 4 {
			return 0, false
		}
		return ValidationCategory(binary.LittleEndian.Uint32(t)), true
	case uint64:
		if t > math.MaxUint32 {
			return 0, false
		}
		return ValidationCategory(t), true
	case int64:
		if t < 0 || t > math.MaxUint32 {
			return 0, false
		}
		return ValidationCategory(t), true
	default:
		return 0, false
	}
}

// parseExtensions interprets a decoded extension map.
func parseExtensions(m map[string]interface{}) *Extensions {
	e := &Extensions{Raw: m}

	if v, ok := m[ExtensionKeyValidationCategory]; ok {
		if category, ok := validationCategoryFromCBOR(v); ok {
			e.ValidationCategory = &category
		}
	}

	if v, ok := m[ExtensionKeyBundleVersion]; ok {
		if s, ok := v.(string); ok {
			e.BundleVersion = &s
		}
	}

	return e
}

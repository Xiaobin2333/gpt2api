package tlsfingerprint

import (
	"fmt"
	"reflect"
	"testing"

	utls "github.com/refraction-networking/utls"
)

func TestCodexHTTPProfileMatchesCLI0148Capture(t *testing.T) {
	profile := CodexHTTPProfile()
	spec := buildClientHelloSpecFromProfile(profile)

	wantCiphers := []uint16{0x1302, 0x1301, 0x1303, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8, 0x00ff}
	wantExtensions := []uint16{0xff01, 0, 11, 10, 35, 22, 23, 13, 43, 45, 51}
	wantCurves := []uint16{0x11ec, 0x001d, 0x0017, 0x001e, 0x0018, 0x0019, 0x0100, 0x0101}
	wantKeyShares := []uint16{0x11ec, 0x001d}
	wantSignatures := []uint16{
		0x0905, 0x0906, 0x0904, 0x0403, 0x0503, 0x0603,
		0x0807, 0x0808, 0x081a, 0x081b, 0x081c, 0x0809, 0x080a, 0x080b,
		0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601,
		0x0303, 0x0301, 0x0302, 0x0402, 0x0502, 0x0602,
	}

	assertUint16s(t, "ciphers", spec.CipherSuites, wantCiphers)
	assertUint16s(t, "extensions", extensionIDs(spec.Extensions), wantExtensions)
	assertUint16s(t, "curves", profile.Curves, wantCurves)
	assertUint16s(t, "key shares", profile.KeyShareGroups, wantKeyShares)
	assertUint16s(t, "signatures", profile.SignatureAlgorithms, wantSignatures)
	assertNoALPN(t, spec.Extensions)
}

func TestCodexWebSocketProfileMatchesCLI0148CaptureAndRandomizesExtensions(t *testing.T) {
	profile := CodexWebSocketProfile()
	wantCiphers := []uint16{0x1302, 0x1301, 0x1303, 0xc02c, 0xc02b, 0xcca9, 0xc030, 0xc02f, 0xcca8, 0x00ff}
	wantCurves := []uint16{0x11ec, 0x001d, 0x0017, 0x0018}
	wantSignatures := []uint16{0x0503, 0x0403, 0x0603, 0x0807, 0x0806, 0x0805, 0x0804, 0x0601, 0x0501, 0x0401}
	wantExtensionSet := extensionSet(profile.Extensions)

	orders := make(map[string]struct{})
	for i := 0; i < 8; i++ {
		spec := buildClientHelloSpecFromProfile(profile)
		assertUint16s(t, "ciphers", spec.CipherSuites, wantCiphers)
		assertUint16s(t, "curves", profile.Curves, wantCurves)
		assertUint16s(t, "signatures", profile.SignatureAlgorithms, wantSignatures)
		if got := extensionSet(extensionIDs(spec.Extensions)); !reflect.DeepEqual(got, wantExtensionSet) {
			t.Fatalf("extension set mismatch: got %v, want %v", got, wantExtensionSet)
		}
		assertNoALPN(t, spec.Extensions)
		orders[extensionOrderKey(extensionIDs(spec.Extensions))] = struct{}{}
	}
	if len(orders) < 2 {
		t.Fatalf("rustls profile did not randomize extension order")
	}
	assertUint16s(t, "profile extensions unchanged", profile.Extensions, []uint16{0, 5, 10, 11, 13, 23, 35, 43, 45, 51})
}

func extensionIDs(extensions []utls.TLSExtension) []uint16 {
	ids := make([]uint16, 0, len(extensions))
	for _, extension := range extensions {
		switch value := extension.(type) {
		case *utls.SNIExtension:
			ids = append(ids, 0)
		case *utls.StatusRequestExtension:
			ids = append(ids, 5)
		case *utls.SupportedCurvesExtension:
			ids = append(ids, 10)
		case *utls.SupportedPointsExtension:
			ids = append(ids, 11)
		case *utls.SignatureAlgorithmsExtension:
			ids = append(ids, 13)
		case *utls.ALPNExtension:
			ids = append(ids, 16)
		case *utls.ExtendedMasterSecretExtension:
			ids = append(ids, 23)
		case *utls.SessionTicketExtension:
			ids = append(ids, 35)
		case *utls.SupportedVersionsExtension:
			ids = append(ids, 43)
		case *utls.PSKKeyExchangeModesExtension:
			ids = append(ids, 45)
		case *utls.KeyShareExtension:
			ids = append(ids, 51)
		case *utls.RenegotiationInfoExtension:
			ids = append(ids, 0xff01)
		case *utls.GenericExtension:
			ids = append(ids, value.Id)
		default:
			ids = append(ids, 0xffff)
		}
	}
	return ids
}

func assertNoALPN(t *testing.T, extensions []utls.TLSExtension) {
	t.Helper()
	for _, extension := range extensions {
		if _, ok := extension.(*utls.ALPNExtension); ok {
			t.Fatal("Codex 0.148.0 capture did not advertise ALPN")
		}
	}
}

func extensionSet(values []uint16) map[uint16]bool {
	result := make(map[uint16]bool, len(values))
	for _, value := range values {
		result[value] = true
	}
	return result
}

func extensionOrderKey(values []uint16) string {
	return fmt.Sprint(values)
}

func assertUint16s(t *testing.T, name string, got, want []uint16) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s mismatch: got %#v, want %#v", name, got, want)
	}
}

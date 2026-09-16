package tpmkey

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// Well-known NV indices for endorsement key certificates, from the TCG EK
// Credential Profile. A TPM that ships with a manufacturer certificate normally
// stores it at one of these.
var ekCertIndices = map[tpm2.TPMHandle]string{
	0x01C00002: "RSA 2048 EK certificate",
	0x01C0000A: "ECC NIST P256 EK certificate",
	0x01C00012: "RSA 2048 EK certificate (high range)",
	0x01C0001A: "ECC NIST P256 EK certificate (high range)",
}

// EKInfo is what we can learn about this TPM's endorsement key.
type EKInfo struct {
	// PublicKeyHash is SHA-256 over the EK public modulus. Manufacturers that
	// serve certificates online key them by this.
	PublicKeyHash string
	Name          string
	// Certificate is the DER certificate found in NV, if any.
	Certificate []byte
	// CertificateIndex is where it was found.
	CertificateIndex string
	// NVIndices lists every NV index defined on this TPM, so a missing
	// certificate can be distinguished from one stored somewhere unexpected.
	NVIndices []string
	// Probed records what a direct read of each well-known certificate index
	// returned. An empty NV index list is a strong claim; this is the
	// independent check on it.
	Probed []string
	// Manufacturer and firmware identify the TPM itself, and double as a
	// control: if these come back, GetCapability works and an empty NV list
	// is real.
	Manufacturer string
	VendorString string
	Firmware     string
}

// Properties reads the TPM's identity out of its fixed capabilities.
func Properties(t transport.TPM) (manufacturer, vendor, firmware string, err error) {
	rsp, err := tpm2.GetCapability{
		Capability:    tpm2.TPMCapTPMProperties,
		Property:      uint32(tpm2.TPMPTManufacturer),
		PropertyCount: 32,
	}.Execute(t)
	if err != nil {
		return "", "", "", fmt.Errorf("tpmkey: reading TPM properties: %w", err)
	}
	props, err := rsp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return "", "", "", fmt.Errorf("tpmkey: parsing TPM properties: %w", err)
	}

	var firmwareHigh, firmwareLow uint32
	for _, prop := range props.TPMProperty {
		switch prop.Property {
		case tpm2.TPMPTManufacturer:
			manufacturer = fourCC(prop.Value)
		case tpm2.TPMPTVendorString1, tpm2.TPMPTVendorString2,
			tpm2.TPMPTVendorString3, tpm2.TPMPTVendorString4:
			vendor += fourCC(prop.Value)
		case tpm2.TPMPTFirmwareVersion1:
			firmwareHigh = prop.Value
		case tpm2.TPMPTFirmwareVersion2:
			firmwareLow = prop.Value
		}
	}
	firmware = fmt.Sprintf("%d.%d.%d.%d",
		firmwareHigh>>16, firmwareHigh&0xFFFF, firmwareLow>>16, firmwareLow&0xFFFF)
	return manufacturer, strings.TrimRight(vendor, "\x00"), firmware, nil
}

// fourCC renders a property that holds four ASCII bytes, as the TPM spec uses
// for manufacturer and vendor strings.
func fourCC(v uint32) string {
	b := []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
	out := make([]byte, 0, 4)
	for _, c := range b {
		if c >= 0x20 && c < 0x7F {
			out = append(out, c)
		}
	}
	return string(out)
}

// EK creates the endorsement key from the standard RSA template and looks for a
// manufacturer certificate to go with it.
//
// The EK is the TPM's identity: a key derived from the endorsement seed, which
// never leaves the part. A certificate over it, signed by the manufacturer, is
// what turns "some TPM says so" into "a genuine TPM made by X says so". Without
// one, enrollment can only be trust-on-first-use.
func EK(t transport.TPM) (*EKInfo, error) {
	primary, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		InPublic:      tpm2.New2B(tpm2.RSAEKTemplate),
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("tpmkey: creating EK: %w", err)
	}
	defer func() {
		_, _ = tpm2.FlushContext{FlushHandle: primary.ObjectHandle}.Execute(t)
	}()

	pub, err := primary.OutPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("tpmkey: reading EK public area: %w", err)
	}
	rsaPub, err := rsaPublicKey(pub)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(rsaPub.N.Bytes())

	info := &EKInfo{
		PublicKeyHash: hex.EncodeToString(sum[:]),
		Name:          hex.EncodeToString(primary.Name.Buffer),
	}

	if manufacturer, vendor, firmware, err := Properties(t); err == nil {
		info.Manufacturer, info.VendorString, info.Firmware = manufacturer, vendor, firmware
	} else {
		info.Manufacturer = fmt.Sprintf("(unreadable: %v)", err)
	}

	// Probe the well-known indices directly, whatever the listing said.
	for index, label := range ekCertIndices {
		public, err := tpm2.NVReadPublic{NVIndex: index}.Execute(t)
		if err != nil {
			info.Probed = append(info.Probed,
				fmt.Sprintf("0x%08X %s: %v", uint32(index), label, err))
			continue
		}
		contents, err := public.NVPublic.Contents()
		size := "unknown size"
		if err == nil {
			size = fmt.Sprintf("%d bytes", contents.DataSize)
		}
		info.Probed = append(info.Probed,
			fmt.Sprintf("0x%08X %s: defined, %s", uint32(index), label, size))
	}
	sort.Strings(info.Probed)

	indices, err := nvIndices(t)
	if err != nil {
		return nil, err
	}
	for _, index := range indices {
		label, known := ekCertIndices[index]
		info.NVIndices = append(info.NVIndices, fmt.Sprintf("0x%08X %s", uint32(index), label))
		if !known || info.Certificate != nil {
			continue
		}
		cert, err := nvReadAll(t, index)
		if err != nil {
			// Report rather than fail: an index can exist but be
			// unreadable with the authorisation we have.
			info.NVIndices[len(info.NVIndices)-1] += fmt.Sprintf(" (read failed: %v)", err)
			continue
		}
		info.Certificate = cert
		info.CertificateIndex = fmt.Sprintf("0x%08X", uint32(index))
	}
	return info, nil
}

// nvIndices lists every NV index defined on the TPM.
func nvIndices(t transport.TPM) ([]tpm2.TPMHandle, error) {
	var out []tpm2.TPMHandle
	next := uint32(tpm2.TPMHTNVIndex) << 24
	for {
		rsp, err := tpm2.GetCapability{
			Capability:    tpm2.TPMCapHandles,
			Property:      next,
			PropertyCount: 64,
		}.Execute(t)
		if err != nil {
			return nil, fmt.Errorf("tpmkey: listing NV indices: %w", err)
		}
		handles, err := rsp.CapabilityData.Data.Handles()
		if err != nil {
			return nil, fmt.Errorf("tpmkey: reading NV index list: %w", err)
		}
		out = append(out, handles.Handle...)
		if !rsp.MoreData || len(handles.Handle) == 0 {
			return out, nil
		}
		next = uint32(handles.Handle[len(handles.Handle)-1]) + 1
	}
}

// nvReadAll reads a whole NV index, in chunks the TPM will accept.
func nvReadAll(t transport.TPM, index tpm2.TPMHandle) ([]byte, error) {
	public, err := tpm2.NVReadPublic{NVIndex: index}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("NVReadPublic: %w", err)
	}
	contents, err := public.NVPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("reading NV public area: %w", err)
	}

	const chunk = 512 // below TPM_PT_NV_BUFFER_MAX on every TPM we care about
	data := make([]byte, 0, contents.DataSize)
	for offset := uint16(0); offset < contents.DataSize; {
		size := contents.DataSize - offset
		if size > chunk {
			size = chunk
		}
		rsp, err := tpm2.NVRead{
			AuthHandle: tpm2.AuthHandle{
				Handle: tpm2.TPMRHOwner,
				Auth:   tpm2.PasswordAuth(nil),
			},
			NVIndex: tpm2.NamedHandle{Handle: index, Name: public.NVName},
			Size:    size,
			Offset:  offset,
		}.Execute(t)
		if err != nil {
			return nil, fmt.Errorf("NVRead at offset %d: %w", offset, err)
		}
		data = append(data, rsp.Data.Buffer...)
		offset += size
	}
	return data, nil
}

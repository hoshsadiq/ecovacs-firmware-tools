package encrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

const (
	// keyFormat is the sprintf format from the robot's fw binary used to
	// derive per-section AES keys. %d = section type, %s = hex size.
	keyFormat = "ZWNvX2Z3X3RhcmdldCAECO-PT1jdSAtpx30byBtYW4%dy5iaW4%s825xxjeff-hk@126.com"

	// After base64-encoding the formatted string, skip this many chars,
	// then truncate to the original input length before hashing.
	base64Skip = 4

	// Key and IV are extracted from hex-encoded SHA-256 at these byte offsets.
	ivStart  = 0
	ivEnd    = 16
	keyStart = 35
	keyEnd   = 51
)

// ManifestOverrides holds optional manifest field overrides for repacking.
type ManifestOverrides struct {
	FwVer       string
	HwVer       string
	Product     string
	ReleaseDate string
}

func (o *ManifestOverrides) HasAny() bool {
	return o.FwVer != "" || o.HwVer != "" || o.Product != "" || o.ReleaseDate != ""
}

// SectionMeta stores per-section metadata for repacking.
type SectionMeta struct {
	Type          string `json:"type"`
	Filename      string `json:"filename"`
	Unkn1         uint8  `json:"unkn1"`
	Unkn2         uint16 `json:"unkn2"`
	Size          int    `json:"size"`
	EncryptedSize int    `json:"encrypted_size"`
}

// metadataFile matches the metadata filename written by pkg/decrypt.
const metadataFile = ".ecovacs_sections.json"

func loadMetadata(dir string) ([]SectionMeta, error) {
	data, err := os.ReadFile(filepath.Join(dir, metadataFile))
	if err != nil {
		return nil, fmt.Errorf("read metadata: %w", err)
	}
	var metas []SectionMeta
	if err := json.Unmarshal(data, &metas); err != nil {
		return nil, fmt.Errorf("parse metadata: %w", err)
	}
	return metas, nil
}

func deriveEcovacsKey(sectionType, sectionSize int) (key, iv []byte, err error) {
	formatted := fmt.Sprintf(keyFormat, sectionType, fmt.Sprintf("%x", sectionSize))

	encoded := base64.StdEncoding.EncodeToString([]byte(formatted))
	if len(encoded) < base64Skip {
		return nil, nil, fmt.Errorf("base64 encoding too short")
	}

	truncated := encoded[base64Skip:]
	if len(truncated) > len(formatted) {
		truncated = truncated[:len(formatted)]
	}

	hash := sha256.Sum256([]byte(truncated))
	hashHex := hex.EncodeToString(hash[:])

	if len(hashHex) < keyEnd {
		return nil, nil, fmt.Errorf("hash too short for key extraction")
	}

	return []byte(hashHex[keyStart:keyEnd]), []byte(hashHex[ivStart:ivEnd]), nil
}

func computeChecksum(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func buildHeader(unkn1 uint8, unkn2 uint16, encryptedSize int) []byte {
	header := make([]byte, 8)
	header[0] = unkn1
	header[1] = 1
	binary.LittleEndian.PutUint16(header[2:4], unkn2)
	binary.LittleEndian.PutUint32(header[4:8], uint32(encryptedSize))
	return header
}

func encryptSection(plaintext []byte, sectionType, encryptedSize int) (encrypted []byte, checksum string, err error) {
	key, iv, err := deriveEcovacsKey(sectionType, encryptedSize)
	if err != nil {
		return nil, "", fmt.Errorf("derive key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, "", fmt.Errorf("create cipher: %w", err)
	}

	padLen := aes.BlockSize - len(plaintext)%aes.BlockSize
	padded := make([]byte, len(plaintext)+padLen)
	copy(padded, plaintext)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}

	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	return ciphertext, computeChecksum(ciphertext), nil
}

// encryptToSize encrypts plaintext to exactly encryptedSize bytes.
// If plaintext is shorter, PKCS7 pads to the nearest block boundary.
func encryptToSize(plaintext []byte, sectionType, targetSize int) (encrypted []byte, checksum string, err error) {
	padLen := targetSize - len(plaintext)
	if padLen < 0 {
		return nil, "", fmt.Errorf("plaintext (%d bytes) exceeds target (%d)", len(plaintext), targetSize)
	}
	if padLen > aes.BlockSize {
		return nil, "", fmt.Errorf("padding (%d bytes) exceeds block size", padLen)
	}

	padded := make([]byte, targetSize)
	copy(padded, plaintext)
	for i := len(plaintext); i < targetSize; i++ {
		padded[i] = byte(padLen)
	}

	key, iv, err := deriveEcovacsKey(sectionType, targetSize)
	if err != nil {
		return nil, "", fmt.Errorf("derive key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, "", fmt.Errorf("create cipher: %w", err)
	}

	ciphertext := make([]byte, targetSize)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	return ciphertext, computeChecksum(ciphertext), nil
}

// Repack encrypts all sections from dir and writes a single firmware binary to output.
// Keys are derived per-section from (type, encryptedSize), matching the original firmware.
// Optional overrides are applied to the manifest before encryption.
func Repack(dir, output string, overrides *ManifestOverrides) error {
	metas, err := loadMetadata(dir)
	if err != nil {
		return err
	}

	sort.Slice(metas, func(i, j int) bool {
		return metas[i].Unkn2 < metas[j].Unkn2
	})

	var out bytes.Buffer
	sectionTypes := make(map[string]int)

	for _, meta := range metas {
		sectionType := int(meta.Unkn2 >> 12)

		data, err := os.ReadFile(filepath.Join(dir, meta.Filename))
		if err != nil {
			return fmt.Errorf("read %s: %w", meta.Filename, err)
		}

		var encrypted []byte
		var checksum string

		if meta.Type == "manifest" && overrides != nil && overrides.HasAny() {
			data, err = applyOverrides(data, overrides)
			if err != nil {
				return fmt.Errorf("apply overrides: %w", err)
			}
		}

		switch sectionType {
		case 0, 1:
			// Space-pad to original decrypted size before encrypting (matches original format).
			if len(data) < meta.Size {
				padded := make([]byte, meta.Size)
				copy(padded, data)
				for i := len(data); i < meta.Size; i++ {
					padded[i] = ' '
				}
				data = padded
			}
			encrypted, checksum, err = encryptToSize(data, sectionType, meta.EncryptedSize)
			if err != nil {
				return fmt.Errorf("encrypt %s: %w", meta.Filename, err)
			}
		case 3:
			encrypted, checksum, err = encryptSection(data, sectionType, meta.EncryptedSize)
			if err != nil {
				return fmt.Errorf("encrypt %s: %w", meta.Filename, err)
			}
		default:
			return fmt.Errorf("unknown section type %d for %s", sectionType, meta.Filename)
		}

		sectionTypes[meta.Type] = sectionType

		out.Write(buildHeader(meta.Unkn1, meta.Unkn2, len(encrypted)))
		out.Write(encrypted)
		out.WriteString(checksum)
	}

	if err := os.WriteFile(output, out.Bytes(), 0644); err != nil {
		return fmt.Errorf("write %s: %w", output, err)
	}

	return nil
}

func applyOverrides(manifestJSON []byte, o *ManifestOverrides) ([]byte, error) {
	var manifest map[string]interface{}
	if err := json.Unmarshal(manifestJSON, &manifest); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}

	if o.FwVer != "" {
		manifest["fw_ver"] = o.FwVer
	}
	if o.HwVer != "" {
		manifest["hw_ver"] = o.HwVer
	}
	if o.Product != "" {
		manifest["product"] = o.Product
	}
	if o.ReleaseDate != "" {
		manifest["release_date"] = o.ReleaseDate
	}

	return json.Marshal(manifest)
}

package detect

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// ── Hashing ───────────────────────────────────────────────────────────────────

func Md5(data []byte) string {
	h := md5.Sum(data)
	return hex.EncodeToString(h[:])
}

func Sha256Hash(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// Mmh3 computes MurmurHash3 32-bit with seed 0 and returns signed int32 string.
// This matches the hash used by Shodan for favicon indexing.
func Mmh3(data []byte) string {
	return fmt.Sprintf("%d", int32(murmur3_32(data, 0)))
}

// murmur3_32 is a pure-Go MurmurHash3 32-bit implementation.
func murmur3_32(data []byte, seed uint32) uint32 {
	const (
		c1 uint32 = 0xcc9e2d51
		c2 uint32 = 0x1b873593
		m  uint32 = 5
		n  uint32 = 0xe6546b64
	)
	hash := seed
	nblocks := len(data) / 4
	for i := 0; i < nblocks; i++ {
		k := binary.LittleEndian.Uint32(data[i*4 : i*4+4])
		k *= c1
		k = (k << 15) | (k >> 17)
		k *= c2
		hash ^= k
		hash = ((hash << 13) | (hash >> 19)) * m + n
	}
	tail := data[nblocks*4:]
	var k1 uint32
	switch len(tail) & 3 {
	case 3:
		k1 ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(tail[0])
		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2
		hash ^= k1
	}
	hash ^= uint32(len(data))
	hash ^= hash >> 16
	hash *= 0x85ebca6b
	hash ^= hash >> 13
	hash *= 0xc2b2ae35
	hash ^= hash >> 16
	return hash
}

// FaviconHash computes the MurmurHash3 of a favicon as Shodan does:
// base64-encode the raw bytes (with newlines every 76 chars), then hash.
func FaviconHash(data []byte) string {
	encoded := faviconBase64(data)
	return Mmh3([]byte(encoded))
}

// faviconBase64 mimics Python's base64.encodebytes() — adds \n every 76 chars.
func faviconBase64(data []byte) string {
	raw := base64.StdEncoding.EncodeToString(data)
	var sb strings.Builder
	for i := 0; i < len(raw); i++ {
		sb.WriteByte(raw[i])
		if (i+1)%76 == 0 {
			sb.WriteByte('\n')
		}
	}
	sb.WriteByte('\n')
	return sb.String()
}

// ComputeHashes computes the requested hash types for body data.
// types can include "md5", "sha256", "mmh3".
func ComputeHashes(body []byte, types []string) map[string]string {
	if len(types) == 0 || len(body) == 0 {
		return nil
	}
	result := make(map[string]string)
	for _, t := range types {
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "md5":
			result["md5"] = Md5(body)
		case "sha256":
			result["sha256"] = Sha256Hash(body)
		case "mmh3":
			result["mmh3"] = Mmh3(body)
		}
	}
	return result
}

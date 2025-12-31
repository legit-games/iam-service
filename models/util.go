package models

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// SnowflakeToUUID4 encodes a 64-bit snowflake ID into a UUIDv4-formatted string without hyphens.
// Reversible mapping: store high 16 bits in bytes 4-5 and low 48 bits in bytes 10-15, preserving version/variant.
func SnowflakeToUUID4(id uint64) string {
	var b [16]byte
	// Map id: hi16 -> b[4:6], lo48 -> b[10:16]
	binary.BigEndian.PutUint16(b[4:6], uint16(id>>48))
	lo := id & 0x0000FFFFFFFFFFFF
	b[10] = byte((lo >> 40) & 0xFF)
	b[11] = byte((lo >> 32) & 0xFF)
	b[12] = byte((lo >> 24) & 0xFF)
	b[13] = byte((lo >> 16) & 0xFF)
	b[14] = byte((lo >> 8) & 0xFF)
	b[15] = byte(lo & 0xFF)

	// Set UUID version to 4 and RFC4122 variant
	b[6] = (b[6] & 0x0F) | 0x40
	b[8] = (b[8] & 0x3F) | 0x80

	// Return 32-hex string (no hyphens)
	return fmt.Sprintf("%08x%04x%04x%04x%012x",
		binary.BigEndian.Uint32(b[0:4]),
		binary.BigEndian.Uint16(b[4:6]),
		binary.BigEndian.Uint16(b[6:8]),
		binary.BigEndian.Uint16(b[8:10]),
		b[10:16],
	)
}

// UUID4ToSnowflake decodes a UUID string produced by SnowflakeToUUID4 back to the original snowflake ID.
// Accepts uppercase/lowercase and with/without hyphens. Returns the 64-bit value or 0 if parsing fails.
func UUID4ToSnowflake(uuid string) (uint64, error) {
	// Remove hyphens and validate length
	s := strings.ReplaceAll(uuid, "-", "")
	if len(s) != 32 {
		return 0, fmt.Errorf("invalid uuid length: %d", len(s))
	}
	// Parse hex into 16 bytes
	var b [16]byte
	for i := 0; i < 16; i++ {
		var v uint64
		_, err := fmt.Sscanf(s[i*2:(i+1)*2], "%02x", &v)
		if err != nil {
			return 0, fmt.Errorf("invalid hex at byte %d", i)
		}
		b[i] = byte(v)
	}
	// Recover hi16 and lo48
	hi := uint64(binary.BigEndian.Uint16(b[4:6]))
	lo := (uint64(b[10]) << 40) | (uint64(b[11]) << 32) | (uint64(b[12]) << 24) | (uint64(b[13]) << 16) | (uint64(b[14]) << 8) | uint64(b[15])
	id := (hi << 48) | lo
	return id, nil
}

// LegitID generates a new identifier by creating a Snowflake ID (node 1)
// and encoding it as a hyphenless UUIDv4-compatible 32-char string.
func LegitID() string {
	sf := NewSnowflake(1)
	return SnowflakeToUUID4(uint64(sf.Next()))
}

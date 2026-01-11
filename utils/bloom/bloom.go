package bloom

import (
	"encoding/binary"
	"encoding/json"
	"math"
)

// Filter represents a Bloom filter data structure.
// It uses MurmurHash3 for hashing values.
type Filter struct {
	m uint   // size of bit array
	k uint   // number of hash functions
	b []uint64 // bit array
}

// FilterJSON is the JSON representation of a Bloom filter
type FilterJSON struct {
	M uint     `json:"m"` // size of bit array
	K uint     `json:"k"` // number of hash functions
	B []uint64 `json:"b"` // bit array
}

// DefaultM is the default size of the bit array (10000 bits)
const DefaultM = 10000

// DefaultK is the default number of hash functions
const DefaultK = 7

// New creates a new Bloom filter with default parameters.
func New() *Filter {
	return NewWithParams(DefaultM, DefaultK)
}

// NewWithParams creates a new Bloom filter with specified m (size) and k (hash functions).
func NewWithParams(m, k uint) *Filter {
	// Calculate the number of uint64 needed to store m bits
	numWords := (m + 63) / 64
	return &Filter{
		m: m,
		k: k,
		b: make([]uint64, numWords),
	}
}

// NewFromData creates a Bloom filter from existing data.
func NewFromData(m, k uint, data []uint64) *Filter {
	return &Filter{
		m: m,
		k: k,
		b: data,
	}
}

// NewFromJSON creates a Bloom filter from JSON representation.
func NewFromJSON(fj FilterJSON) *Filter {
	return &Filter{
		m: fj.M,
		k: fj.K,
		b: fj.B,
	}
}

// OptimalParams calculates optimal m and k for expected items and false positive rate.
func OptimalParams(expectedItems uint, falsePositiveRate float64) (m, k uint) {
	// m = -n * ln(p) / (ln(2)^2)
	m = uint(math.Ceil(-float64(expectedItems) * math.Log(falsePositiveRate) / (math.Ln2 * math.Ln2)))
	// k = (m/n) * ln(2)
	k = uint(math.Ceil(float64(m) / float64(expectedItems) * math.Ln2))
	return
}

// Put adds an item to the Bloom filter.
func (f *Filter) Put(data []byte) {
	h1, h2 := murmurHash3_128(data, 0)
	for i := uint(0); i < f.k; i++ {
		// Use double hashing: h(i) = h1 + i*h2
		pos := (h1 + uint64(i)*h2) % uint64(f.m)
		f.setBit(uint(pos))
	}
}

// Test checks if an item might be in the Bloom filter.
// Returns true if the item might be present (possibly false positive).
// Returns false if the item is definitely not present.
func (f *Filter) Test(data []byte) bool {
	h1, h2 := murmurHash3_128(data, 0)
	for i := uint(0); i < f.k; i++ {
		pos := (h1 + uint64(i)*h2) % uint64(f.m)
		if !f.testBit(uint(pos)) {
			return false
		}
	}
	return true
}

// M returns the size of the bit array.
func (f *Filter) M() uint {
	return f.m
}

// K returns the number of hash functions.
func (f *Filter) K() uint {
	return f.k
}

// B returns the bit array.
func (f *Filter) B() []uint64 {
	return f.b
}

// ToJSON converts the filter to JSON representation.
func (f *Filter) ToJSON() FilterJSON {
	return FilterJSON{
		M: f.m,
		K: f.k,
		B: f.b,
	}
}

// MarshalJSON implements json.Marshaler
func (f *Filter) MarshalJSON() ([]byte, error) {
	return json.Marshal(f.ToJSON())
}

// UnmarshalJSON implements json.Unmarshaler
func (f *Filter) UnmarshalJSON(data []byte) error {
	var fj FilterJSON
	if err := json.Unmarshal(data, &fj); err != nil {
		return err
	}
	f.m = fj.M
	f.k = fj.K
	f.b = fj.B
	return nil
}

// Merge combines two Bloom filters into one.
// Both filters must have the same m and k values.
func Merge(f1, f2 *Filter) (*Filter, error) {
	if f1.m != f2.m || f1.k != f2.k {
		return nil, ErrIncompatibleFilters
	}

	merged := NewWithParams(f1.m, f1.k)
	for i := range f1.b {
		merged.b[i] = f1.b[i] | f2.b[i]
	}
	return merged, nil
}

// setBit sets a bit at the given position.
func (f *Filter) setBit(pos uint) {
	wordIndex := pos / 64
	bitIndex := pos % 64
	f.b[wordIndex] |= (1 << bitIndex)
}

// testBit checks if a bit is set at the given position.
func (f *Filter) testBit(pos uint) bool {
	wordIndex := pos / 64
	bitIndex := pos % 64
	return (f.b[wordIndex] & (1 << bitIndex)) != 0
}

// murmurHash3_128 implements MurmurHash3 128-bit hash function.
// Returns two 64-bit hash values for double hashing.
func murmurHash3_128(data []byte, seed uint64) (uint64, uint64) {
	const c1 uint64 = 0x87c37b91114253d5
	const c2 uint64 = 0x4cf5ad432745937f

	h1 := seed
	h2 := seed

	length := len(data)
	nblocks := length / 16

	// Body
	for i := 0; i < nblocks; i++ {
		k1 := binary.LittleEndian.Uint64(data[i*16:])
		k2 := binary.LittleEndian.Uint64(data[i*16+8:])

		k1 *= c1
		k1 = rotl64(k1, 31)
		k1 *= c2
		h1 ^= k1

		h1 = rotl64(h1, 27)
		h1 += h2
		h1 = h1*5 + 0x52dce729

		k2 *= c2
		k2 = rotl64(k2, 33)
		k2 *= c1
		h2 ^= k2

		h2 = rotl64(h2, 31)
		h2 += h1
		h2 = h2*5 + 0x38495ab5
	}

	// Tail
	tail := data[nblocks*16:]
	var k1, k2 uint64

	switch len(tail) {
	case 15:
		k2 ^= uint64(tail[14]) << 48
		fallthrough
	case 14:
		k2 ^= uint64(tail[13]) << 40
		fallthrough
	case 13:
		k2 ^= uint64(tail[12]) << 32
		fallthrough
	case 12:
		k2 ^= uint64(tail[11]) << 24
		fallthrough
	case 11:
		k2 ^= uint64(tail[10]) << 16
		fallthrough
	case 10:
		k2 ^= uint64(tail[9]) << 8
		fallthrough
	case 9:
		k2 ^= uint64(tail[8])
		k2 *= c2
		k2 = rotl64(k2, 33)
		k2 *= c1
		h2 ^= k2
		fallthrough
	case 8:
		k1 ^= uint64(tail[7]) << 56
		fallthrough
	case 7:
		k1 ^= uint64(tail[6]) << 48
		fallthrough
	case 6:
		k1 ^= uint64(tail[5]) << 40
		fallthrough
	case 5:
		k1 ^= uint64(tail[4]) << 32
		fallthrough
	case 4:
		k1 ^= uint64(tail[3]) << 24
		fallthrough
	case 3:
		k1 ^= uint64(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint64(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint64(tail[0])
		k1 *= c1
		k1 = rotl64(k1, 31)
		k1 *= c2
		h1 ^= k1
	}

	// Finalization
	h1 ^= uint64(length)
	h2 ^= uint64(length)

	h1 += h2
	h2 += h1

	h1 = fmix64(h1)
	h2 = fmix64(h2)

	h1 += h2
	h2 += h1

	return h1, h2
}

func rotl64(x uint64, r uint8) uint64 {
	return (x << r) | (x >> (64 - r))
}

func fmix64(h uint64) uint64 {
	h ^= h >> 33
	h *= 0xff51afd7ed558ccd
	h ^= h >> 33
	h *= 0xc4ceb9fe1a85ec53
	h ^= h >> 33
	return h
}

// Package hashset provides hash-allowlist / hash-denylist lookup for forensic
// and security workflows — e.g. filtering known-good files against an NSRL
// reference set, or flagging known-bad hashes from a threat-intel feed.
//
// Two backing stores share one [Set] interface:
//
//   - in-memory ([NewMemory] + [LoadText]): three maps keyed by raw hash
//     bytes. Fast for lists up to ~1M entries; held entirely in RAM.
//   - bbolt-backed ([OpenBolt], built via [Build]): three buckets keyed by raw
//     hash bytes. Used for NSRL-scale lists (~50M entries) where holding
//     everything in RAM is impractical.
//
// Lookup is O(1) for in-memory and O(log N) for bbolt — either is fast enough
// that allowlist filtering doesn't dominate a walk where the per-file hashing
// is already paid for. Supported algorithms: MD5, SHA-1, SHA-256.
package hashset

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// Set is the read interface every hashset backing store exposes.
//
// Contains reports whether the given hex-encoded hash (lowercase, canonical
// length: 32 for md5, 40 for sha1, 64 for sha256) appears in the set. Hashes
// of unrecognised length always return false. algo is "md5" / "sha1" /
// "sha256"; other values return false.
//
// Counts returns the per-algorithm entry count snapshot, so a caller can
// sanity-check that a set loaded as expected.
//
// Close releases resources (the bbolt-backed impl closes the file; in-memory
// is a no-op). Safe to call more than once; subsequent calls are no-ops.
type Set interface {
	Contains(algo, hexHash string) bool
	Counts() map[string]int
	Close() error
}

// Algorithms is the canonical set of algorithm names supported by every
// backing store. Other values passed to Contains return false.
var Algorithms = []string{"md5", "sha1", "sha256"}

// LineLengthToAlgo maps hex-string lengths back to the algorithm name. Used by
// the text loader to auto-detect each line's algo without explicit markers.
var LineLengthToAlgo = map[int]string{
	32: "md5",
	40: "sha1",
	64: "sha256",
}

// memorySet is the in-memory Set. Three maps keyed by the raw hash bytes
// (16 / 20 / 32 bytes). Holding hashes as raw strings (not hex) halves the
// storage relative to hex-string keys, with the same O(1) lookup.
type memorySet struct {
	md5    map[string]struct{}
	sha1   map[string]struct{}
	sha256 map[string]struct{}
}

// NewMemory returns an empty in-memory Set. Callers populate it via [LoadText]
// (the typical entry point) or by inserting hashes through AddHex.
func NewMemory() Set {
	return &memorySet{
		md5:    make(map[string]struct{}),
		sha1:   make(map[string]struct{}),
		sha256: make(map[string]struct{}),
	}
}

func (m *memorySet) Contains(algo, hexHash string) bool {
	raw, err := hex.DecodeString(hexHash)
	if err != nil {
		return false
	}
	switch algo {
	case "md5":
		_, ok := m.md5[string(raw)]
		return ok
	case "sha1":
		_, ok := m.sha1[string(raw)]
		return ok
	case "sha256":
		_, ok := m.sha256[string(raw)]
		return ok
	}
	return false
}

func (m *memorySet) Counts() map[string]int {
	return map[string]int{
		"md5":    len(m.md5),
		"sha1":   len(m.sha1),
		"sha256": len(m.sha256),
	}
}

func (m *memorySet) Close() error { return nil }

// AddHex inserts one hex-encoded hash into the in-memory set. Auto-detects the
// algorithm from the string length (32/40/64). Returns [ErrUnknownAlgo] for
// unrecognised lengths and [ErrInvalidHex] for non-hex content.
func (m *memorySet) AddHex(hexHash string) error {
	hexHash = strings.ToLower(strings.TrimSpace(hexHash))
	if hexHash == "" {
		return nil
	}
	algo, ok := LineLengthToAlgo[len(hexHash)]
	if !ok {
		return fmt.Errorf("%w: length %d", ErrUnknownAlgo, len(hexHash))
	}
	raw, err := hex.DecodeString(hexHash)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidHex, err)
	}
	switch algo {
	case "md5":
		m.md5[string(raw)] = struct{}{}
	case "sha1":
		m.sha1[string(raw)] = struct{}{}
	case "sha256":
		m.sha256[string(raw)] = struct{}{}
	}
	return nil
}

// ErrUnknownAlgo is returned when a hex string's length doesn't match any
// supported algorithm (md5=32, sha1=40, sha256=64).
var ErrUnknownAlgo = errors.New("unknown hash algorithm")

// ErrInvalidHex is returned when a hex string contains non-hex characters.
var ErrInvalidHex = errors.New("invalid hex hash")

// LoadText reads a newline-separated hash list from r and inserts every hash
// into an in-memory [Set].
//
// File format:
//   - One hex-encoded hash per line, mixed algorithms allowed (each line's
//     algorithm is auto-detected by its length).
//   - Blank lines are ignored.
//   - Lines beginning with `#` are comments and ignored.
//   - Inline whitespace is trimmed.
//   - Lines that aren't blank, comments, or valid hex of a known length are
//     rejected with an error naming the line number.
func LoadText(r io.Reader) (Set, error) {
	set := &memorySet{
		md5:    make(map[string]struct{}),
		sha1:   make(map[string]struct{}),
		sha256: make(map[string]struct{}),
	}
	scanner := bufio.NewScanner(r)
	// 1 MiB max line — generous for any hash format we care about.
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if err := set.AddHex(line); err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNum, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return set, nil
}

// LoadTextFile opens path and calls [LoadText] against its contents.
func LoadTextFile(path string) (Set, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return LoadText(f)
}

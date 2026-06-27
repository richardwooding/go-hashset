# go-hashset

[![Go Reference](https://pkg.go.dev/badge/github.com/richardwooding/go-hashset.svg)](https://pkg.go.dev/github.com/richardwooding/go-hashset)

Hash **allowlist / denylist** lookup for forensic and security workflows — filter
known-good files against an [NSRL](https://www.nist.gov/itl/ssd/software-quality-group/national-software-reference-library-nsrl)
reference set, or flag known-bad hashes from a threat-intel feed. MD5, SHA-1,
SHA-256.

Two backing stores behind one `Set` interface:

| Store | Build with | For |
|---|---|---|
| **in-memory** | `LoadText` / `LoadTextFile` | lists up to ~1M entries; O(1) lookup |
| **bbolt-backed** | `Build` → `OpenBolt` | NSRL-scale (~50M entries); O(log N), stays on disk |

Only dependency: [`go.etcd.io/bbolt`](https://github.com/etcd-io/bbolt).

## Install

```sh
go get github.com/richardwooding/go-hashset
```

## Usage

**Query an in-memory list:**

```go
import hashset "github.com/richardwooding/go-hashset"

set, err := hashset.LoadTextFile("known-bad.txt") // one hex hash per line, # comments, mixed algos
if err != nil { /* ... */ }
defer set.Close()

if set.Contains("sha256", "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824") {
    // flag it
}
fmt.Println(set.Counts()) // map[md5:.. sha1:.. sha256:..]
```

**Build a bbolt set from a big NSRL drop, then query it:**

```go
in, _ := os.Open("NSRLFile.txt")
defer in.Close()
err := hashset.Build(in, "nsrl.hashset", hashset.BuildOpts{
    Format:   "auto", // "text" | "nsrl" | "auto" (sniffs the header)
    Progress: func(n int64) { log.Printf("%d hashes", n) },
})

set, _ := hashset.OpenBolt("nsrl.hashset") // read-only
defer set.Close()
known := set.Contains("sha1", sha1hex)
```

`Open(path)` auto-detects: a bbolt file loads via `OpenBolt`, anything else
falls back to `LoadTextFile`.

## Formats

- **Text** — one hex-encoded hash per line; algorithm auto-detected by length
  (32 = md5, 40 = sha1, 64 = sha256); blank lines and `#` comments ignored;
  mixed algorithms allowed.
- **NSRL** — the `NSRLFile.txt` quoted-CSV with a `"SHA-1","MD5",…` header;
  the SHA-1 and MD5 columns are extracted (header-driven, tolerant of
  reordering / extra columns).

The bbolt file is a four-bucket database (`md5`/`sha1`/`sha256` + `meta` with a
`schema_version`); raw hash bytes are the keys.

Extracted from [file-search-on](https://github.com/richardwooding/file-search-on),
where it backs the `is_known_good` / `is_known_bad` search predicates.

## License

MIT — see [LICENSE](LICENSE).

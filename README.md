# gsb-cidrset

Python 3 stdlib only. `python3 -m unittest discover -s . -v`

## Usage

```python
from cidrset import CIDRSet, AddressFamilyError, CIDRSetError

# Overlapping and adjacent prefixes are merged on insert.
nets = CIDRSet(["10.0.0.0/24", "10.0.1.0/24", "10.0.0.128/25"])
nets.networks()          # [IPv4Network("10.0.0.0/23")]

# Ask whether an IP or a smaller/equal prefix is fully covered.
"10.0.0.5" in nets       # True
nets.contains("10.0.0.0/24")  # True
nets.overlaps("10.0.2.0/24")  # False

# Carve a hole out of the middle; both flanks survive.
nets.subtract("10.0.0.64/26")

# Exact-prefix removal and set algebra are supported too.
nets.remove("10.0.0.0/25")
other = CIDRSet(["10.0.1.0/24"])
nets.union(other)
nets.difference(other)
nets.intersection(other)
```

Rules that are enforced rather than papered over:

- IPv4 and IPv6 cannot share a set; mixing raises `AddressFamilyError`.
- Host bits in a prefix (`10.0.0.1/24`) and bad prefix lengths raise
  `CIDRSetError` instead of being masked silently.
- `0.0.0.0/0` / `::/0` work, and feeding in all /8s (or all /127s)
  collapses to the default route.

No third-party dependencies, no CLI: import `cidrset` as a library.

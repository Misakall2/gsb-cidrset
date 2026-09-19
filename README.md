# gsb-cidrset

Python 3 stdlib only. `python3 -m unittest discover -s . -v`

## Usage

```python
from cidrset import CIDRSet

s = CIDRSet(["10.0.0.0/24", "10.0.1.0/24", "10.0.1.0/25"])
s.networks()          # [IPv4Network('10.0.0.0/23')] — overlaps/adjacent merged

"10.0.0.7" in s       # True
"10.0.0.0/25" in s    # True (fully contained)

s.discard("10.0.0.128/25")   # punch a hole; both sides remain
s.networks()          # [10.0.0.0/25, 10.0.1.0/24]
```

- One address family per set: mixing IPv4 and IPv6 raises
  `MixedAddressFamilyError`. Pin an empty set with `CIDRSet(version=6)`.
- Strict parsing: host bits set (`10.0.0.1/24`) or bad prefix lengths
  raise `ValueError`.
- Accepts strings or `ipaddress` network/address objects.

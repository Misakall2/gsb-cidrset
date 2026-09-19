"""A small, dependency-free library for normalizing and querying CIDR sets.

A :class:`CIDRSet` holds a set of IP networks of a single address family
(IPv4 or IPv6). Networks are stored as sorted, disjoint, non-adjacent
integer ranges, so overlapping and adjacent prefixes are merged
automatically on insertion.

Only the Python standard library is used.
"""

from __future__ import annotations

import bisect
import ipaddress
from typing import Iterable, Iterator, List, Optional, Union

NetworkLike = Union[str, "ipaddress.IPv4Network", "ipaddress.IPv6Network"]
AddressLike = Union[str, "ipaddress.IPv4Address", "ipaddress.IPv6Address"]

_IPNetwork = (ipaddress.IPv4Network, ipaddress.IPv6Network)
_IPAddress = (ipaddress.IPv4Address, ipaddress.IPv6Address)


class MixedAddressFamilyError(ValueError):
    """Raised when IPv4 and IPv6 objects are combined in one CIDRSet."""


def _parse_network(value: NetworkLike):
    """Parse *value* into an ipaddress network, strictly.

    ``strict=True`` rejects networks whose host bits are set
    (e.g. ``10.0.0.1/24``) and invalid prefix lengths raise as usual.
    """
    if isinstance(value, _IPNetwork):
        return value
    if isinstance(value, str):
        try:
            return ipaddress.ip_network(value, strict=True)
        except ValueError as exc:
            raise ValueError(f"invalid network {value!r}: {exc}") from exc
    raise TypeError(
        f"expected str or IPv4Network/IPv6Network, got {type(value).__name__}"
    )


def _parse_address(value: AddressLike):
    if isinstance(value, _IPAddress):
        return value
    if isinstance(value, str):
        try:
            return ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError(f"invalid IP address {value!r}: {exc}") from exc
    raise TypeError(
        f"expected str or IPv4Address/IPv6Address, got {type(value).__name__}"
    )


class CIDRSet:
    """A normalized set of CIDR prefixes of one address family.

    Parameters
    ----------
    networks:
        Optional iterable of networks (strings or ``ipaddress`` network
        objects) to seed the set with.
    version:
        ``4``, ``6`` or ``None``. When ``None`` the version is fixed by the
        first network added; passing an explicit version pins the set to
        that family even while it is empty.
    """

    def __init__(self, networks=None, *, version=None):
        if version not in (None, 4, 6):
            raise ValueError("version must be 4, 6 or None")
        self._version = version
        # Sorted list of disjoint, non-adjacent [start, end] inclusive ranges.
        self._ranges = []
        self._starts = []  # cached range starts for bisect
        if networks is not None:
            for net in networks:
                self.add(net)

    # ------------------------------------------------------------------
    # family handling
    # ------------------------------------------------------------------
    @property
    def version(self):
        """The IP version of the set (4 or 6), or None if not yet fixed."""
        return self._version

    def _check_version(self, obj_version):
        if self._version is None:
            self._version = obj_version
        elif self._version != obj_version:
            raise MixedAddressFamilyError(
                f"cannot mix IPv{obj_version} with an IPv{self._version} CIDRSet"
            )

    # ------------------------------------------------------------------
    # mutation
    # ------------------------------------------------------------------
    def add(self, network):
        """Add *network*, merging overlaps and adjacencies."""
        net = _parse_network(network)
        self._check_version(net.version)
        start = int(net.network_address)
        end = int(net.broadcast_address)
        self._add_range(start, end)

    def _add_range(self, start, end):
        # Merge with every existing range overlapping or touching [start, end].
        i = bisect.bisect_left(self._starts, start)
        if i > 0 and self._ranges[i - 1][1] >= start - 1:
            i -= 1
        while i < len(self._ranges) and self._ranges[i][0] <= end + 1:
            start = min(start, self._ranges[i][0])
            end = max(end, self._ranges[i][1])
            del self._ranges[i]
            del self._starts[i]
        self._ranges.insert(i, [start, end])
        self._starts.insert(i, start)

    def discard(self, network):
        """Remove *network* from the set.

        Ranges are split as needed, so punching a hole in the middle of a
        range leaves both sides intact. Removing something not present is
        a no-op.
        """
        net = _parse_network(network)
        if self._version is not None and net.version != self._version:
            raise MixedAddressFamilyError(
                f"cannot remove an IPv{net.version} network from an "
                f"IPv{self._version} CIDRSet"
            )
        start = int(net.network_address)
        end = int(net.broadcast_address)

        i = bisect.bisect_right(self._starts, end) - 1
        while i >= 0 and self._ranges[i][1] >= start:
            r_start, r_end = self._ranges[i]
            new_ranges = []
            if r_start < start:
                new_ranges.append([r_start, start - 1])
            if r_end > end:
                new_ranges.append([end + 1, r_end])
            self._ranges[i : i + 1] = new_ranges
            self._starts[i : i + 1] = [r[0] for r in new_ranges]
            i -= 1

    # ------------------------------------------------------------------
    # queries
    # ------------------------------------------------------------------
    def __contains__(self, item):
        """True if the IP address or network is fully contained in the set."""
        if isinstance(item, _IPNetwork) or (isinstance(item, str) and "/" in item):
            net = _parse_network(item)
            if self._version is None or net.version != self._version:
                return False
            start = int(net.network_address)
            end = int(net.broadcast_address)
        else:
            addr = _parse_address(item)
            if self._version is None or addr.version != self._version:
                return False
            start = end = int(addr)
        i = bisect.bisect_right(self._starts, start) - 1
        return i >= 0 and self._ranges[i][1] >= end

    def __len__(self):
        """Number of disjoint ranges currently stored."""
        return len(self._ranges)

    def __bool__(self):
        return bool(self._ranges)

    def __iter__(self):
        return iter(self.networks())

    def networks(self):
        """Return the minimal list of CIDR networks covering the set."""
        addr_cls = (
            ipaddress.IPv4Address if self._version == 4 else ipaddress.IPv6Address
        )
        result = []
        for start, end in self._ranges:
            result.extend(
                ipaddress.summarize_address_range(addr_cls(start), addr_cls(end))
            )
        return result

    def __repr__(self):
        nets = ", ".join(str(n) for n in self.networks())
        return f"CIDRSet([{nets}])"

    def __eq__(self, other):
        if not isinstance(other, CIDRSet):
            return NotImplemented
        return self._version == other._version and self._ranges == other._ranges

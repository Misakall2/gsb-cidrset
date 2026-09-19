"""cidrset: a normalized, merge-on-insert set of IP network prefixes.

IPv4 and IPv6 prefixes are kept in strictly separate sets. The
implementation only relies on the Python standard library
(:mod:`ipaddress`).

Typical usage::

    from cidrset import CIDRSet

    nets = CIDRSet(["10.0.0.0/24", "10.0.1.0/24"])
    assert nets.contains("10.0.0.5")
    assert list(nets.networks()) == [IPv4Network("10.0.0.0/23")]
"""

from __future__ import annotations

import ipaddress
from typing import Iterable, Iterator, List, Optional, Union

__all__ = ["CIDRSet", "CIDRSetError", "AddressFamilyError"]

# Accepted inputs mirror what ``ipaddress`` can turn into a network/address.
AddressInput = Union[
    str,
    int,
    bytes,
    ipaddress.IPv4Address,
    ipaddress.IPv6Address,
    ipaddress.IPv4Network,
    ipaddress.IPv6Network,
]
NetworkInput = Union[
    str,
    int,
    bytes,
    ipaddress.IPv4Network,
    ipaddress.IPv6Network,
]

_Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
_Address = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


class CIDRSetError(ValueError):
    """Raised when a prefix or address cannot be interpreted."""


class AddressFamilyError(TypeError):
    """Raised when IPv4 and IPv6 are mixed in one set or comparison."""


def _as_network(value: NetworkInput) -> _Network:
    """Return ``value`` as a strictly validated, host-bit-cleared network.

    ``strict=True`` means ``10.0.0.1/24`` is rejected instead of being
    silently masked down to ``10.0.0.0/24``.
    """
    if isinstance(value, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        net = value
    else:
        try:
            net = ipaddress.ip_network(value, strict=True)
        except AddressFamilyError:
            raise
        except (ValueError, TypeError) as exc:
            raise CIDRSetError(str(exc)) from exc
    if not (0 <= net.prefixlen <= net.max_prefixlen):
        # ip_network already guarantees this; keep the contract explicit for
        # network objects constructed elsewhere and passed in directly.
        raise CIDRSetError("invalid prefix length: %d" % net.prefixlen)
    if net.prefixlen < net.max_prefixlen:
        host_mask = (1 << (net.max_prefixlen - net.prefixlen)) - 1
        if int(net.network_address) & host_mask:
            raise CIDRSetError("%s has host bits set" % net)
    return net


def _as_address(value: AddressInput) -> _Address:
    if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return value
    try:
        return ipaddress.ip_address(value)
    except (ValueError, TypeError) as exc:
        raise CIDRSetError(str(exc)) from exc


def _adjacent_buddy(net: _Network) -> Optional[_Network]:
    """Return the same-sized sibling prefix under ``net``'s supernet.

    Two equal-length prefixes can merge into a /(n-1) only when they are
    the two halves of that parent block.
    """
    if net.prefixlen == 0:
        return None
    left, right = net.supernet(prefixlen_diff=1).subnets()
    return right if net == left else left


def _enclosing(a: _Network, b: _Network) -> _Network:
    """Smallest prefix containing both overlapping networks."""
    if a.version != b.version:
        raise AddressFamilyError("cannot enclose IPv4 and IPv6 in one prefix")
    length = a.max_prefixlen
    start = min(int(a.network_address), int(b.network_address))
    end = max(int(a.broadcast_address), int(b.broadcast_address))
    prefixlen = length - (start ^ end).bit_length()
    while prefixlen >= 0:
        host_mask = ((1 << (length - prefixlen)) - 1)
        net_addr = start & ~host_mask
        net = ipaddress.ip_network(
            (a.version, net_addr, prefixlen), strict=False)
        if int(net.broadcast_address) >= end:
            return net
        prefixlen -= 1
    raise AssertionError("unreachable: 0/0 must contain both networks")


def _merge(networks: Iterable[_Network]) -> List[_Network]:
    """Merge overlapping or immediately adjacent, aligned prefixes."""
    items = sorted(
        networks, key=lambda n: (int(n.network_address), -n.prefixlen))
    merged: List[_Network] = []
    for net in items:
        if merged and net.subnet_of(merged[-1]):
            continue
        if merged and net.overlaps(merged[-1]):
            # Neither block contains the other; replace the pair with the
            # smallest enclosing prefix and fold into earlier blocks.
            merged[-1] = _enclosing(merged[-1], net)
            while len(merged) >= 2 and merged[-1].overlaps(merged[-2]):
                right = merged.pop()
                merged[-1] = _enclosing(merged[-1], right)
            continue
        if merged and _adjacent_buddy(merged[-1]) == net:
            parent = merged.pop().supernet(prefixlen_diff=1)
            while merged and _adjacent_buddy(merged[-1]) == parent:
                parent = merged.pop().supernet(prefixlen_diff=1)
            merged.append(parent)
            continue
        merged.append(net)
    return merged


class CIDRSet:
    """A mutable set of non-overlapping, maximally merged CIDR prefixes."""

    def __init__(self, prefixes: Iterable[NetworkInput] = ()) -> None:
        self._version: Optional[int] = None
        self._nets: List[_Network] = []
        for prefix in prefixes:
            self.add(prefix)

    # -- container basics -------------------------------------------------

    @property
    def version(self) -> Optional[int]:
        """4 or 6 once the set is non-empty, otherwise ``None``."""
        return self._version

    def __len__(self) -> int:
        return len(self._nets)

    def __iter__(self) -> Iterator[_Network]:
        return iter(self._nets)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CIDRSet):
            return NotImplemented
        return self._nets == other._nets

    def __repr__(self) -> str:
        return "CIDRSet([%s])" % ", ".join(str(n) for n in self._nets)

    def copy(self) -> "CIDRSet":
        clone = CIDRSet()
        clone._version = self._version
        clone._nets = list(self._nets)
        return clone

    def networks(self) -> List[_Network]:
        """Return a snapshot list of the canonical prefixes."""
        return list(self._nets)

    def is_empty(self) -> bool:
        return not self._nets

    # -- mutation ---------------------------------------------------------

    def add(self, prefix: NetworkInput) -> None:
        """Add one prefix, merging overlaps and adjacencies."""
        net = _as_network(prefix)
        if self._version is None:
            self._version = net.version
        elif self._version != net.version:
            raise AddressFamilyError(
                "this CIDRSet holds IPv%d; cannot add IPv%d prefix %s"
                % (self._version, net.version, net))
        if any(net.subnet_of(existing) for existing in self._nets):
            return
        self._nets = _merge(self._nets + [net])

    def remove(self, prefix: NetworkInput) -> None:
        """Remove an exact prefix; raise ``KeyError`` if it is not present."""
        net = _as_network(prefix)
        self._check_family(net.version, net)
        if net not in self._nets:
            raise KeyError(str(net))
        self._nets.remove(net)
        if not self._nets:
            self._version = None

    def discard(self, prefix: NetworkInput) -> None:
        """Remove a prefix exactly, ignoring it if absent."""
        try:
            self.remove(prefix)
        except KeyError:
            pass

    def clear(self) -> None:
        self._nets = []
        self._version = None

    def subtract(self, prefix: NetworkInput) -> None:
        """Punch ``prefix`` out of the set, splitting any containing block."""
        hole = _as_network(prefix)
        self._check_family(hole.version, hole)
        result: List[_Network] = []
        for net in self._nets:
            if net.subnet_of(hole):
                continue
            if hole.subnet_of(net):
                result.extend(net.address_exclude(hole))
            elif net.overlaps(hole):
                # Partial overlap where neither contains the other. Keep the
                # portion of ``net`` outside ``hole`` by carving hole-aligned
                # host addresses out one by one, then re-merging below.
                remaining = [net]
                host_len = net.max_prefixlen
                first = max(int(hole.network_address), int(net.network_address))
                last = min(int(hole.broadcast_address),
                           int(net.broadcast_address))
                for host_int in range(first, last + 1):
                    host_net = ipaddress.ip_network(
                        (net.version, host_int, host_len), strict=False)
                    remaining = [
                        piece
                        for piece in remaining
                        for piece in (
                            piece.address_exclude(host_net)
                            if host_net.subnet_of(piece) else [piece])
                    ]
                result.extend(remaining)
            else:
                result.append(net)
        self._nets = _merge(result)
        if not self._nets:
            self._version = None

    # -- queries ----------------------------------------------------------

    def contains(self, item: AddressInput) -> bool:
        """True if an IP, or an entire (smaller/equal) prefix, is covered."""
        is_network = isinstance(
            item, (ipaddress.IPv4Network, ipaddress.IPv6Network))
        if not is_network and isinstance(item, str) and "/" in item:
            is_network = True
        if is_network:
            net = _as_network(item)
            self._check_family(net.version, net, allow_empty=False)
            return any(net.subnet_of(existing) for existing in self._nets)
        addr = _as_address(item)
        self._check_family(addr.version, addr, allow_empty=False)
        return any(addr in net for net in self._nets)

    def overlaps(self, prefix: NetworkInput) -> bool:
        """True if ``prefix`` shares any address with the set."""
        net = _as_network(prefix)
        if self._version is None:
            return False
        self._check_family(net.version, net, allow_empty=False)
        return any(net.overlaps(existing) for existing in self._nets)

    def __contains__(self, item: AddressInput) -> bool:
        return self.contains(item)

    # -- set algebra ------------------------------------------------------

    def union(self, other: "CIDRSet") -> "CIDRSet":
        self._check_same_family(other)
        result = self.copy()
        for net in other._nets:
            result.add(net)
        return result

    def difference(self, other: "CIDRSet") -> "CIDRSet":
        self._check_same_family(other, allow_empty_other=True)
        result = self.copy()
        for net in other._nets:
            result.subtract(net)
        return result

    def intersection(self, other: "CIDRSet") -> "CIDRSet":
        self._check_same_family(other, allow_empty_other=True)
        result = CIDRSet()
        for a in self._nets:
            for b in other._nets:
                if a == b:
                    result.add(a)
                elif b.subnet_of(a):
                    result.add(b)
                elif a.subnet_of(b):
                    result.add(a)
        return result

    # -- helpers ----------------------------------------------------------

    def _check_family(self, version: int, value: object,
                      allow_empty: bool = True) -> None:
        if self._version is None:
            if allow_empty:
                return
            raise AddressFamilyError(
                "cannot query an empty CIDRSet with %r" % (value,))
        if self._version != version:
            raise AddressFamilyError(
                "this CIDRSet holds IPv%d; %r is IPv%d"
                % (self._version, value, version))

    def _check_same_family(self, other: "CIDRSet",
                           allow_empty_other: bool = False) -> None:
        if not isinstance(other, CIDRSet):
            raise TypeError("expected CIDRSet, got %r" % type(other).__name__)
        if self._version is None or other._version is None:
            if allow_empty_other or self._version is None:
                return
        if (self._version is not None
                and other._version is not None
                and self._version != other._version):
            raise AddressFamilyError(
                "cannot combine IPv%d and IPv%d sets"
                % (self._version, other._version))

"""Unit tests for :mod:`cidrset`.

Run with::

    python3 -m unittest discover -s . -v
"""

import ipaddress
import unittest

from cidrset import (
    AddressFamilyError,
    CIDRSet,
    CIDRSetError,
)


def v4(text):
    return ipaddress.IPv4Network(text)


def v6(text):
    return ipaddress.IPv6Network(text)


class MergeTests(unittest.TestCase):
    def test_overlapping_prefixes_merge(self):
        nets = CIDRSet([
            "10.0.0.0/24",
            "10.0.0.128/25",      # fully contained
            "10.0.1.0/24",
            "10.0.0.0/23",        # contains all of the above
        ])
        self.assertEqual(nets.networks(), [v4("10.0.0.0/23")])

    def test_partial_overlap_collapses_to_enclosing(self):
        # 10.0.1.0/24 and 10.0.0.128/25 overlap and together span /23.
        nets = CIDRSet(["10.0.1.0/24", "10.0.0.128/25"])
        self.assertEqual(nets.networks(), [v4("10.0.0.128/25"),
                                           v4("10.0.1.0/24")])
        nets.add("10.0.0.0/25")
        self.assertEqual(nets.networks(), [v4("10.0.0.0/23")])

    def test_adjacent_24s_merge_to_23(self):
        nets = CIDRSet(["192.168.0.0/24", "192.168.1.0/24"])
        self.assertEqual(nets.networks(), [v4("192.168.0.0/23")])

    def test_adjacent_but_not_siblings_do_not_merge(self):
        # .0 and .2 are adjacent numerically but are not the two halves of a
        # single /23, so they must remain separate.
        nets = CIDRSet(["10.0.0.0/24", "10.0.2.0/24"])
        self.assertEqual(nets.networks(),
                         [v4("10.0.0.0/24"), v4("10.0.2.0/24")])

    def test_chain_folds_repeatedly(self):
        nets = CIDRSet([
            "172.16.0.0/24",
            "172.16.1.0/24",
            "172.16.2.0/24",
            "172.16.3.0/24",
        ])
        self.assertEqual(nets.networks(), [v4("172.16.0.0/22")])

    def test_insert_order_independent(self):
        order_a = ["10.0.3.0/24", "10.0.0.0/24", "10.0.2.0/24",
                   "10.0.1.0/24"]
        order_b = list(reversed(order_a))
        self.assertEqual(CIDRSet(order_a).networks(),
                         CIDRSet(order_b).networks())

    def test_ipv6_merges(self):
        nets = CIDRSet(["2001:db8::/33", "2001:db8:8000::/33"])
        self.assertEqual(nets.networks(), [v6("2001:db8::/32")])

    def test_adjacent_127s_merge_to_126(self):
        nets = CIDRSet(["2001:db8::/127", "2001:db8::2/127"])
        self.assertEqual(nets.networks(), [v6("2001:db8::/126")])


class SubtractTests(unittest.TestCase):
    def test_hole_leaves_left_and_right(self):
        nets = CIDRSet(["192.168.0.0/24"])
        nets.subtract("192.168.0.64/26")
        self.assertEqual(nets.networks(),
                         [v4("192.168.0.0/26"), v4("192.168.0.128/25")])
        self.assertIn("192.168.0.1", nets)
        self.assertNotIn("192.168.0.64", nets)
        self.assertIn("192.168.0.200", nets)

    def test_carve_middle_of_large_block(self):
        nets = CIDRSet(["10.0.0.0/16"])
        nets.subtract("10.0.1.0/24")
        # address_exclude gives a minimal CIDR partition of the remainder.
        self.assertFalse(nets.overlaps("10.0.1.0/24"))
        self.assertTrue(nets.contains("10.0.0.0/24"))
        self.assertTrue(nets.contains("10.0.2.0/23"))
        self.assertTrue(nets.contains("10.0.128.0/17"))
        self.assertEqual(
            sum(n.num_addresses for n in nets.networks()),
            v4("10.0.0.0/16").num_addresses - 256)

    def test_subtract_entire_block_empties_set(self):
        nets = CIDRSet(["10.0.0.0/24"])
        nets.subtract("10.0.0.0/24")
        self.assertTrue(nets.is_empty())
        self.assertIsNone(nets.version)

    def test_subtract_partial_overlap(self):
        nets = CIDRSet(["10.0.0.0/25"])
        # Hole starts outside and covers the first 64 addresses of the block.
        nets.subtract("10.0.0.0/26")
        self.assertEqual(nets.networks(), [v4("10.0.0.64/26")])


class ContainmentTests(unittest.TestCase):
    def test_address_and_prefix_containment(self):
        nets = CIDRSet(["10.0.0.0/23"])
        self.assertIn("10.0.0.1", nets)
        self.assertIn("10.0.1.255", nets)
        self.assertNotIn("10.0.2.0", nets)
        self.assertTrue(nets.contains("10.0.0.0/24"))
        self.assertTrue(nets.contains(v4("10.0.1.128/25")))
        self.assertFalse(nets.contains("10.0.0.0/22"))
        self.assertTrue(nets.overlaps("10.0.0.0/31"))
        self.assertFalse(nets.overlaps("10.1.0.0/16"))

    def test_accepts_integer_and_object_addresses(self):
        nets = CIDRSet(["10.0.0.0/24"])
        self.assertTrue(nets.contains(ipaddress.IPv4Address("10.0.0.9")))
        self.assertTrue(nets.contains(int(ipaddress.IPv4Address("10.0.0.9"))))


class FamilyTests(unittest.TestCase):
    def test_v4_and_v6_cannot_mix(self):
        nets = CIDRSet(["10.0.0.0/8"])
        with self.assertRaises(AddressFamilyError):
            nets.add("2001:db8::/32")
        with self.assertRaises(AddressFamilyError):
            nets.contains("2001:db8::1")
        with self.assertRaises(AddressFamilyError):
            nets.subtract("2001:db8::/48")

    def test_set_algebra_family_guard(self):
        v4set = CIDRSet(["10.0.0.0/24"])
        v6set = CIDRSet(["2001:db8::/32"])
        with self.assertRaises(AddressFamilyError):
            v4set.union(v6set)
        with self.assertRaises(AddressFamilyError):
            v4set.difference(v6set)

    def test_separate_v6_set_works(self):
        nets = CIDRSet(["2001:db8::/32"])
        self.assertEqual(nets.version, 6)
        self.assertIn("2001:db8::1", nets)
        self.assertNotIn("2001:db9::1", nets)


class EmptyAndDefaultsTests(unittest.TestCase):
    def test_empty_set(self):
        nets = CIDRSet()
        self.assertTrue(nets.is_empty())
        self.assertEqual(nets.networks(), [])
        self.assertEqual(len(nets), 0)
        self.assertFalse(nets.overlaps("0.0.0.0/0"))
        with self.assertRaises(AddressFamilyError):
            nets.contains("1.2.3.4")

    def test_default_route_v4(self):
        nets = CIDRSet(["0.0.0.0/0"])
        self.assertEqual(nets.networks(), [v4("0.0.0.0/0")])
        self.assertIn("8.8.8.8", nets)
        self.assertTrue(nets.contains("0.0.0.0/0"))

    def test_default_route_v6(self):
        nets = CIDRSet(["::/0"])
        self.assertEqual(nets.networks(), [v6("::/0")])
        self.assertIn("2001:db8::1", nets)

    def test_all_quads_fill_default_route(self):
        nets = CIDRSet()
        for i in range(256):
            nets.add("%d.0.0.0/8" % i)
        self.assertEqual(nets.networks(), [v4("0.0.0.0/0")])


class ValidationTests(unittest.TestCase):
    def test_host_bits_are_rejected(self):
        with self.assertRaises(CIDRSetError):
            CIDRSet(["10.0.0.1/24"])
        nets = CIDRSet()
        with self.assertRaises(CIDRSetError):
            nets.add("10.0.0.0/33")

    def test_garbage_inputs(self):
        with self.assertRaises(CIDRSetError):
            CIDRSet(["not a cidr"])
        with self.assertRaises(CIDRSetError):
            CIDRSet(["10.0.0.0/999.0.0.1"])

    def test_exact_remove_and_discard(self):
        nets = CIDRSet(["10.0.0.0/24", "10.0.1.0/24"])
        with self.assertRaises(KeyError):
            nets.remove("10.0.0.0/25")
        nets.remove("10.0.0.0/23")
        self.assertTrue(nets.is_empty())
        nets.discard("9.9.9.0/24")  # must not raise

    def test_union_difference_intersection(self):
        a = CIDRSet(["10.0.0.0/23"])
        b = CIDRSet(["10.0.1.0/24"])
        self.assertEqual(a.union(b).networks(), [v4("10.0.0.0/23")])
        self.assertEqual(a.difference(b).networks(), [v4("10.0.0.0/24")])
        self.assertEqual(a.intersection(b).networks(), [v4("10.0.1.0/24")])


if __name__ == "__main__":
    unittest.main()

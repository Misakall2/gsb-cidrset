import ipaddress
import unittest

from cidrset import CIDRSet, MixedAddressFamilyError


def nets(*cidrs):
    return [ipaddress.ip_network(c) for c in cidrs]


class TestMerging(unittest.TestCase):
    def test_overlapping_networks_merge(self):
        s = CIDRSet(["10.0.0.0/8", "10.1.0.0/16", "10.2.0.0/16"])
        self.assertEqual(s.networks(), nets("10.0.0.0/8"))

    def test_adjacent_slash24_merge_into_slash23(self):
        s = CIDRSet(["192.168.0.0/24", "192.168.1.0/24"])
        self.assertEqual(s.networks(), nets("192.168.0.0/23"))

    def test_adjacent_added_in_reverse_order(self):
        s = CIDRSet(["192.168.1.0/24", "192.168.0.0/24"])
        self.assertEqual(s.networks(), nets("192.168.0.0/23"))

    def test_non_adjacent_networks_stay_separate(self):
        s = CIDRSet(["192.168.0.0/24", "192.168.2.0/24"])
        self.assertEqual(s.networks(), nets("192.168.0.0/24", "192.168.2.0/24"))

    def test_duplicate_add_is_idempotent(self):
        s = CIDRSet(["10.0.0.0/24"])
        s.add("10.0.0.0/24")
        self.assertEqual(s.networks(), nets("10.0.0.0/24"))

    def test_gap_filled_by_later_add(self):
        s = CIDRSet(["10.0.0.0/24", "10.0.2.0/24"])
        s.add("10.0.1.0/24")
        self.assertEqual(s.networks(), nets("10.0.0.0/23", "10.0.2.0/24"))


class TestContains(unittest.TestCase):
    def setUp(self):
        self.s = CIDRSet(["10.0.0.0/8", "192.168.0.0/16"])

    def test_address_membership(self):
        self.assertIn("10.1.2.3", self.s)
        self.assertIn("192.168.255.255", self.s)
        self.assertNotIn("172.16.0.1", self.s)
        self.assertNotIn("192.169.0.1", self.s)

    def test_subnet_membership(self):
        self.assertIn("10.0.0.0/9", self.s)
        self.assertIn("192.168.1.0/24", self.s)
        self.assertNotIn("192.168.0.0/15", self.s)
        self.assertNotIn("8.0.0.0/8", self.s)

    def test_accepts_ipaddress_objects(self):
        self.assertIn(ipaddress.ip_address("10.0.0.1"), self.s)
        self.assertIn(ipaddress.ip_network("10.0.0.0/24"), self.s)

    def test_wrong_family_is_not_contained(self):
        self.assertNotIn("::1", self.s)
        self.assertNotIn("2001:db8::/32", self.s)


class TestSubtract(unittest.TestCase):
    def test_hole_punch_keeps_both_sides(self):
        s = CIDRSet(["10.0.0.0/24"])
        s.discard("10.0.0.64/26")
        self.assertEqual(s.networks(), nets("10.0.0.0/26", "10.0.0.128/25"))
        self.assertIn("10.0.0.1", s)
        self.assertIn("10.0.0.200", s)
        self.assertNotIn("10.0.0.64", s)
        self.assertNotIn("10.0.0.127", s)

    def test_discard_tail(self):
        s = CIDRSet(["10.0.0.0/24"])
        s.discard("10.0.0.128/25")
        self.assertEqual(s.networks(), nets("10.0.0.0/25"))

    def test_discard_exact_and_superset(self):
        s = CIDRSet(["10.0.0.0/24"])
        s.discard("10.0.0.0/24")
        self.assertEqual(len(s), 0)
        s = CIDRSet(["10.0.0.0/24"])
        s.discard("10.0.0.0/16")
        self.assertEqual(len(s), 0)

    def test_discard_absent_is_noop(self):
        s = CIDRSet(["10.0.0.0/24"])
        s.discard("10.1.0.0/24")
        self.assertEqual(s.networks(), nets("10.0.0.0/24"))

    def test_discard_spans_multiple_ranges(self):
        s = CIDRSet(["10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24"])
        s.discard("10.0.0.128/25")
        s.discard("10.0.1.0/24")
        s.discard("10.0.2.0/25")
        self.assertEqual(s.networks(), nets("10.0.0.0/25", "10.0.2.128/25"))


class TestAddressFamilies(unittest.TestCase):
    def test_ipv6_set(self):
        s = CIDRSet(["2001:db8::/32", "2001:db9::/32"])
        self.assertEqual(s.version, 6)
        self.assertIn("2001:db8::1", s)
        self.assertNotIn("2001:dba::1", s)

    def test_ipv6_adjacent_merge(self):
        s = CIDRSet(["2001:db8::/33", "2001:db8:8000::/33"])
        self.assertEqual(s.networks(), nets("2001:db8::/32"))

    def test_mixing_v4_into_v6_raises(self):
        s = CIDRSet(["2001:db8::/32"])
        with self.assertRaises(MixedAddressFamilyError):
            s.add("10.0.0.0/8")
        with self.assertRaises(MixedAddressFamilyError):
            s.discard("10.0.0.0/8")

    def test_mixing_v6_into_v4_raises(self):
        s = CIDRSet(["10.0.0.0/8"])
        with self.assertRaises(MixedAddressFamilyError):
            s.add("2001:db8::/32")

    def test_pinned_empty_set_rejects_other_family(self):
        s = CIDRSet(version=4)
        with self.assertRaises(MixedAddressFamilyError):
            s.add("::/0")

    def test_families_are_separate_sets(self):
        v4 = CIDRSet(["0.0.0.0/0"])
        v6 = CIDRSet(["::/0"])
        self.assertEqual(v4.version, 4)
        self.assertEqual(v6.version, 6)
        self.assertIn("1.2.3.4", v4)
        self.assertIn("::1", v6)


class TestEmptyAndEverything(unittest.TestCase):
    def test_empty_set(self):
        s = CIDRSet()
        self.assertEqual(len(s), 0)
        self.assertFalse(s)
        self.assertEqual(s.networks(), [])
        self.assertIsNone(s.version)
        self.assertNotIn("10.0.0.1", s)
        self.assertNotIn("::1", s)

    def test_all_zeros_v4(self):
        s = CIDRSet(["0.0.0.0/0"])
        self.assertEqual(s.networks(), nets("0.0.0.0/0"))
        self.assertIn("255.255.255.255", s)
        self.assertIn("0.0.0.0", s)
        s.discard("0.0.0.0/0")
        self.assertEqual(len(s), 0)

    def test_all_zeros_v6(self):
        s = CIDRSet(["::/0"])
        self.assertIn("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", s)
        s.discard("::/0")
        self.assertEqual(len(s), 0)

    def test_adjacent_halves_merge_to_slash0(self):
        s = CIDRSet(["0.0.0.0/1", "128.0.0.0/1"])
        self.assertEqual(s.networks(), nets("0.0.0.0/0"))


class TestStrictInputValidation(unittest.TestCase):
    def test_host_bits_set_rejected(self):
        with self.assertRaises(ValueError):
            CIDRSet(["10.0.0.1/24"])

    def test_bad_prefix_length_rejected(self):
        with self.assertRaises(ValueError):
            CIDRSet(["10.0.0.0/33"])
        with self.assertRaises(ValueError):
            CIDRSet(["2001:db8::/129"])

    def test_garbage_rejected(self):
        with self.assertRaises(ValueError):
            CIDRSet(["not-a-network"])
        with self.assertRaises(ValueError):
            CIDRSet(["10.0.0.0/24"]).add("999.0.0.0/8")

    def test_wrong_type_rejected(self):
        with self.assertRaises(TypeError):
            CIDRSet([12345])

    def test_bad_version_kwarg(self):
        with self.assertRaises(ValueError):
            CIDRSet(version=5)


class TestEqualityAndRepr(unittest.TestCase):
    def test_equality(self):
        a = CIDRSet(["10.0.0.0/24", "10.0.1.0/24"])
        b = CIDRSet(["10.0.0.0/23"])
        self.assertEqual(a, b)

    def test_repr(self):
        s = CIDRSet(["10.0.0.0/24"])
        self.assertIn("10.0.0.0/24", repr(s))


if __name__ == "__main__":
    unittest.main()

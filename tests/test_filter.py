import tempfile
import time
import unittest

from adblock.filter import Filter, normalize_domain, parse_list


class ParseListTest(unittest.TestCase):
    def test_hosts_and_adblock_formats(self):
        text = """
        # comment
        0.0.0.0 ads.example.com
        127.0.0.1 localhost
        0.0.0.0 tracker.example  # trailing comment
        plain.example
        ||adblock.example^
        ||path.example/ads^
        @@||exception.example^
        ! adblock comment
        """
        self.assertEqual(parse_list(text),
                         {"ads.example.com", "tracker.example", "plain.example", "adblock.example"})

    def test_normalize_domain(self):
        self.assertEqual(normalize_domain(" Ads.Example.COM. "), "ads.example.com")
        self.assertEqual(normalize_domain("*.example.com"), "example.com")
        with self.assertRaises(ValueError):
            normalize_domain("not a domain")


class FilterTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.f = Filter(self.tmp.name)
        self.f._list_domains = frozenset({"ads.example.com", "doubleclick.net"})

    def tearDown(self):
        self.tmp.cleanup()

    def test_blocks_listed_domains_and_subdomains(self):
        self.assertTrue(self.f.check("ads.example.com")[0])
        self.assertTrue(self.f.check("stats.g.doubleclick.net")[0])
        self.assertFalse(self.f.check("example.com")[0])

    def test_allowlist_overrides_blocklists(self):
        self.f.add_entry("allowlist", "doubleclick.net")
        self.assertFalse(self.f.check("stats.g.doubleclick.net")[0])

    def test_custom_block(self):
        self.f.add_entry("blocklist", "example.org")
        self.assertTrue(self.f.check("www.example.org")[0])

    def test_client_bypass(self):
        self.f.add_entry("bypass_clients", "192.168.1.50")
        self.assertFalse(self.f.check("doubleclick.net", "192.168.1.50")[0])
        self.assertTrue(self.f.check("doubleclick.net", "192.168.1.51")[0])

    def test_disable_and_pause(self):
        self.f.set_enabled(False)
        self.assertFalse(self.f.check("doubleclick.net")[0])
        self.f.set_enabled(True)
        self.f.pause(5)
        self.assertFalse(self.f.check("doubleclick.net")[0])
        self.f.paused_until = time.time() - 1
        self.assertTrue(self.f.check("doubleclick.net")[0])

    def test_settings_persist(self):
        self.f.add_entry("allowlist", "keep.example")
        self.f.set_enabled(False)
        reloaded = Filter(self.tmp.name)
        self.assertIn("keep.example", reloaded.allowlist)
        self.assertFalse(reloaded.enabled)


if __name__ == "__main__":
    unittest.main()

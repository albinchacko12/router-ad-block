import functools
import http.server
import json
import os
import tempfile
import threading
import time
import unittest

from adblock.config import DEFAULT_LISTS
from adblock.filter import Filter, normalize_domain, parse_list


class ParseListTest(unittest.TestCase):
    def test_hosts_file(self):
        text = """
        # comment
        0.0.0.0 ads.example.com
        127.0.0.1 localhost
        0.0.0.0 tracker.example other.example  # trailing comment
        """
        self.assertEqual(set(parse_list(text).block),
                         {"ads.example.com", "tracker.example", "other.example"})

    def test_plain_domain_list(self):
        self.assertEqual(set(parse_list("# list\nads.example\ntrack.example\n").block),
                         {"ads.example", "track.example"})

    def test_ubo_host_rules(self):
        text = """
        [Adblock Plus 2.0]
        ! Title: test
        ||plain.example^
        ||thirdparty.example^$third-party
        ||short3p.example^$3p
        ||doc.example^$doc
        ||all.example^$all
        ||pipe.example^|
        """
        self.assertEqual(set(parse_list(text).block),
                         {"plain.example", "thirdparty.example", "short3p.example",
                          "doc.example", "all.example", "pipe.example"})

    def test_ubo_rules_that_do_not_cover_a_whole_host_are_ignored(self):
        text = """
        ! Title: test
        ||script.example^$script
        ||site.example^$domain=other.example
        ||popup.example^$popup
        ||path.example/ads/banner.js
        ||wild.*^
        ||1.2.3.4^
        example.com##.ad-banner
        ##.generic-ad
        example.com#@#.ad
        example.com##+js(set-constant, x, y)
        /banner[0-9]+/
        _chartbeat.js
        -ad-banner.
        """
        self.assertEqual(len(parse_list(text)), 0)

    def test_exceptions_and_badfilter(self):
        text = """
        ! Title: test
        ||ads.example^
        @@||ok.ads.example^
        @@||partial.example^$script
        @@||cosmetic.example^$ghide
        ||broken.example^$3p
        ||broken.example^$3p,badfilter
        """
        parsed = parse_list(text)
        self.assertEqual(parsed.allow, {"ok.ads.example"})
        self.assertIn(("broken.example", frozenset({"3p"})), parsed.badfilter)

    def test_preprocessor(self):
        text = """
        ! Title: test
        !#if env_mobile
        ||mobile.example^
        !#else
        ||desktop.example^
        !#endif
        !#if !ext_ubol
        ||notlite.example^
        !#endif
        !#if false
        !#if true
        ||nested.example^
        !#endif
        !#endif
        """
        self.assertEqual(set(parse_list(text).block), {"desktop.example", "notlite.example"})

    def test_normalize_domain(self):
        self.assertEqual(normalize_domain(" Ads.Example.COM. "), "ads.example.com")
        self.assertEqual(normalize_domain("*.example.com"), "example.com")
        with self.assertRaises(ValueError):
            normalize_domain("not a domain")


class FilterTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.f = Filter(self.tmp.name)
        self.f._index = ({"ads.example.com": "Test list", "doubleclick.net": "Test list"},
                         frozenset(), frozenset())

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

    def _write_list(self, name, text):
        url = f"https://lists.example/{name}.txt"
        self.f.lists.append({"name": name, "url": url, "enabled": True})
        with open(self.f._cache_path(url), "w") as fh:
            fh.write(text)

    def test_lists_combine_exceptions_badfilter_and_important(self):
        self.f.lists = []
        self._write_list("ads", "! a\n||ads.example^\n||cdn.example^$3p\n||evil.example^$important\n")
        self._write_list("unbreak", "! b\n@@||ok.ads.example^\n||cdn.example^$3p,badfilter\n"
                                    "@@||evil.example^\n")
        self.f._rebuild_from_cache()
        self.assertEqual(self.f.check("x.ads.example"), (True, "ads (ads.example)"))
        self.assertFalse(self.f.check("ok.ads.example")[0])
        self.assertFalse(self.f.check("cdn.example")[0])
        self.assertTrue(self.f.check("evil.example")[0])

    def test_disabled_list_is_ignored(self):
        self.f.lists = []
        self._write_list("ads", "||ads.example^\n")
        self.f.set_list_enabled("https://lists.example/ads.txt", False)
        self.assertFalse(self.f.check("ads.example")[0])

    def test_legacy_default_lists_are_upgraded(self):
        with open(self.f.state_path, "w") as fh:
            json.dump({"lists": [{"url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
                                  "enabled": True}]}, fh)
        self.assertEqual([e["url"] for e in Filter(self.tmp.name).lists],
                         [e["url"] for e in DEFAULT_LISTS])

    def test_includes_are_inlined(self):
        site = tempfile.TemporaryDirectory()
        self.addCleanup(site.cleanup)
        os.mkdir(os.path.join(site.name, "filters"))
        files = {"filters/main.txt": "! main\n||main.example^\n!#include sub.txt\n"
                                     "!#if env_mobile\n!#include mobile.txt\n!#endif\n"
                                     "!#include ../outside.txt\n",
                 "filters/sub.txt": "||sub.example^\n",
                 "filters/mobile.txt": "||mobile.example^\n",
                 "outside.txt": "||outside.example^\n"}
        for name, body in files.items():
            with open(os.path.join(site.name, name), "w") as fh:
                fh.write(body)
        handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=site.name)
        handler.log_message = lambda *a: None
        server = http.server.HTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)

        self.f.lists = []
        self.f.add_list(f"http://127.0.0.1:{server.server_port}/filters/main.txt", "main")
        self.f.refresh_lists()
        self.assertTrue(self.f.check("main.example")[0])
        self.assertTrue(self.f.check("sub.example")[0])
        self.assertFalse(self.f.check("mobile.example")[0])
        self.assertFalse(self.f.check("outside.example")[0])

    def test_settings_persist(self):
        self.f.add_entry("allowlist", "keep.example")
        self.f.set_enabled(False)
        reloaded = Filter(self.tmp.name)
        self.assertIn("keep.example", reloaded.allowlist)
        self.assertFalse(reloaded.enabled)


if __name__ == "__main__":
    unittest.main()

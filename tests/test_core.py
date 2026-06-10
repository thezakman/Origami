"""Unit tests for Origami's pure logic — no network required.

Run:  PYTHONPATH=. .venv/bin/python -m unittest discover -s tests -p 'test_*.py'
"""

import unittest

from origami.core.normalize import hamming, simhash
from origami.core.evidence import ContextBaseline, TargetProfile
from origami.core.httpclient import Probe
from origami.core.response_classifier import Filters, classify
from origami.modules import waf
from origami.modules.discovery import backups, js_parser, robots, shortname


def make_probe(status=200, body=b"<html>hi</html>", url="http://t/x", ctype="text/html",
               location=""):
    return Probe(url=url, method="GET", status=status, length=len(body),
                 words=len(body.split()), lines=body.count(b"\n") + 1,
                 content_type=ctype, location=location,
                 body_simhash=simhash(body), elapsed_ms=1.0,
                 body_head=body[:2048], body=body)


class TestSimhash(unittest.TestCase):
    def test_identical_zero_distance(self):
        b = b"<html><body>welcome to the portal</body></html>"
        self.assertEqual(hamming(simhash(b), simhash(b)), 0)

    def test_dynamic_noise_ignored(self):
        # same page, different CSRF token / timestamp each render
        a = b"<html><body>Not Found <!-- csrf=deadbeefdeadbeef 1700000000 --></body></html>"
        b = b"<html><body>Not Found <!-- csrf=cafebabecafebabe 1700009999 --></body></html>"
        self.assertLessEqual(hamming(simhash(a), simhash(b)), 3)

    def test_structurally_different_far(self):
        a = b"<html><body>login form username password submit</body></html>"
        b = b"<html><body>welcome dashboard reports settings logout</body></html>"
        self.assertGreater(hamming(simhash(a), simhash(b)), 3)


class TestClassify(unittest.TestCase):
    def _profile_with_baseline(self, miss_body=b"<html>not found</html>", status=404):
        p = TargetProfile(host="t", base_url="http://t/")
        cb = ContextBaseline(prefix="/", ext_class="none", status=status,
                             simhashes=[simhash(miss_body)], content_type="text/html")
        p.baseline[TargetProfile.context_key("/", "none")] = cb
        return p

    def test_404_never_a_hit(self):
        # even on a soft-404 host (baseline 200), a real 404 is not found
        p = self._profile_with_baseline(status=200)
        probe = make_probe(status=404, url="http://t/whatever")
        self.assertIsNone(classify(p, probe, "wordlist", "/"))

    def test_400_never_a_hit(self):
        p = self._profile_with_baseline()
        self.assertIsNone(classify(p, make_probe(status=400, url="http://t/%2e"), "wordlist", "/"))

    def test_real_hit_differs_from_miss(self):
        p = self._profile_with_baseline()
        probe = make_probe(status=200, body=b"<html>real admin dashboard here</html>",
                           url="http://t/admin")
        f = classify(p, probe, "wordlist", "/")
        self.assertIsNotNone(f)
        self.assertEqual(f.status, 200)

    def test_miss_matches_baseline(self):
        p = self._profile_with_baseline()
        # same status + same body shape as the miss baseline → not a hit
        probe = make_probe(status=404, body=b"<html>not found</html>", url="http://t/x")
        self.assertIsNone(classify(p, probe, "wordlist", "/"))


class TestFilters(unittest.TestCase):
    def test_default_accepts_all(self):
        f = Filters()
        self.assertTrue(f.accept(200, 100))
        self.assertTrue(f.accept(403, 50))

    def test_match_codes(self):
        f = Filters(match_codes={200})
        self.assertTrue(f.accept(200, 1))
        self.assertFalse(f.accept(403, 1))

    def test_filter_codes(self):
        f = Filters(filter_codes={403})
        self.assertFalse(f.accept(403, 1))
        self.assertTrue(f.accept(200, 1))

    def test_size_filters(self):
        self.assertFalse(Filters(filter_sizes={150}).accept(200, 150))
        self.assertFalse(Filters(match_sizes={10}).accept(200, 99))


class TestShortname(unittest.TestCase):
    SAMPLE = (
        '{"type":"status","url":"http://t/","server":"IIS","vulnerable":true}\n'
        '{"type":"file","baseurl":"http://t/","shorttilde":"ADMINI~1",'
        '"shortfile":"ADMINI","shortext":"ASP","fullname":"administration.aspx","fullmatch":true}\n'
        '{"type":"file","baseurl":"http://t/","shorttilde":"CONFIG~1",'
        '"shortfile":"CONFIG","shortext":"CON"}\n'
        '{"type":"statistics","requests":10}\n'
    )

    def test_parse(self):
        r = shortname.parse_ndjson(self.SAMPLE)
        self.assertTrue(r.vulnerable)
        self.assertEqual(len(r.entries), 2)
        self.assertEqual(r.entries[0].fullname, "administration.aspx")

    def test_ext_family(self):
        self.assertEqual(shortname.ext_family("ASP"), [".asp", ".aspx"])
        self.assertEqual(shortname.ext_family("CON"), [".config"])
        self.assertEqual(shortname.ext_family("XYZ"), [".xyz"])

    def test_expand_constraint_filter(self):
        r = shortname.parse_ndjson(self.SAMPLE)
        words = ["administration", "admin", "configuration", "config", "other"]
        paths = {p for _, p in shortname.expand(r.entries, words)}
        self.assertIn("administration.aspx", paths)      # autocomplete seed
        self.assertIn("configuration.config", paths)      # constraint-filtered
        self.assertNotIn("admin.asp", paths)              # too short for ADMINI prefix
        self.assertNotIn("other.config", paths)           # doesn't match CONFIG prefix


class TestRobots(unittest.TestCase):
    def test_robots(self):
        body = b"User-agent: *\nDisallow: /admin/\nDisallow: /secret/x.aspx\nDisallow: /*.json\n"
        paths = robots.parse_robots(body, "http://t/")
        self.assertIn("/admin/", paths)
        self.assertIn("/secret/x.aspx", paths)
        self.assertFalse(any("*" in p for p in paths))     # wildcards dropped

    def test_sitemap(self):
        body = b"<urlset><url><loc>http://t/a/b.pdf</loc></url><loc>/c/d.aspx</loc></urlset>"
        paths = robots.parse_sitemap(body, "http://t/")
        self.assertIn("/a/b.pdf", paths)
        self.assertIn("/c/d.aspx", paths)


class TestBackups(unittest.TestCase):
    def test_variations(self):
        v = backups.variations("admin/index.php")
        self.assertIn("admin/index.php.bak", v)
        self.assertIn("admin/index.php~", v)
        self.assertIn("admin/.index.php.swp", v)
        self.assertIn("admin/index.bak", v)

    def test_no_variations_for_dirs_or_extless(self):
        self.assertEqual(backups.variations("admin/"), [])
        self.assertEqual(backups.variations("noextension"), [])

    def test_is_file_hit(self):
        self.assertTrue(backups.is_file_hit("http://t/a/x.php", 200))
        self.assertFalse(backups.is_file_hit("http://t/a/", 200))
        self.assertFalse(backups.is_file_hit("http://t/a/x.php", 403))


class TestVocabulary(unittest.TestCase):
    def test_derive(self):
        from origami.core.scheduler import derive_vocabulary
        names, exts = derive_vocabulary(
            {"api/v1/users", "js/app.min.js", "reports/q3.pdf", "getOrders.ashx"})
        self.assertIn("users", names)
        self.assertIn("app", names)         # split on app.min
        self.assertIn("getorders", names)   # lowercased
        for e in (".js", ".ashx", ".pdf"):
            self.assertIn(e, exts)
        # frequency-ranked: most_common works for the fold budget
        self.assertTrue(names.most_common(1))


class TestNGram(unittest.TestCase):
    def test_completes_from_prefix(self):
        from origami.brain.ngram import NGram
        corpus = ["integration", "integrations", "integrationservice", "internal",
                  "interface", "administration", "administrator"]
        ng = NGram(order=3).train(corpus)
        out = ng.complete("integ", n_results=5)
        self.assertTrue(out)                              # generated something
        self.assertTrue(all(c.startswith("integ") for c in out))
        self.assertTrue(all(len(c) > len("integ") for c in out))

    def test_empty_model_and_no_match(self):
        from origami.brain.ngram import NGram
        self.assertEqual(NGram().complete("anything"), [])      # untrained
        ng = NGram(order=3).train(["foobar"])
        self.assertEqual(ng.complete("zzzzz"), [])             # prefix unseen


class TestWaf(unittest.TestCase):
    def test_f5_block_body(self):
        body = (b"<html><head><title>Request Rejected</title></head><body>"
                b"The requested URL was rejected. Please consult with your administrator."
                b"<br/>Your support ID is a59f337a-4368-47a0-bf56-f8d538cb1b22</body></html>")
        self.assertEqual(waf.detect_block_body(body), "F5 BIG-IP ASM")
        self.assertTrue(waf.is_block(make_probe(body=body)))

    def test_clean_body_not_block(self):
        self.assertIsNone(waf.detect_block_body(b"<html>welcome to the dashboard</html>"))

    def test_header_cookie_detection(self):
        self.assertEqual(waf.detect_from_headers({"cf-ray": "abc"}, []), "Cloudflare")
        self.assertEqual(waf.detect_from_headers({}, ["incap_ses_123=x"]), "Imperva Incapsula")

    def test_classify_suppresses_waf_block(self):
        from origami.core.evidence import ContextBaseline, TargetProfile
        from origami.core.response_classifier import classify
        p = TargetProfile(host="t", base_url="http://t/")
        p.baseline[TargetProfile.context_key("/", "none")] = ContextBaseline(
            prefix="/", ext_class="none", status=302, redirect_to="->x", is_soft404=True)
        block = make_probe(status=200, url="http://t/.env",
                           body=b"The requested URL was rejected. Your support ID is x")
        self.assertIsNone(classify(p, block, "wordlist", "/"))
        self.assertEqual(p.waf, "F5 BIG-IP ASM")


class TestJsParser(unittest.TestCase):
    def test_extract(self):
        body = (b'<a href="/admin/panel">x</a>'
                b'fetch("/api/v1/users");'
                b'<link href="/style.css">'
                b'axios.get("/reports/data.json")')
        paths = js_parser.extract_paths(body, "http://t/")
        self.assertIn("/admin/panel", paths)
        self.assertIn("/api/v1/users", paths)
        self.assertIn("/reports/data.json", paths)
        self.assertNotIn("/style.css", paths)              # asset, dropped

    def test_query_stripped_and_params(self):
        body = (b'fetch("/lms/?accesssala&idtrilha");'
                b'fetch("/lms/?cid&onlyCategories");'
                b'fetch("/api/users?idCurso=1&isAdmin=0");')
        paths = js_parser.extract_paths(body, "http://t/")
        self.assertEqual({p for p in paths if "lms" in p}, {"/lms/"})  # collapsed, root-abs
        self.assertNotIn("/lms/?accesssala&idtrilha", paths)
        params = js_parser.extract_params(body)
        for name in ("accesssala", "idtrilha", "cid", "onlycategories", "idcurso", "isadmin"):
            self.assertIn(name, params)

    def test_script_urls_skip_vendor_pick_datamain(self):
        body = (b'<script src="//cdn.x.com/lib/jquery/jquery.js"></script>'
                b'<script src="//cdn.x.com/lib/bootstrap/js/bootstrap.js"></script>'
                b'<script data-main="app.bootstrap.js" src="//cdn.x.com/lib/require.js"></script>'
                b'<script src="//cdn.x.com/app.definitions.js"></script>')
        urls = js_parser.script_urls(body, "http://x.com/lms/")
        joined = " ".join(urls)
        self.assertNotIn("jquery", joined)                  # vendor skipped
        self.assertNotIn("require.js", joined)              # vendor skipped
        self.assertNotIn("lib/bootstrap/js/bootstrap.js", joined)
        self.assertTrue(any(u.endswith("/lms/app.bootstrap.js") for u in urls))  # data-main
        self.assertTrue(any("app.definitions.js" in u for u in urls))

    def test_sourcemap_and_chunk(self):
        body = (b'var c="/js/chunk.2f3a.js";'
                b'//# sourceMappingURL=/js/app.js.map')
        paths = js_parser.extract_paths(body, "http://t/")
        self.assertIn("/js/chunk.2f3a.js", paths)
        self.assertIn("/js/app.js.map", paths)


if __name__ == "__main__":
    unittest.main()

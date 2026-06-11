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


class TestMemoryKNN(unittest.TestCase):
    def test_knn_primes_from_nearest_host(self):
        import os
        import tempfile
        from origami.brain.memory import Memory
        from origami.core.evidence import TargetProfile
        from origami.core.response_classifier import Finding

        class R:
            def __init__(self, findings):
                self.findings = findings
                self.requests_made = 10

        db = tempfile.mktemp(suffix=".sqlite")
        m = Memory(db)
        try:
            a = TargetProfile(host="a.com", base_url="http://a.com/")
            a.tech_scores = {"iis": 90, "aspnet": 80}
            a.enabled_extensions = {".aspx", ".asmx"}
            m.record_run(a, R([make_finding("http://a.com/admin.aspx"),
                               make_finding("http://a.com/api.asmx")]))
            b = TargetProfile(host="b.com", base_url="http://b.com/")
            b.tech_scores = {"php": 90}
            b.enabled_extensions = {".php"}
            m.record_run(b, R([make_finding("http://b.com/index.php")]))

            probe = TargetProfile(host="c.com", base_url="http://c.com/")
            probe.tech_scores = {"iis": 85, "aspnet": 75}
            probe.enabled_extensions = {".aspx"}
            primed = m.recall_knn(probe)
            self.assertIn("/admin.aspx", primed)      # from the near IIS host
            self.assertNotIn("/index.php", primed)    # PHP host is far → excluded
        finally:
            m.close()
            os.unlink(db)


def make_finding(url, status=200):
    from origami.core.response_classifier import Finding
    return Finding(url, status, 100, "text/html", 0.9, "wordlist")


class TestAssociation(unittest.TestCase):
    def test_corpus_rule(self):
        import os
        import tempfile
        from origami.brain.memory import Memory
        from origami.core.evidence import TargetProfile

        class R:
            def __init__(self, findings):
                self.findings = findings
                self.requests_made = 10

        db = tempfile.mktemp(suffix=".sqlite")
        m = Memory(db)
        try:
            # 3 hosts that have BOTH /backup/ and /.git/HEAD
            for h in ("h1", "h2", "h3"):
                p = TargetProfile(host=h, base_url=f"http://{h}/")
                m.record_run(p, R([make_finding(f"http://{h}/backup/", 403),
                                   make_finding(f"http://{h}/.git/HEAD")]))
            # 1 host with only /backup/
            p = TargetProfile(host="h4", base_url="http://h4/")
            m.record_run(p, R([make_finding("http://h4/backup/", 403)]))

            assoc = m.associate(["/backup/"], min_support=2, min_conf=0.5)
            self.assertIn("/.git/HEAD", assoc)        # 3/4 hosts → conf 0.75
            self.assertNotIn("/backup/", assoc)       # antecedent excluded
        finally:
            m.close()
            os.unlink(db)


class TestWappalyzerIngest(unittest.TestCase):
    def test_literalize(self):
        from origami.brain.ingest import wappalyzer as w
        self.assertEqual(w.literalize(r"Microsoft-IIS\;confidence:100"), "Microsoft-IIS")
        self.assertEqual(w.literalize(r"jquery[.-]?([\d.]+)?\.js\;version:\1"), "jquery")
        self.assertEqual(w.literalize(r"^\d+$"), "")          # no usable literal

    def test_kb_merge_overlay_wins_folds(self):
        import os
        import tempfile
        from pathlib import Path
        from origami.brain.kb import load_kb
        ing, ov = tempfile.mktemp(suffix=".yaml"), tempfile.mktemp(suffix=".yaml")
        Path(ing).write_text(
            "- {tech: IIS, signals: [{type: header, name: server, match: iis, weight: 40}]}\n")
        Path(ov).write_text(
            "- {tech: iis, signals: [{type: cookie, match: ASP.NET_SessionId, weight: 80}],"
            " on_confirm: {extensions: ['.aspx'], folds: [shortscan]}}\n")
        try:
            rules = {r.tech: r for r in load_kb(Path(ing), Path(ov))}
            iis = rules["iis"]                              # merged by lowercased name
            self.assertEqual({s.type for s in iis.signals}, {"header", "cookie"})  # union
            self.assertEqual(iis.folds, ["shortscan"])     # overlay folds win
            self.assertIn(".aspx", iis.extensions)
        finally:
            os.unlink(ing)
            os.unlink(ov)

    def test_db_to_rules(self):
        from origami.brain.ingest import wappalyzer as w
        db = {
            "Microsoft IIS": {"headers": {"Server": r"Microsoft-IIS(?:/([\d.]+))?\;version:\1"}},
            "PHP": {"headers": {"X-Powered-By": r"PHP(?:/([\d.]+))?\;version:\1"},
                    "cookies": {"PHPSESSID": ""}},
            "WordPress": {"html": [r"<link[^>]+/wp-content/"]},
            "Empty": {"cats": [1]},
        }
        rules = {r["tech"]: r for r in w.db_to_rules(db)}
        self.assertIn("microsoft iis", rules)
        self.assertEqual(rules["microsoft iis"]["signals"][0]["match"], "Microsoft-IIS")
        self.assertTrue(any(s["type"] == "cookie" and s["match"] == "PHPSESSID"
                            for s in rules["php"]["signals"]))
        self.assertIn("wordpress", rules)
        self.assertNotIn("empty", rules)                       # no usable signals


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


class TestEngineBackoff(unittest.TestCase):
    def _engine(self, c=20):
        from origami.core.httpclient import Engine, EngineConfig
        return Engine(EngineConfig(concurrency=c))

    def test_pushback_halves_limit(self):
        e = self._engine(20)
        self.assertEqual(e.concurrency_limit, 20)
        e._note_pushback()
        self.assertEqual(e._limit, 10.0)
        e._note_pushback()
        self.assertEqual(e._limit, 5.0)

    def test_limit_floor_is_one(self):
        e = self._engine(20)
        for _ in range(50):
            e._note_pushback()
        self.assertEqual(e._limit, 1.0)

    def test_relax_ramps_back_to_ceiling(self):
        e = self._engine(8)
        e._note_pushback()           # 8 -> 4
        self.assertEqual(e._limit, 4.0)
        for _ in range(100):
            e._relax()
        self.assertEqual(e.concurrency_limit, 8)

    def test_pushback_grows_delay_floor(self):
        e = self._engine()
        self.assertEqual(e._delay_floor, 0.0)
        e._note_pushback()
        self.assertGreater(e._delay_floor, 0.0)
        self.assertLessEqual(e._delay_floor, 5.0)


class TestBandit(unittest.TestCase):
    def test_word_of(self):
        from origami.brain.bandit import word_of
        self.assertEqual(word_of("admin.aspx"), "admin")
        self.assertEqual(word_of("/api/Login.PHP"), "login")
        self.assertEqual(word_of("backup/"), "backup")
        self.assertEqual(word_of("https://h/x/getOrders.ashx"), "getorders")

    def test_expected_ordering(self):
        from origami.brain.bandit import Ranker
        r = Ranker({"good": (20, 1), "bad": (0, 40), "unseen": (0, 0)})
        self.assertGreater(r.expected("good"), r.expected("unseen"))
        self.assertGreater(r.expected("unseen"), r.expected("bad"))

    def test_order_puts_proven_first(self):
        import random
        from origami.brain.bandit import Ranker
        r = Ranker({"login": (30, 1), "zzqqx": (0, 60)}, rng=random.Random(1))
        order = r.order(["zzqqx.aspx", "login.aspx"])
        self.assertEqual(order[0], "login.aspx")

    def test_update_and_deltas(self):
        from origami.brain.bandit import Ranker
        r = Ranker()
        r.observe("admin.php", hit=True)
        r.observe("admin.php", hit=False)
        r.observe("nope", hit=False)
        self.assertEqual(r.deltas(), {"admin": (1, 1), "nope": (0, 1)})

    def test_memory_roundtrip(self):
        import tempfile
        from pathlib import Path
        from origami.brain.memory import Memory
        with tempfile.TemporaryDirectory() as d:
            m = Memory(Path(d) / "m.sqlite")
            m.record_word_stats({"login": (3, 2), "admin": (1, 0)}, ["php"])
            m.record_word_stats({"login": (1, 1)}, ["php"])
            stats = m.load_word_stats(["php"])
            # each run writes both a '*' row and a 'php' row; load pools both.
            # login: '*'=(4,3) + 'php'=(4,3) = (8,6)
            self.assertEqual(stats["login"], (8, 6))
            self.assertEqual(stats["admin"], (2, 0))
            m.close()


class TestResume(unittest.TestCase):
    def _state(self, path):
        from origami.core import resume as R
        from origami.core.evidence import Evidence
        from origami.core.response_classifier import Finding
        p = TargetProfile(host="h.example", base_url="https://h.example/app/")
        p.tech_scores = {"iis": 70.0}
        p.enabled_extensions = {".aspx", ".asmx"}
        p.parameters = {"id", "q"}
        p.wildcard = True
        p.add_evidence(Evidence(source="header", tech="iis", detail="Server: IIS", weight=70))
        cb = ContextBaseline(prefix="/app/", ext_class=".aspx", status=404)
        cb.simhashes = [123, 456]
        cb.soft_signatures = [(200, 999)]
        p.baseline["/app/|.aspx"] = cb
        findings = [Finding("https://h.example/app/login.aspx", 200, 10, "text/html",
                            0.9, "wordlist", note="x", tags=["auth"], simhash=42)]
        R.save(path, profile=p, findings=findings, requests_made=17, folds={"shortscan"},
               words=["a", "b"], exts={".aspx"}, priority_paths=["/p"],
               root_seeds=[("/x", "js")], base_prefix="/app/",
               queue=[("/app/sub/", 1)], scanned={"/app/"})

    def test_roundtrip(self):
        import tempfile
        from pathlib import Path
        from origami.core import resume as R
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "s.json"
            self._state(path)
            st = R.load(path)
            self.assertEqual(st["profile"].host, "h.example")
            self.assertEqual(st["profile"].tech_scores["iis"], 70.0)
            self.assertEqual(st["profile"].enabled_extensions, {".aspx", ".asmx"})
            self.assertTrue(st["profile"].wildcard)
            cb = st["profile"].baseline["/app/|.aspx"]
            self.assertEqual(cb.simhashes, [123, 456])
            self.assertEqual(cb.soft_signatures, [(200, 999)])
            self.assertEqual(len(st["findings"]), 1)
            self.assertEqual(st["findings"][0].url, "https://h.example/app/login.aspx")
            self.assertEqual(st["findings"][0].tags, ["auth"])
            self.assertEqual(st["requests_made"], 17)
            self.assertEqual(st["queue"], [("/app/sub/", 1)])
            self.assertEqual(st["scanned"], ["/app/"])
            self.assertEqual(st["exts"], {".aspx"})
            self.assertEqual(st["root_seeds"], [("/x", "js")])

    def test_missing_returns_none(self):
        from pathlib import Path
        from origami.core import resume as R
        self.assertIsNone(R.load(Path("/nonexistent/nope.json")))

    def test_start_offset_roundtrip(self):
        import tempfile
        from pathlib import Path
        from origami.core import resume as R
        from origami.core.evidence import TargetProfile
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "s.json"
            R.save(path, profile=TargetProfile(host="h", base_url="http://h/"),
                   findings=[], requests_made=0, folds=set(), words=[], exts=set(),
                   priority_paths=[], root_seeds=[], base_prefix="/",
                   queue=[("/a/", 1)], scanned=set(), start_offset=137)
            self.assertEqual(R.load(path)["start_offset"], 137)

    def test_bad_version_rejected(self):
        import json
        import tempfile
        from pathlib import Path
        from origami.core import resume as R
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "s.json"
            path.write_text(json.dumps({"version": 99}))
            self.assertIsNone(R.load(path))


class TestApiDocs(unittest.TestCase):
    def test_swagger2_basepath_and_templating(self):
        from origami.modules.discovery import apidocs
        spec = {"swagger": "2.0", "basePath": "/api/v2",
                "paths": {"/users": {}, "/users/{id}": {}, "/orders/list": {}}}
        eps = apidocs.extract_endpoints(spec)
        self.assertIn("/api/v2/users", eps)            # static, kept whole
        self.assertIn("/api/v2/orders/list", eps)
        self.assertIn("/api/v2/users/", eps)           # templated → static dir
        self.assertNotIn("/api/v2/users/{id}", eps)    # never the literal template

    def test_openapi3_server_url(self):
        from origami.modules.discovery import apidocs
        spec = {"openapi": "3.0.1", "servers": [{"url": "https://h.example/api/v3"}],
                "paths": {"/ping": {}}}
        self.assertIn("/api/v3/ping", apidocs.extract_endpoints(spec))

    def test_is_spec_and_load(self):
        import json
        from origami.modules.discovery import apidocs
        good = json.dumps({"openapi": "3.0", "paths": {"/a": {}}}).encode()
        self.assertTrue(apidocs._is_spec(apidocs._load(good)))
        self.assertIsNone(apidocs._load(b"not json at all {{{"))
        self.assertFalse(apidocs._is_spec({"hello": "world"}))   # no paths/openapi

    def test_no_paths_returns_empty(self):
        from origami.modules.discovery import apidocs
        self.assertEqual(apidocs.extract_endpoints({"openapi": "3.0"}), set())


class TestHeaderParse(unittest.TestCase):
    def test_parse_headers(self):
        from origami.cli import _parse_headers
        h = _parse_headers(["Cookie: sid=abc", "Authorization: Bearer x.y.z"])
        self.assertEqual(h["Cookie"], "sid=abc")
        self.assertEqual(h["Authorization"], "Bearer x.y.z")

    def test_parse_headers_value_with_colon(self):
        from origami.cli import _parse_headers
        h = _parse_headers(["X-Time: 12:30:00"])         # only first colon splits
        self.assertEqual(h["X-Time"], "12:30:00")

    def test_parse_headers_empty(self):
        from origami.cli import _parse_headers
        self.assertEqual(_parse_headers(None), {})

    def test_parse_headers_bad(self):
        from origami.cli import _parse_headers
        with self.assertRaises(SystemExit):
            _parse_headers(["no-colon-here"])


class TestDirRedirect(unittest.TestCase):
    def test_self_redirect_relative(self):
        from origami.core.scanner import _is_self_redirect_dir
        self.assertTrue(_is_self_redirect_dir("/admin/", "/admin"))     # added trailing slash
        self.assertTrue(_is_self_redirect_dir("/admin", "/admin"))

    def test_self_redirect_absolute(self):
        from origami.core.scanner import _is_self_redirect_dir
        self.assertTrue(_is_self_redirect_dir("http://h/admin/", "/admin"))

    def test_cross_path_redirect_is_not_a_dir(self):
        from origami.core.scanner import _is_self_redirect_dir
        # /login 302 -> /gateway/login must NOT look like a directory self-redirect
        self.assertFalse(_is_self_redirect_dir("/gateway/login", "/login"))
        self.assertFalse(_is_self_redirect_dir("http://h/auth?next=/login", "/login"))


class TestDedup(unittest.TestCase):
    def test_dedup_by_url_keeps_best_confidence(self):
        from origami.core.response_classifier import Finding
        from origami.core.scanner import _dedup_by_url
        fs = [Finding("http://h/a", 200, 10, "", 0.4, "wordlist"),
              Finding("http://h/a", 200, 10, "", 0.9, "memory"),
              Finding("http://h/b", 200, 10, "", 0.5, "wordlist")]
        out = {f.url: f for f in _dedup_by_url(fs)}
        self.assertEqual(len(out), 2)                 # /a collapsed to one
        self.assertEqual(out["http://h/a"].confidence, 0.9)
        self.assertEqual(out["http://h/a"].origin, "memory")


if __name__ == "__main__":
    unittest.main()

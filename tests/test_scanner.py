"""Origami unit tests — scan orchestration — path climb, dedup/collapse, exclude, e2e, graph, parsers.

Split from tests/test_core.py; run via unittest discover.
"""
import unittest

from origami.core.normalize import hamming, simhash
from origami.core.evidence import ContextBaseline, TargetProfile
from origami.core.httpclient import Probe
from origami.core.response_classifier import Filters, classify
from origami.modules import waf
from origami.modules.discovery import backups, js_parser, robots, shortname


def make_probe(status=200, body=b"<html>hi</html>", url="http://t/x", ctype="text/html",
               location="", headers=None):
    return Probe(url=url, method="GET", status=status, length=len(body),
                 words=len(body.split()), lines=body.count(b"\n") + 1,
                 content_type=ctype, location=location,
                 body_simhash=simhash(body), elapsed_ms=1.0,
                 headers=headers or {},
                 body_head=body[:2048], body=body)


def make_finding(url, status=200):
    from origami.core.response_classifier import Finding
    return Finding(url, status, 100, "text/html", 0.9, "wordlist")


def _git_index(paths):
    import struct
    body = b"DIRC" + struct.pack(">II", 2, len(paths))
    for p in paths:
        name = p.encode()
        entry = b"\x00" * 60 + struct.pack(">H", len(name)) + name
        entry += b"\x00" * (8 - (len(entry) % 8))
        body += entry
    return body


def _ds_store(names):
    import struct
    body = b"\x00" * 8
    for n in names:
        nb = n.encode("utf-16-be")
        body += struct.pack(">I", len(n)) + nb + b"Iloc" + b"blob"
    return body + b"\x00" * 4


def _svn_wcdb(relpaths):
    import sqlite3
    con = sqlite3.connect(":memory:")
    con.execute("CREATE TABLE nodes (local_relpath TEXT)")
    con.executemany("INSERT INTO nodes VALUES (?)", [("",)] + [(p,) for p in relpaths])
    con.commit()
    data = con.serialize()
    con.close()
    return data



class TestPathClimb(unittest.TestCase):
    """Path regression: a deep/file target scans its dir and climbs every ancestor."""

    def test_file_target_scans_parent_and_climbs(self):
        from origami.core.scanner import _path_climb
        base, file_seed, anc = _path_climb("/caminho/path/arquivo.pdf")
        self.assertEqual(base, "/caminho/path/")               # scan the DIR, not the file
        self.assertEqual(file_seed, "/caminho/path/arquivo.pdf")  # fetch the file
        self.assertEqual(anc, ["/caminho/", "/"])              # climb to root

    def test_dir_target_climbs_no_file(self):
        from origami.core.scanner import _path_climb
        base, file_seed, anc = _path_climb("/a/b/")
        self.assertEqual(base, "/a/b/")
        self.assertIsNone(file_seed)
        self.assertEqual(anc, ["/a/", "/"])

    def test_root_and_bare_segment(self):
        from origami.core.scanner import _path_climb
        self.assertEqual(_path_climb("/"), ("/", None, []))
        self.assertEqual(_path_climb(""), ("/", None, []))
        # a bare segment with no extension is treated as a directory
        base, file_seed, anc = _path_climb("/caminho")
        self.assertEqual((base, file_seed, anc), ("/caminho/", None, ["/"]))

class TestScanDiff(unittest.TestCase):
    """--diff: current scan vs the last stored run (new / gone / newly-accessible)."""

    def _f(self, path, status, length):
        from origami.core.response_classifier import Finding
        return Finding(f"https://h{path}", status, length, "", 0.9, "wordlist")

    def test_compute_new_gone_changed_opened(self):
        from origami.output import diff
        prior = {"/a": (200, 100), "/admin": (403, 50), "/old": (200, 10)}
        cur = [self._f("/a", 200, 100),          # unchanged
               self._f("/admin", 200, 500),      # 403 → 200: opened (and changed)
               self._f("/new", 200, 20)]         # new
        d = diff.compute(prior, cur)
        self.assertEqual([e["path"] for e in d["new"]], ["/new"])
        self.assertEqual([e["path"] for e in d["gone"]], ["/old"])
        self.assertEqual([e["path"] for e in d["opened"]], ["/admin"])   # the headline
        self.assertIn("/admin", [e["path"] for e in d["changed"]])
        self.assertFalse(diff.is_empty(d))
        rendered = diff.render(d, "h", None)
        self.assertIn("403→200", rendered)
        self.assertIn("newly ACCESSIBLE", rendered)

    def test_compute_empty_when_identical(self):
        from origami.output import diff
        prior = {"/a": (200, 100)}
        d = diff.compute(prior, [self._f("/a", 200, 100)])
        self.assertTrue(diff.is_empty(d))
        self.assertIn("no change", diff.render(d, "h"))

class TestOverlays(unittest.TestCase):
    """Tech-overlay wordlists: confirmed fingerprint → additive stack path packs."""

    def test_packs_for_matches_tech_keywords(self):
        from origami.core import overlays as o
        self.assertEqual(o.packs_for(["iis", "microsoft asp.net"]), ["aspnet"])
        self.assertEqual(o.packs_for(["wordpress", "php"]), ["wordpress"])
        self.assertEqual(o.packs_for(["spring boot", "java"]), ["spring"])
        self.assertEqual(o.packs_for(["nginx", "plone"]), [])          # no pack → nothing
        # multiple confirmed techs → multiple packs, stable order
        self.assertEqual(o.packs_for(["laravel", "wordpress"]), ["wordpress", "laravel"])

    def test_overlay_words_are_additive_and_rooted(self):
        from origami.core import overlays as o
        words, packs = o.overlay_words(["wordpress"])
        self.assertEqual(packs, ["wordpress"])
        self.assertIn("/wp-login.php", words)
        self.assertTrue(all(w.startswith("/") for w in words))         # root-absolute seeds
        self.assertEqual(len(words), len(set(words)))                  # deduped
        self.assertEqual(o.overlay_words(["nginx"]), ([], []))

    def test_all_bundled_packs_load_clean(self):
        from origami.core import overlays as o
        packs = [p for _, p in o._TECH_TO_PACK]
        for pack in packs:
            words = o.load_pack(pack)
            self.assertTrue(words, f"{pack} pack is empty/missing")
            self.assertEqual(len(words), len(set(words)), f"{pack} has dupes")
            self.assertTrue(all(w.startswith("/") and not w.startswith("#") for w in words),
                            f"{pack} has a non-rooted or comment line")

class TestReportDedup(unittest.TestCase):
    def _setup(self, case_sensitive=None):
        from origami.core.scanner import ScanResult, _report
        from origami.core.evidence import TargetProfile
        from origami.output.ui import NullObserver
        from origami.core.scanner import ScanOptions
        p = TargetProfile(host="h", base_url="https://h/")
        p.case_sensitive = case_sensitive
        return ScanResult(profile=p), _report, NullObserver(), ScanOptions()

    def test_same_url_from_two_sources_listed_once(self):
        # memory primes /trace.axd, then the priority list re-finds the same URL.
        r, _report, obs, opts = self._setup()
        _report(obs, r, opts, make_finding("https://h/trace.axd"), "https://h/trace.axd")
        _report(obs, r, opts, make_finding("https://h/trace.axd"), "https://h/trace.axd")
        self.assertEqual([f.url for f in r.findings], ["https://h/trace.axd"])

    def test_declared_api_endpoints_never_collapse(self):
        # A swagger-sourced wall of 401 0B endpoints is the API map, not noise:
        # each must stay listed. Guessed-wordlist 401s at the same shape collapse.
        from origami.core.scanner import _dedupe_and_collapse
        from origami.core.response_classifier import Finding
        from origami.output.ui import NullObserver
        findings = []
        for i in range(6):
            findings.append(Finding(f"https://h/api/res{i}", 401, 0, "", 0.85, "apidocs"))
            findings.append(Finding(f"https://h/guess{i}", 401, 0, "", 0.5, "wordlist"))
        out = _dedupe_and_collapse(findings, NullObserver())
        api = [f for f in out if f.origin == "apidocs"]
        guessed = [f for f in out if f.origin == "wordlist"]
        self.assertEqual(len(api), 6)          # every declared endpoint kept
        self.assertEqual(len(guessed), 1)      # guessed wall collapses to one

    def test_case_variants_collapse_on_iis(self):
        r, _report, obs, opts = self._setup(case_sensitive=False)
        for u in ("https://h/WEBSERVICES", "https://h/webservices", "https://h/WebServices"):
            _report(obs, r, opts, make_finding(u), u)
        self.assertEqual(len(r.findings), 1)

    def test_case_variants_kept_when_case_sensitive(self):
        r, _report, obs, opts = self._setup(case_sensitive=True)
        for u in ("https://h/A", "https://h/a"):
            _report(obs, r, opts, make_finding(u), u)
        self.assertEqual(len(r.findings), 2)

    def test_dedup_survives_case_sensitivity_flip_mid_scan(self):
        # case-sensitivity is undetermined (None) when the first variant is
        # reported, then flips to insensitive (IIS detected on the first hit).
        # The earlier variant must still be deduped against later case variants.
        r, _report, obs, opts = self._setup(case_sensitive=None)
        _report(obs, r, opts, make_finding("https://h/WebServices"), "https://h/WebServices")
        r.profile.case_sensitive = False                  # IIS detected mid-scan
        for u in ("https://h/webservices", "https://h/WEBSERVICES"):
            _report(obs, r, opts, make_finding(u), u)
        self.assertEqual(len(r.findings), 1)              # all one resource

    def test_block_wall_flood_muted_live_but_kept_for_report(self):
        # A 403 wall (same status+length for many .env*/.git* paths): the live
        # stream is muted past COLLISION_MAX, but every finding is still kept so
        # the end-of-scan collapse folds them to one line in the report.
        from origami.core.scanner import _report, ScanResult, ScanOptions, COLLISION_MAX
        from origami.core.evidence import TargetProfile
        from origami.output.ui import NullObserver

        class CountObs(NullObserver):
            def __init__(self): super().__init__(); self.streamed = 0
            def finding(self, f, stream=True):
                if stream: self.streamed += 1

        r = ScanResult(profile=TargetProfile(host="h", base_url="https://h/"))
        obs = CountObs()
        opts = ScanOptions()
        for i in range(20):
            u = f"https://h/.env.{i}"
            _report(obs, r, opts, make_finding(u, status=403), u)
        self.assertEqual(len(r.findings), 20)              # all kept for the collapse
        self.assertEqual(obs.streamed, COLLISION_MAX)      # only the first few streamed

    def test_non_wall_status_not_muted(self):
        from origami.core.scanner import _report, ScanResult, ScanOptions
        from origami.core.evidence import TargetProfile
        from origami.output.ui import NullObserver

        class CountObs(NullObserver):
            def __init__(self): super().__init__(); self.streamed = 0
            def finding(self, f, stream=True):
                if stream: self.streamed += 1

        r = ScanResult(profile=TargetProfile(host="h", base_url="https://h/"))
        obs = CountObs()
        for i in range(20):
            u = f"https://h/page{i}"                        # distinct 200 URLs
            _report(obs, r, ScanOptions(), make_finding(u, status=200), u)
        self.assertEqual(obs.streamed, 20)                 # 2xx never muted live

class TestSlashTwinCollapse(unittest.TestCase):
    def _f(self, url, status=200, length=7, simhash=0, conf=0.95):
        from origami.core.response_classifier import Finding
        return Finding(url, status, length, "text/plain", conf, "memory", simhash=simhash)

    def test_identical_twins_collapse_to_one(self):
        from origami.core.scanner import _collapse_slash_twins
        fs = [self._f("https://h/health"), self._f("https://h/health/")]
        out = _collapse_slash_twins(fs)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].url, "https://h/health")      # no-slash form kept
        # simhash-based identity when set
        fs2 = [self._f("https://h/a", simhash=123, length=5),
               self._f("https://h/a/", simhash=123, length=999)]  # same simhash → same resource
        self.assertEqual(len(_collapse_slash_twins(fs2)), 1)

    def test_differing_twins_both_kept(self):
        from origami.core.scanner import _collapse_slash_twins
        # a redirect vs a 200 → genuinely different, keep both
        fs = [self._f("https://h/x", status=301, length=0),
              self._f("https://h/x/", status=200, length=50)]
        self.assertEqual(len(_collapse_slash_twins(fs)), 2)
        # same status but different body → different, keep both
        fs2 = [self._f("https://h/y", simhash=1, length=10),
               self._f("https://h/y/", simhash=2, length=20)]
        self.assertEqual(len(_collapse_slash_twins(fs2)), 2)
        # unrelated paths never merge
        fs3 = [self._f("https://h/a"), self._f("https://h/ab")]
        self.assertEqual(len(_collapse_slash_twins(fs3)), 2)

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

class TestFoldHygiene(unittest.TestCase):
    def test_confirm_rejects_5xx(self):
        # a speculative fold guess that 500s is the server erroring, not a find
        import asyncio
        from origami.core.scanner import _confirm
        from origami.core.evidence import TargetProfile
        p = TargetProfile(host="h", base_url="http://h/")
        probe = make_probe(status=500, url="http://h/PRINCI~1")
        self.assertIsNone(asyncio.run(_confirm(None, p, "/", probe, "shortscan")))

    def test_dedup_case_insensitive(self):
        from origami.core.scanner import _dedup_by_url
        from origami.core.response_classifier import Finding
        fs = [Finding("http://h/PRINCIPAL", 301, 1, "", 0.85, "shortscan"),
              Finding("http://h/principal", 301, 1, "", 0.85, "shortscan"),
              Finding("http://h/Principal", 301, 1, "", 0.85, "shortscan")]
        self.assertEqual(len(_dedup_by_url(fs, ci=True)), 1)    # IIS: one resource
        self.assertEqual(len(_dedup_by_url(fs, ci=False)), 3)   # case-sensitive: distinct

class TestFoldIsolation(unittest.TestCase):
    def test_guard_isolates_exceptions(self):
        import asyncio
        from origami.core.scanner import _guard
        from origami.output.ui import NullObserver
        obs = NullObserver()

        async def boom():
            raise ValueError("bad response")

        async def good():
            return "ok"

        # a crashing fold yields the default; the scan would carry on
        self.assertEqual(asyncio.run(_guard(obs, "x", boom(), "DEFAULT")), "DEFAULT")
        # a healthy fold passes its value through
        self.assertEqual(asyncio.run(_guard(obs, "x", good(), "DEFAULT")), "ok")

class TestExclude(unittest.TestCase):
    def _opts(self, patterns):
        from origami.core.scanner import ScanOptions
        return ScanOptions(exclude=patterns)

    def test_excluded_matches(self):
        from origami.core.scanner import _excluded
        o = self._opts(["logout", "/delete"])
        self.assertTrue(_excluded("/app/logout", o))
        self.assertTrue(_excluded("/admin/LogOut.aspx", o))   # case-insensitive
        self.assertTrue(_excluded("/api/delete/3", o))
        self.assertFalse(_excluded("/api/users", o))

    def test_empty_exclude_never_matches(self):
        from origami.core.scanner import _excluded
        self.assertFalse(_excluded("/logout", self._opts([])))

    def test_exclude_ext_filters_by_extension_with_glob(self):
        from origami.core.scanner import _ext_excluded, _excluded, ScanOptions
        pats = ["jpg", "png", "css"]
        self.assertTrue(_ext_excluded("/images/balde.png", pats))
        self.assertTrue(_ext_excluded("/css/index.CSS", pats))     # case-insensitive
        self.assertFalse(_ext_excluded("/images/Thumbs.db", pats))  # .db not excluded
        self.assertFalse(_ext_excluded("/css/", pats))             # the dir itself stays
        self.assertFalse(_ext_excluded("/admin", pats))            # no extension
        # glob: jpg* matches jpg, jpge, jpg2 (the user's prefix example)
        g = ["jpg*"]
        self.assertTrue(_ext_excluded("/a/x.jpg", g))
        self.assertTrue(_ext_excluded("/a/x.jpge", g))
        self.assertFalse(_ext_excluded("/a/x.png", g))
        # wired through _excluded (the universal fire guard)
        o = ScanOptions(exclude_ext=["png"])
        self.assertTrue(_excluded("/images/seo.png", o))
        self.assertFalse(_excluded("/images/data.json", o))

class TestEndToEndScan(unittest.TestCase):
    """A real scan against the in-process fake server — exercises the integrated
    pipeline (recon → walk → folds) that the unit tests mock. This is the layer
    that would have caught the 403-bypass report-drop regression."""

    def _server(self):
        import importlib.util
        from pathlib import Path
        from http.server import ThreadingHTTPServer
        spec = importlib.util.spec_from_file_location(
            "_fakeserver_e2e", Path(__file__).parent / "fakeserver" / "server.py")
        srv = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(srv)
        srv.Handler.log_message = lambda *a, **k: None     # quiet during tests
        try:
            httpd = ThreadingHTTPServer(("127.0.0.1", 0), srv.Handler)
        except OSError as e:
            self.skipTest(f"cannot bind loopback socket: {e}")
        return httpd

    def test_full_scan_reports_403_bypass(self):
        import asyncio, tempfile, threading, os
        from origami.core.httpclient import Engine, EngineConfig
        from origami.core.scanner import scan, ScanOptions
        from origami.output.ui import NullObserver

        httpd = self._server()
        port = httpd.server_address[1]
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        wl = tempfile.mktemp(suffix=".txt")
        with open(wl, "w") as fh:
            fh.write("admin\nindex\n")
        quiet = NullObserver(stream=open(os.devnull, "w"))   # no scan chatter in test output
        try:
            async def run():
                # jitter off → fast against the loopback server
                async with Engine(EngineConfig(concurrency=20, timeout=5, jitter=(0.0, 0.0))) as e:
                    return await scan(e, f"http://127.0.0.1:{port}/",
                                      opts=ScanOptions(max_depth=1, wordlist_paths=[str(wl)],
                                                       bypass403=True, js=False, apidocs=False,
                                                       backups=False, max_folds=0),
                                      observer=quiet, memory=None)
            res = asyncio.run(run())
        finally:
            httpd.shutdown(); httpd.server_close()
            quiet.stream.close()
            os.unlink(wl)

        origins = {f.origin for f in res.findings}
        self.assertIn("methods", origins)          # OPTIONS dangerous-verbs always present
        # the /admin-secret 403 → 200 trailing-slash bypass must reach the report
        byp = [f for f in res.findings if f.origin == "bypass403"]
        self.assertTrue(byp, "403-bypass finding missing from the report")
        self.assertTrue(any(f.url.rstrip("/").endswith("/admin-secret") for f in byp))
        self.assertTrue(any("bypass" in (f.tags or []) for f in byp))

class TestDirRedirect(unittest.TestCase):
    def test_add_slash_is_a_dir(self):
        from origami.core.scanner import _is_self_redirect_dir
        self.assertTrue(_is_self_redirect_dir("/admin/", "/admin"))       # /admin → /admin/ (dir)
        self.assertTrue(_is_self_redirect_dir("http://h/admin/", "/admin"))

    def test_strip_slash_is_not_a_dir(self):
        # /admin/ → /admin (framework slash-canonicalization) is NOT a directory
        from origami.core.scanner import _is_self_redirect_dir, _strips_trailing_slash
        self.assertFalse(_is_self_redirect_dir("/admin", "/admin/"))
        self.assertTrue(_strips_trailing_slash("/admin", "/admin/"))
        self.assertFalse(_is_self_redirect_dir("/admin", "/admin"))       # same path, no slash added

    def test_cross_path_redirect_is_not_a_dir(self):
        from origami.core.scanner import _is_self_redirect_dir
        # /login 302 -> /gateway/login must NOT look like a directory self-redirect
        self.assertFalse(_is_self_redirect_dir("/gateway/login", "/login"))
        self.assertFalse(_is_self_redirect_dir("http://h/auth?next=/login", "/login"))

    def test_redirect_kind_dir_vs_self(self):
        from origami.core.baseline import _redirect_kind
        self.assertEqual(_redirect_kind("http://h/admin", "http://h/admin/"), "DIR")   # add slash
        self.assertEqual(_redirect_kind("http://h/cache/", "http://h/cache"), "SELF")  # strip slash
        self.assertEqual(_redirect_kind("http://h/x", "https://h/x"), "SELF")          # scheme
        self.assertTrue(_redirect_kind("http://h/a", "http://h/login").startswith("->"))

class TestExtList(unittest.TestCase):
    def test_normalizes_and_dedups(self):
        from origami.cli import _ext_list
        self.assertEqual(_ext_list(["php,asp"]), [".php", ".asp"])
        self.assertEqual(_ext_list(["php", ".ASP", "php"]), [".php", ".asp"])
        self.assertEqual(_ext_list(["bak, old "]), [".bak", ".old"])
        self.assertEqual(_ext_list(None), [])
        self.assertEqual(_ext_list([""]), [])

class TestExtCandidates(unittest.TestCase):
    def test_base_exts_override_for_ext_only(self):
        from origami.core.scheduler import build_candidates
        # ext_only path: P1 = user exts, P2 base reduced to just the bare word
        cands = {c.path for c in build_candidates(
            [], ["admin"], {".php"}, base_exts=[""])}
        self.assertIn("admin.php", cands)        # P1 user extension
        self.assertIn("admin", cands)            # P2 bare word
        self.assertIn("admin/", cands)           # dir probe always
        self.assertNotIn("admin.txt", cands)     # generic exts suppressed
        self.assertNotIn("admin.html", cands)

    def test_default_base_exts_keep_generics(self):
        from origami.core.scheduler import build_candidates
        cands = {c.path for c in build_candidates([], ["admin"], {".php"})}
        self.assertIn("admin.php", cands)
        self.assertIn("admin.txt", cands)        # default generic set kept
        self.assertIn("admin.html", cands)

class TestOutputRobustness(unittest.TestCase):
    def test_write_outputs_graceful_on_unwritable_path(self):
        # the scan already ran — a bad --out (existing file) must not crash with a
        # traceback / abort remaining targets; it should report cleanly
        import argparse, tempfile, os
        from origami.cli import _write_outputs
        from origami.core.scanner import ScanResult
        from origami.core.evidence import TargetProfile
        r = ScanResult(profile=TargetProfile(host="h", base_url="https://h/"))
        f = tempfile.mktemp()
        with open(f, "w") as fh:
            fh.write("x")                 # --out points at an existing FILE → mkdir fails
        try:
            args = argparse.Namespace(json=None, html=None, out=f, graph=None)
            _write_outputs(args, r, "https://h/", multi=False)   # must not raise
        finally:
            os.unlink(f)

class TestEndpointGraph(unittest.TestCase):
    def _result(self):
        from origami.core.scanner import ScanResult
        from origami.core.evidence import TargetProfile
        from origami.core.response_classifier import Finding
        r = ScanResult(profile=TargetProfile(host="h", base_url="https://h/"))
        r.findings = [Finding("https://h/api/v2/admin/secret", 200, 10, "", 0.9, "js"),
                      Finding("https://h/login", 200, 10, "", 0.9, "wordlist")]
        r.edges = [("/app.js", "/api/v2/admin/secret"),   # machine-only → hidden
                   ("/", "/login"),                        # page link → not hidden
                   ("/robots.txt", "/sitemap-page")]       # published index → not hidden
        return r

    def test_build_and_orphans(self):
        from origami.output import graph
        m = graph.build(self._result())
        self.assertTrue(m.nodes["/api/v2/admin/secret"].hidden)     # only-JS referenced
        self.assertFalse(m.nodes["/login"].hidden)
        self.assertIsNone(m.nodes["/sitemap-page"].status)          # referenced, not confirmed
        self.assertEqual(m.nodes["/login"].status, 200)
        self.assertIn("/api/v2/admin/secret", graph.orphans(m))
        self.assertNotIn("/login", graph.orphans(m))

    def test_to_dot(self):
        from origami.output import graph
        dot = graph.to_dot(graph.build(self._result()))
        self.assertIn("digraph", dot)
        self.assertIn('"/app.js" -> "/api/v2/admin/secret"', dot)

    def test_to_html_self_contained(self):
        from origami.output import graph
        h = graph.to_html(graph.build(self._result()), "h")
        self.assertIn("<svg", h)
        self.assertIn("secret", h)                                  # node label present
        self.assertNotIn('src="http', h)                           # no external assets
        self.assertNotIn("cdn", h.lower())

    def test_cross_host_edge_dropped(self):
        from origami.output import graph
        from origami.core.scanner import ScanResult
        from origami.core.evidence import TargetProfile
        r = ScanResult(profile=TargetProfile(host="h", base_url="https://h/"))
        r.edges = [("/app.js", "https://evil.cdn/x"), ("/app.js", "/local")]
        m = graph.build(r)
        self.assertNotIn("/x", m.nodes)        # external target not collapsed in
        self.assertIn("/local", m.nodes)

    def test_offhost_vhost_finding_excluded(self):
        # an off-host vhost finding (admin.example.com) must NOT collapse onto the
        # root path key and overwrite the real same-host root node
        from origami.output import graph
        from origami.core.scanner import ScanResult
        from origami.core.evidence import TargetProfile
        from origami.core.response_classifier import Finding
        r = ScanResult(profile=TargetProfile(host="example.com", base_url="https://example.com/"))
        r.findings = [Finding("https://example.com/", 200, 10, "text/html", 0.9, "wordlist"),
                      Finding("http://admin.example.com/", 403, 5, "text/html", 0.8, "vhost", tags=["vhost"])]
        m = graph.build(r)
        self.assertEqual(m.nodes["/"].origin, "wordlist")   # real root preserved
        self.assertEqual(m.nodes["/"].status, 200)
        self.assertEqual(len(m.nodes), 1)                   # vhost finding not added

    def test_report_styles_loud_tags(self):
        # the loudest tags must have their own CSS, not fall back to grey
        from origami.output import html_report
        h = html_report.render(self._result())
        for tag in ("secret", "leak", "bypass", "param"):
            self.assertIn(f".tag.{tag}{{", h)

    def test_empty_result_renders(self):
        from origami.output import graph
        from origami.core.scanner import ScanResult
        from origami.core.evidence import TargetProfile
        m = graph.build(ScanResult(profile=TargetProfile(host="h", base_url="https://h/")))
        self.assertIn("<svg", graph.to_html(m, "h"))   # no crash on empty graph
        self.assertIn("digraph", graph.to_dot(m))

    def test_orphan_filter_control(self):
        from origami.output import graph
        h = graph.to_html(graph.build(self._result()), "h")
        self.assertIn('id="oo"', h)                    # "only hidden" toggle
        self.assertIn("only-hidden", h)                # the CSS/JS hook

    def test_report_links_graph_when_hidden_given(self):
        from origami.output import html_report
        r = self._result()
        h = html_report.render(r, n_hidden=3)
        self.assertIn('href="graph.html"', h)
        self.assertIn("3 hidden", h)
        self.assertNotIn('href="graph.html"', html_report.render(r))   # no card without count

    def test_report_sortable_and_summary(self):
        from origami.output import html_report
        h = html_report.render(self._result())
        self.assertIn('data-sort="num"', h)        # clickable sortable headers
        self.assertIn(">status<", h)               # status-code summary card
        self.assertIn("200×2", h)                  # both findings are 200

    def test_report_only_links_http_schemes(self):
        # defense-in-depth: a server-controlled javascript:/data: finding URL
        # must never become a clickable link in the shared HTML report
        from origami.output import html_report
        from origami.core.scanner import ScanResult
        from origami.core.evidence import TargetProfile
        from origami.core.response_classifier import Finding
        r = ScanResult(profile=TargetProfile(host="h", base_url="https://h/"))
        r.findings = [Finding("javascript:alert(1)", 200, 1, "text/html", 0.9, "x"),
                      Finding("https://h/ok", 200, 1, "text/html", 0.9, "x")]
        h = html_report.render(r)
        self.assertNotIn('href="javascript:', h)   # not linked
        self.assertIn('href="https://h/ok"', h)    # real URL still linked

class TestCLIUrlFlag(unittest.TestCase):
    def _run(self, *argv):
        import subprocess, sys
        return subprocess.run([sys.executable, "-m", "origami", *argv],
                              capture_output=True, text=True)

    def test_url_flag_supplies_target(self):
        # -u/--url provide the target, so the "give a URL" check passes and the run
        # fails later on the bad --list path instead → proves the flag was accepted.
        for flag in ("-u", "--url"):
            r = self._run(flag, "https://x/", "-l", "/no/such/file")
            self.assertIn("target list not found", r.stderr)
            self.assertNotIn("give at least one target", r.stderr)

    def test_missing_target_still_errors(self):
        r = self._run("-F")
        self.assertIn("give at least one target", r.stderr)

    def test_ui_imports_and_falls_back_without_rich(self):
        # the "dependency-free fallback" claim: origami.output.ui must import even
        # when rich is absent, and make_observer must degrade to NullObserver.
        import subprocess, sys
        code = ("import sys; sys.modules['rich'] = None;"
                "import origami.output.ui as u;"
                "assert u.HAS_RICH is False, 'HAS_RICH should be False';"
                "assert type(u.make_observer('t', True)).__name__ == 'NullObserver';"
                "print('ok')")
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
        self.assertEqual(r.stdout.strip(), "ok", r.stderr)

    def test_deep_includes_base_wordlist(self):
        # --deep always runs base; -w merges on top (preamble shows "base + big").
        import subprocess, sys
        r = subprocess.run([sys.executable, "-m", "origami", "--deep", "-w", "big",
                            "-u", "https://127.0.0.1:9/", "-t", "1", "--no-ui"],
                           capture_output=True, text=True, timeout=30)
        self.assertIn("base + big", r.stdout)

    def test_deep_preset_announced(self):
        # --deep bundles the aggressive folds; the preamble announces them (the
        # dead-port target fails fast at the root fetch, so no real scan runs).
        import subprocess, sys
        r = subprocess.run([sys.executable, "-m", "origami", "--deep",
                            "-u", "https://127.0.0.1:9/", "-t", "1", "--no-ui"],
                           capture_output=True, text=True, timeout=30)
        self.assertIn("deep", r.stdout.lower())

    def test_no_history_disables_history_step(self):
        # --no-history overrides the --wayback/--gau that --deep turns on: the
        # "history :" preamble line is present with --deep, absent with --no-history.
        import subprocess, sys
        base = [sys.executable, "-m", "origami", "-u", "https://127.0.0.1:9/",
                "-t", "1", "--no-ui"]
        with_hist = subprocess.run(base + ["--deep"], capture_output=True, text=True, timeout=30)
        self.assertIn("history  :", with_hist.stdout)
        no_hist = subprocess.run(base + ["--deep", "--no-history"],
                                 capture_output=True, text=True, timeout=30)
        self.assertNotIn("history  :", no_hist.stdout)


if __name__ == "__main__":
    unittest.main()

class TestAuthz(unittest.TestCase):
    @staticmethod
    def _seg(d):
        import base64, json
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()

    def _jwt(self, header, claims):
        return f"{self._seg(header)}.{self._seg(claims)}.sig"

    def test_find_jwts_body_and_headers(self):
        from origami.modules import authz
        tok = self._jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "guest", "exp": 1})
        # in a JSON body
        self.assertIn(tok, authz.find_jwts(f'{{"token":"{tok}"}}'.encode()))
        # in a Set-Cookie header (lowercased key, as the engine stores it)
        self.assertIn(tok, authz.find_jwts(b"", {"set-cookie": f"session={tok}; HttpOnly"}))
        # an unsigned (alg:none) token has an EMPTY third segment — still caught
        none_tok = f"{self._seg({'alg': 'none'})}.{self._seg({'sub': 'admin'})}."
        self.assertIn(none_tok, authz.find_jwts(none_tok.encode()))
        # not-a-jwt is ignored
        self.assertEqual(authz.find_jwts(b"just some text, no token here"), [])

    def test_analyze_jwt_flags_header_weaknesses(self):
        from origami.modules import authz

        def issues(header, claims=None):
            info = authz.analyze_jwt(self._jwt(header, claims or {"sub": "x", "exp": 9}))
            return {t for _, t in info["issues"]}, {s for s, _ in info["issues"]}

        # alg:none → high
        txt, sev = issues({"alg": "none"})
        self.assertTrue(any("alg:none" in t for t in txt))
        self.assertIn("high", sev)
        # kid path traversal → high
        txt, _ = issues({"alg": "HS256", "kid": "../../../dev/null"})
        self.assertTrue(any("path-traversal" in t for t in txt))
        # kid URL injection → high
        txt, _ = issues({"alg": "HS256", "kid": "https://evil.example/k"})
        self.assertTrue(any("URL-injection" in t for t in txt))
        # jku / x5u remote key → high (SSRF)
        txt, _ = issues({"alg": "RS256", "jku": "https://evil/jwks.json"})
        self.assertTrue(any("jku" in t and "SSRF" in t for t in txt))
        txt, _ = issues({"alg": "RS256", "x5u": "https://evil/c.pem"})
        self.assertTrue(any("x5u" in t for t in txt))
        # x5c embedded cert → med
        _, sev = issues({"alg": "RS256", "x5c": ["MIID..."]})
        self.assertIn("med", sev)

    def test_analyze_jwt_claims(self):
        from origami.modules import authz
        # missing exp → low; privilege claim captured
        info = authz.analyze_jwt(self._jwt({"alg": "HS256"}, {"sub": "u", "role": "admin"}))
        self.assertTrue(any("no exp" in t for _, t in info["issues"]))
        self.assertEqual(info["sensitive"], {"role": "admin"})
        self.assertEqual(info["sub"], "u")
        # a clean HS256 token with exp and no privilege claim → no issues
        clean = authz.analyze_jwt(self._jwt({"alg": "HS256"}, {"sub": "u", "exp": 9}))
        self.assertEqual(clean["issues"], [])
        self.assertEqual(clean["sensitive"], {})
        # garbage → empty dict
        self.assertEqual(authz.analyze_jwt("not.a.jwt"), {})

    def test_find_oauth_issues(self):
        from origami.modules import authz
        base = ("https://h/authorize?client_id=abc&response_type=code"
                "&redirect_uri=https%3A%2F%2Fh%2Fcb")
        # missing state AND no PKCE
        r = authz.find_oauth_issues(f'<a href="{base}&scope=openid">go</a>'.encode())
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0]["client_id"], "abc")
        self.assertTrue(any("missing state" in i for i in r[0]["issues"]))
        self.assertTrue(any("no PKCE" in i for i in r[0]["issues"]))
        # PKCE plain downgrade flagged; state present → no CSRF issue
        r2 = authz.find_oauth_issues(
            (base + "&state=xyz&code_challenge=q&code_challenge_method=plain").encode())
        self.assertTrue(any("plain" in i for i in r2[0]["issues"]))
        self.assertFalse(any("state" in i for i in r2[0]["issues"]))
        # a proper flow (state + S256) → no issues
        r3 = authz.find_oauth_issues(
            (base + "&state=xyz&code_challenge=q&code_challenge_method=S256").encode())
        self.assertEqual(r3[0]["issues"], [])
        # a non-OAuth URL is ignored
        self.assertEqual(authz.find_oauth_issues(b"https://h/page?client_id=only"), [])
        # HTML-encoded `&amp;` separators must parse — else a flow WITH state+S256
        # would false-flag "missing state"/"no PKCE"
        amp = (b'<a href="https://h/authorize?client_id=abc&amp;response_type=code'
               b'&amp;state=s&amp;code_challenge=c&amp;code_challenge_method=S256">')
        r4 = authz.find_oauth_issues(amp)
        self.assertEqual(r4[0]["issues"], [])          # no false positive

    def test_authz_candidate_predicate(self):
        from origami.core.scanner import _authz_candidate
        from origami.core.response_classifier import Finding
        def f(url, status=200, ct="application/json", tags=None):
            return Finding(url, status, 100, ct, 0.9, "wordlist", tags=tags or [])
        # auth walls always qualify (token cookie / WWW-Authenticate lives here)
        self.assertTrue(_authz_candidate(f("https://h/x", 403)))
        self.assertTrue(_authz_candidate(f("https://h/x", 401)))
        # a generic 2xx JSON page (no auth signal) does NOT — avoid re-fetching content
        self.assertFalse(_authz_candidate(f("https://h/api/products", 200)))
        # 2xx qualifies on an auth-ish path or tag
        self.assertTrue(_authz_candidate(f("https://h/oauth/login", 200, "text/html")))
        self.assertTrue(_authz_candidate(f("https://h/api/token", 200)))
        self.assertTrue(_authz_candidate(f("https://h/x", 200, tags=["auth"])))
        # static assets never qualify
        self.assertFalse(_authz_candidate(f("https://h/app.js", 200, "application/javascript")))

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

    def test_extract_paths_with_query_in_quotes(self):
        # a URL the JS builds by concatenation: '/x/edit.aspx?id=' + n — the quoted
        # literal carries a `?query`, which used to make the path-matcher miss it
        # entirely (exactly the parameterised endpoints we most want).
        base = "https://t/scripts.js"
        js = (b".open('/account/licensemanager/editors/storelocater.aspx?license_key=' + k);"
              b"var u='/account/agreements/agreement.aspx?id='+id;"
              b"go('/account/tools/finder.aspx');")            # no-query still works
        paths = js_parser.extract_paths(js, base)
        self.assertIn("/account/licensemanager/editors/storelocater.aspx", paths)  # query stripped
        self.assertIn("/account/agreements/agreement.aspx", paths)
        self.assertIn("/account/tools/finder.aspx", paths)
        self.assertFalse(any("?" in p or "=" in p for p in paths))   # query never leaks into a path
        # the param names are still harvested separately
        self.assertEqual(js_parser.extract_params(js) & {"license_key", "id"}, {"license_key", "id"})

    def test_multiviews_negotiation(self):
        from origami.modules.discovery import negotiation
        body = (b'<html><head><title>300 Multiple Choices</title></head><body>'
                b'<h1>Multiple Choices</h1>The document name you requested (<code>/composer</code>)'
                b' could not be found. However, we found documents with names similar.'
                b'<p>Available documents:<ul>'
                b'<li><a href="/composer.json">/composer.json</a> (common basename)'
                b'<li><a href="/composer.lock">/composer.lock</a> (common basename)'
                b'</ul></body></html>')
        self.assertTrue(negotiation.is_multiple_choices(body))
        self.assertEqual(negotiation.parse_choices(body, "https://h/composer"),
                         {"/composer.json", "/composer.lock"})
        # a normal 404 body is not MultiViews
        self.assertFalse(negotiation.is_multiple_choices(b"<html><h1>404 Not Found</h1></html>"))
        # off-host choices and directory links are dropped
        off = (b'<title>Multiple Choices</title>Available documents:'
               b'<a href="https://evil.com/x.php">x</a><a href="/real.php">r</a>'
               b'<a href="/sub/">dir</a>')
        self.assertEqual(negotiation.parse_choices(off, "https://h/y"), {"/real.php"})
        # THE FP GUARD: Apache's "common basename" traversal noise (/./x, /../x, /.,
        # /..) returned for ANY unresolvable name is NOT a real document → dropped,
        # so a MultiViews host doesn't flood every probed dotfile as a phantom leak
        noise = (b'<title>Multiple Choices</title>Available documents:'
                 b'<a href="/./config">a</a><a href="/../config">b</a>'
                 b'<a href="/.">c</a><a href="/..">d</a>')
        self.assertEqual(negotiation.parse_choices(noise, "https://h/.git/config"), set())

    def test_protocol_relative_offhost_dropped(self):
        # regression: //evil.com/x must NOT pass as a same-host root-absolute path
        # (it would leak an off-host endpoint into the --graph edges)
        base = "https://target.com/"
        self.assertEqual(js_parser.extract_paths(b'fetch("//evil.com/api/steal")', base), set())
        self.assertIn("/api/ok", js_parser.extract_paths(b'fetch("/api/ok")', base))
        # same applies to header-derived paths (CSP/Link)
        hp = js_parser.extract_header_paths({"link": "<//evil.com/x>; rel=preload"}, base)
        self.assertNotIn("//evil.com/x", hp)
        self.assertFalse(any(p.startswith("//") for p in hp))

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

    def test_expand_resolved_names_fire_before_wordlist_guesses(self):
        # A late entry's *resolved* fullname must outrank an early entry's
        # speculative wordlist expansions — under a WAF the tail gets cut, so the
        # sure things have to go first. Here DEFAULT.ASPX (2nd entry, resolved)
        # must precede ADMINI's wordlist guess "administrators.aspx".
        sample = (
            '{"type":"status","url":"http://t/","vulnerable":true}\n'
            '{"type":"file","baseurl":"http://t/","shorttilde":"ADMINI~1",'
            '"shortfile":"ADMINI","shortext":"ASP"}\n'
            '{"type":"file","baseurl":"http://t/","shorttilde":"DEFAUL~1",'
            '"shortfile":"DEFAUL","shortext":"ASP","fullname":"default.aspx"}\n'
        )
        r = shortname.parse_ndjson(sample)
        order = [p for _, p in shortname.expand(r.entries, ["administrators"])]
        self.assertLess(order.index("default.aspx"), order.index("administrators.aspx"))

    def test_expand_raw_83_name_not_prefix_doubled(self):
        # The raw 8.3 candidate is the tilde name itself ("WEBREF~1.CON"), not
        # prefix+tilde ("WEBREFWEBREF~1.CON") — the latter is a guaranteed 404.
        r = shortname.parse_ndjson(
            '{"type":"status","vulnerable":true}\n'
            '{"type":"file","baseurl":"http://t/","shorttilde":"WEBREF~1",'
            '"shortfile":"WEBREF","shortext":"CON"}\n')
        paths = {p for _, p in shortname.expand(r.entries, [])}
        self.assertIn("WEBREF~1.CON", paths)
        self.assertNotIn("WEBREFWEBREF~1.CON", paths)

    def test_expand_case_insensitive_collapses_variants(self):
        # IIS host: the resolved fullname (WEBSERVICES), the lowercased prefix
        # (webservices) and a mixed-case wordlist match (WebServices) are one
        # resource — collapse to a single candidate when case_insensitive=True.
        r = shortname.parse_ndjson(
            '{"type":"status","vulnerable":true}\n'
            '{"type":"file","baseurl":"http://t/","shorttilde":"WEBSER~1",'
            '"shortfile":"WEBSER","shortext":"","fullname":"WEBSERVICES"}\n')
        words = ["WebServices"]
        ci = [p for _, p in shortname.expand(r.entries, words, case_insensitive=True)]
        self.assertEqual(sum(1 for p in ci if p.lower() == "webservices"), 1)
        cs = [p for _, p in shortname.expand(r.entries, words, case_insensitive=False)]
        self.assertGreater(sum(1 for p in cs if p.lower() == "webservices"), 1)

    def test_parse_ndjson_survives_malformed_lines(self):
        # shortscan output is untrusted: a line with null/number/list fields must
        # not crash the parser or expand() and forfeit the whole fold
        from origami.modules.discovery import shortname
        r = shortname.parse_ndjson(
            '{"shortfile":null,"shorttilde":"ADMIN~1"}\n'
            '{"shortfile":123}\n'
            '{"shortext":["x"],"shortfile":"web"}\n'
            '{"shorttilde":456}\n'
            '{"shortfile":"admini","shortext":"asp","shorttilde":"ADMINI~1"}\n'  # 1 valid
            'not json\n{truncated\n')
        self.assertEqual(len(r.entries), 5)               # all parsed, none crashed
        # every coerced field is a str → expand() can't blow up on .lower()/.upper()
        self.assertTrue(all(isinstance(e.prefix, str) and isinstance(e.ext, str)
                            and isinstance(e.tilde, str) for e in r.entries))
        shortname.expand(r.entries, [], case_insensitive=True)   # must not raise

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

    def test_backup_fold_drops_catchall_echo(self):
        # a route that serves the SAME body for any suffix (swagger.json.bak ==
        # swagger.json) must NOT be reported as a backup disclosure.
        import asyncio
        from urllib.parse import urlparse
        from origami.core.scanner import _backup_fold, ScanResult, ScanOptions
        from origami.core.evidence import TargetProfile, ContextBaseline
        from origami.core.response_classifier import Finding
        from origami.output.ui import NullObserver

        original = b'{"swagger":"2.0","paths":{"/a":{}}}'
        class FakeEngine:
            spent = 0
            async def fetch(self, url, method="GET", keep_body=False, **kw):
                if "swagger" in urlparse(url).path:          # catch-all echo
                    return make_probe(200, original, url=url, ctype="application/json")
                return make_probe(404, b"not found", url=url)

        p = TargetProfile(host="h", base_url="http://h/")
        cb = ContextBaseline(prefix="/api/", ext_class="none", status=404,
                             simhashes=[simhash(b"not found")], content_type="text/html")
        p.baseline[TargetProfile.context_key("/api/", "none")] = cb
        result = ScanResult(profile=p)
        result.findings.append(Finding("http://h/api/swagger.json", 200, len(original),
                                       "application/json", 0.95, "memory", simhash=simhash(original)))
        import asyncio as _a
        _a.run(_backup_fold(FakeEngine(), p, result, ScanOptions(), NullObserver()))
        self.assertEqual([f for f in result.findings if f.origin == "backup"], [])

    def test_backup_fold_keeps_distinct_backup(self):
        # a real backup whose body DIFFERS from the original IS reported.
        import asyncio
        from urllib.parse import urlparse
        from origami.core.scanner import _backup_fold, ScanResult, ScanOptions
        from origami.core.evidence import TargetProfile, ContextBaseline
        from origami.core.response_classifier import Finding
        from origami.output.ui import NullObserver

        original = b'<?php $x = render(); ?>'
        source = b'<?php $db_password = "s3cr3t"; $x = render(); ?>'   # the leaked source
        class FakeEngine:
            spent = 0
            async def fetch(self, url, method="GET", keep_body=False, **kw):
                if urlparse(url).path.endswith(".php.bak"):
                    return make_probe(200, source, url=url, ctype="text/plain")
                return make_probe(404, b"not found", url=url)

        p = TargetProfile(host="h", base_url="http://h/")
        cb = ContextBaseline(prefix="/", ext_class="none", status=404,
                             simhashes=[simhash(b"not found")], content_type="text/html")
        p.baseline[TargetProfile.context_key("/", "none")] = cb
        result = ScanResult(profile=p)
        result.findings.append(Finding("http://h/app.php", 200, len(original),
                                       "text/html", 0.95, "wordlist", simhash=simhash(original)))
        asyncio.run(_backup_fold(FakeEngine(), p, result, ScanOptions(), NullObserver()))
        self.assertTrue(any(f.origin == "backup" and f.url.endswith(".php.bak")
                            for f in result.findings))

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

class TestJsonlStream(unittest.TestCase):
    def test_finding_record_shape(self):
        from origami.output.json_report import finding_record
        from origami.core.response_classifier import Finding
        r = finding_record(Finding("https://h/a", 200, 12, "application/json",
                                   0.953, "js", tags=["api"]), host="h")
        self.assertEqual(r["url"], "https://h/a")
        self.assertEqual(r["status"], 200)
        self.assertEqual(r["confidence"], 0.95)        # rounded
        self.assertEqual(r["tags"], ["api"])
        self.assertEqual(r["host"], "h")

    def test_finding_sink_called_per_reported_finding(self):
        from origami.core.scanner import _report, ScanResult, ScanOptions
        from origami.core.evidence import TargetProfile
        from origami.output.ui import NullObserver
        streamed = []
        opts = ScanOptions(finding_sink=streamed.append)
        r = ScanResult(profile=TargetProfile(host="h", base_url="https://h/"))
        _report(NullObserver(), r, opts, make_finding("https://h/a"), "https://h/a")
        _report(NullObserver(), r, opts, make_finding("https://h/a"), "https://h/a")  # dup
        _report(NullObserver(), r, opts, make_finding("https://h/b"), "https://h/b")
        self.assertEqual([f.url for f in streamed], ["https://h/a", "https://h/b"])  # dup not streamed

    def test_identical_slash_twin_suppressed_live(self):
        from origami.core.scanner import _report, ScanResult, ScanOptions
        from origami.core.evidence import TargetProfile
        from origami.core.response_classifier import Finding
        from origami.output.ui import NullObserver
        # /x and /x/ with an identical response → only ONE streams (the report-time
        # collapse would fold them, but the live stream must not show both)
        streamed = []
        opts = ScanOptions(finding_sink=streamed.append)
        r = ScanResult(profile=TargetProfile(host="h", base_url="https://h/"))
        _report(NullObserver(), r, opts, make_finding("https://h/x"), "https://h/x")
        _report(NullObserver(), r, opts, make_finding("https://h/x/"), "https://h/x/")
        self.assertEqual([f.url for f in streamed], ["https://h/x"])
        self.assertEqual(len(r.findings), 1)                       # twin not even stored
        # a twin with a DIFFERENT response (different length) still shows both
        streamed2 = []
        opts2 = ScanOptions(finding_sink=streamed2.append)
        r2 = ScanResult(profile=TargetProfile(host="h", base_url="https://h/"))
        _report(NullObserver(), r2, opts2,
                Finding("https://h/y", 200, 10, "text/html", 0.9, "wordlist"), "https://h/y")
        _report(NullObserver(), r2, opts2,
                Finding("https://h/y/", 200, 999, "text/html", 0.9, "wordlist"), "https://h/y/")
        self.assertEqual([f.url for f in streamed2], ["https://h/y", "https://h/y/"])


if __name__ == "__main__":
    unittest.main()

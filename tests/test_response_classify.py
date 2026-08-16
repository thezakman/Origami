"""Origami unit tests — response classification, filtering, tagging, dir-listing, error pages.

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



class TestSimhash(unittest.TestCase):
    def test_identical_zero_distance(self):
        b = b"<html><body>welcome to the portal</body></html>"
        self.assertEqual(hamming(simhash(b), simhash(b)), 0)

    def test_simhash_golden_values_stable(self):
        # Locks the exact 64-bit output: simhashes are stored in the memory DB
        # (--diff, corpus k-NN), so any optimization MUST stay byte-identical or
        # cross-run comparison silently breaks. Values predate the fast rewrite.
        golden = {
            b"": 0xe4a6a0577479b2b4,
            b"<html>hi</html>": 0x106bce4401410416,
            b"<html><body><h1>Welcome</h1><p>portal home page</p></body></html>": 0x628292d559e4000a,
            b'{"status":"running","version":"1.2.2","name":"svc"}': 0x115203b7674b6b87,
            b"<ul>" + b"<li class='x'>item produto preco</li>" * 40 + b"</ul>": 0xa95b253eb8ce514b,
        }
        for body, expected in golden.items():
            self.assertEqual(simhash(body), expected, f"simhash drifted for {body[:32]!r}")

    def test_dynamic_noise_ignored(self):
        # same page, different CSRF token / timestamp each render
        a = b"<html><body>Not Found <!-- csrf=deadbeefdeadbeef 1700000000 --></body></html>"
        b = b"<html><body>Not Found <!-- csrf=cafebabecafebabe 1700009999 --></body></html>"
        self.assertLessEqual(hamming(simhash(a), simhash(b)), 3)

    def test_structurally_different_far(self):
        a = b"<html><body>login form username password submit</body></html>"
        b = b"<html><body>welcome dashboard reports settings logout</body></html>"
        self.assertGreater(hamming(simhash(a), simhash(b)), 3)

    def test_normalize_no_redos_on_unclosed_tags(self):
        # regression: the tag-strip regex must stay linear — a body with a long run
        # of unclosed '<' was O(n^2) (300KB → ~17s), hanging the scan (simhash runs
        # on every response body)
        import time
        t0 = time.time()
        simhash(b"a<" * 150_000)          # ~300 KB of unclosed '<'
        self.assertLess(time.time() - t0, 2.0)   # was ~17s pre-fix

    def test_volatile_comment_with_inner_gt_dropped(self):
        # A comment carrying a literal '>' (IE-conditional, "a > b") must be
        # dropped WHOLE — the generic <[^>]+> tag rule alone would truncate at
        # the inner '>', leaking the volatile tail into the structural hash.
        a = b"<html><body><h1>App</h1><!-- build 12345 > rev aaaaaa --></body></html>"
        b = b"<html><body><h1>App</h1><!-- build 99999 > rev zzzzzz --></body></html>"
        self.assertEqual(hamming(simhash(a), simhash(b)), 0)
        c = b"<!--[if lt IE 9]><script src=x.js?v=111></script><![endif]--><h1>Home</h1>"
        d = b"<!--[if lt IE 9]><script src=x.js?v=222></script><![endif]--><h1>Home</h1>"
        self.assertEqual(hamming(simhash(c), simhash(d)), 0)

class TestClassify(unittest.TestCase):
    def _profile_with_baseline(self, miss_body=b"<html>not found</html>", status=404, samples=4):
        p = TargetProfile(host="t", base_url="http://t/")
        cb = ContextBaseline(prefix="/", ext_class="none", status=status, samples=samples,
                             simhashes=[simhash(miss_body)], content_type="text/html")
        p.baseline[TargetProfile.context_key("/", "none")] = cb
        return p

    def test_real_hit_high_confidence_with_valid_baseline(self):
        # a calibrated baseline (samples>0) → a differing 200 is a confident hit
        p = self._profile_with_baseline(status=404, samples=4)
        f = classify(p, make_probe(status=200, body=b"<html>real dashboard</html>",
                                   url="http://t/admin"), "wordlist", "/")
        self.assertEqual(f.confidence, 0.95)

    def test_failed_calibration_is_cautious_not_a_flood(self):
        # samples==0 = calibration probes all failed → must NOT pass every 200 as a
        # 0.95 hit (the soft-404 flood); fall back to the cautious no-baseline path
        p = self._profile_with_baseline(status=404, samples=0)
        f = classify(p, make_probe(status=200, body=b"<html>anything</html>",
                                   url="http://t/whatever"), "wordlist", "/")
        self.assertEqual(f.confidence, 0.5)
        self.assertEqual(f.note, "no-baseline")

    def test_empty_body_2xx_demoted_no_disclosure(self):
        # a 0-byte `.old` leaked nothing → drop the disclosure tag + low confidence,
        # so it never reads as `200 0B disclosure 0.95`. A non-empty one is untouched.
        p = self._profile_with_baseline(status=404, samples=4)
        empty = classify(p, make_probe(status=200, body=b"", url="http://t/backup.old"),
                         "wordlist", "/")
        self.assertLessEqual(empty.confidence, 0.4)
        self.assertNotIn("disclosure", empty.tags)
        self.assertIn("empty body", empty.note)
        full = classify(p, make_probe(status=200, body=b"SELECT * FROM users; secret dump",
                                      url="http://t/backup.old"), "wordlist", "/")
        self.assertIn("disclosure", full.tags)             # real content → still flagged
        self.assertGreater(full.confidence, 0.4)

    def test_generalize_location_whole_token_only(self):
        # a short request token must not blank unrelated substrings of the redirect
        from origami.core.baseline import _generalize_location as g
        self.assertEqual(g("http://x/a", "http://x/path/a/area"), "http://x/path/*/area")
        # the calibration random token is still blanked wherever it stands alone
        self.assertEqual(g("http://x/tok123", "http://x/err?from=tok123"), "http://x/err?from=*")

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

    def test_strip_slash_redirect_never_a_finding(self):
        # the make.com case: a blanket 308 /x/ → /x (framework slash-canonicalization)
        # must not be reported — it's not a discovered resource
        from origami.core.evidence import TargetProfile
        p = TargetProfile(host="t", base_url="https://t/")
        for st in (301, 302, 308):
            probe = make_probe(status=st, body=b"", url="https://t/authenticate/composer/",
                               location="/authenticate/composer")
            self.assertIsNone(classify(p, probe, "wordlist", "/"), f"{st} strip-slash leaked")

    def test_add_slash_redirect_confirms_directory(self):
        from origami.core.evidence import TargetProfile
        p = TargetProfile(host="t", base_url="https://t/")
        probe = make_probe(status=301, body=b"", url="https://t/admin", location="/admin/")
        f = classify(p, probe, "wordlist", "/")
        self.assertIsNotNone(f)                 # /admin → /admin/ confirms a directory
        self.assertEqual(f.status, 301)

    def test_dir_redirect_survives_redirect_soft404_baseline(self):
        # Regression: on a host whose MISSES are 3xx (a constant-target catch-all
        # 301 → /home, or a slash-canonicalizing framework), a real directory
        # `/admin → /admin/` (also 301, DIR) must still be a hit. Both redirect
        # bodies are empty boilerplate, so their simhash matches — the miss-body
        # fallback in looks_like_miss would otherwise mask the DIR redirect and
        # suppress the directory. The DIR redirect kind wins over the body match.
        p = TargetProfile(host="t", base_url="http://t/")
        cb = ContextBaseline(prefix="/", ext_class="none", status=301, samples=4,
                             simhashes=[simhash(b"")], content_type="",
                             redirect_to="->/home", is_soft404=True)
        p.baseline[TargetProfile.context_key("/", "none")] = cb
        probe = make_probe(status=301, body=b"", url="http://t/admin", location="/admin/")
        f = classify(p, probe, "wordlist", "/")
        self.assertIsNotNone(f, "a real /admin → /admin/ directory was suppressed as a miss")
        self.assertEqual(f.status, 301)
        # a genuine miss on this host (same constant-target 301) stays suppressed
        miss = make_probe(status=301, body=b"", url="http://t/rand987", location="/home")
        self.assertIsNone(classify(p, miss, "wordlist", "/"))

class TestDirListing(unittest.TestCase):
    APACHE = (b'<html><head><title>Index of /images</title></head><body>'
              b'<h1>Index of /images</h1><pre><a href="?C=N;O=D">Name</a><hr>'
              b'<a href="../">Parent Directory</a><a href="logo.png">logo.png</a>'
              b'<a href="backup.zip">backup.zip</a><a href="thumbs/">thumbs/</a></pre></body></html>')

    def test_detects_autoindex_flavours(self):
        from origami.core.response_classifier import is_dir_listing
        self.assertTrue(is_dir_listing(self.APACHE))
        self.assertTrue(is_dir_listing(b'<title>Index of /css/</title>'))
        self.assertTrue(is_dir_listing(b'<pre>[To Parent Directory]</pre>'))     # IIS
        self.assertTrue(is_dir_listing(b'<h1>Directory Listing For /scripts/</h1>'))  # tomcat
        self.assertFalse(is_dir_listing(b'<html><title>Welcome</title><h1>Home</h1></html>'))

    def test_parse_listing_resolves_entries(self):
        from origami.modules.discovery.js_parser import parse_listing
        entries = parse_listing(self.APACHE, "https://h/images/")
        self.assertEqual(entries, {"/images/logo.png", "/images/backup.zip", "/images/thumbs/"})
        self.assertNotIn("/images/", entries)          # parent/self dropped
        self.assertFalse(any("?" in e for e in entries))  # sort links dropped

    def test_classify_tags_listing(self):
        from origami.core.response_classifier import classify
        p = TargetProfile(host="h", base_url="http://h/")
        cb = ContextBaseline(prefix="/", ext_class="none", status=404,
                             simhashes=[simhash(b"not found")], content_type="text/html")
        p.baseline[TargetProfile.context_key("/", "none")] = cb
        probe = make_probe(200, self.APACHE, url="http://h/images/")
        f = classify(p, probe, "wordlist", "/")
        self.assertIsNotNone(f)
        self.assertIn("listing", f.tags)

    def test_scan_prefix_marks_autoindex_dir(self):
        # a confirmed dir whose body is a listing lands in listed_dirs, so the
        # walk skips the blind wordlist for it.
        import asyncio
        from origami.core.scanner import _scan_prefix, ScanResult, ScanOptions, ScanControl
        from origami.core.evidence import TargetProfile, ContextBaseline
        from origami.core.scheduler import Candidate
        from origami.output.ui import NullObserver
        listing = self.APACHE
        class FakeEngine:
            cfg = type("C", (), {"verify_tls": False})()
            total_requests = 0
            async def fetch(self, url, method="GET", keep_body=False, headers=None):
                FakeEngine.total_requests += 1
                from urllib.parse import urlparse
                if urlparse(url).path == "/images/":
                    return make_probe(200, listing, url=url, ctype="text/html")
                return make_probe(404, b"not found", url=url)
            async def gather(self, urls, method="GET"):
                return [await self.fetch(u) for u in urls]
        p = TargetProfile(host="h", base_url="http://h/")
        cb = ContextBaseline(prefix="/", ext_class="none", status=404,
                             simhashes=[simhash(b"not found")], content_type="text/html")
        p.baseline[TargetProfile.context_key("/", "none")] = cb
        result = ScanResult(profile=p)
        listed = set()
        asyncio.run(_scan_prefix(FakeEngine(), p, "/", [Candidate("images/", 2, "wordlist")],
                                 result, ScanOptions(), NullObserver(), ScanControl(),
                                 listed_dirs=listed))
        self.assertIn("/images/", listed)

    def test_scan_prefix_multiviews_notice_validate_dedup(self):
        # MultiViews: flag the misconfig ONCE (not per-300), validate each disclosed
        # file inline exactly once (dedup across extension variants), never report the
        # per-request 300s (a MultiViews host 300s every /x.bak /x.inc … → one real
        # file, which would flood), and drop traversal-only noise.
        import asyncio
        from origami.core.scanner import _scan_prefix, ScanResult, ScanOptions, ScanControl
        from origami.core.evidence import TargetProfile, ContextBaseline
        from origami.core.scheduler import Candidate
        from origami.output.ui import NullObserver
        MV = (b'<title>300 Multiple Choices</title>Available documents:'
              b'<a href="/script.php">x</a>')                 # every /script.* → /script.php
        NOISE = (b'<title>300 Multiple Choices</title>Available documents:'
                 b'<a href="/./env">a</a><a href="/../env">b</a>')

        class FakeEngine:
            cfg = type("C", (), {"verify_tls": False})()
            total_requests = 0
            fetched = []
            async def fetch(self, url, method="GET", keep_body=False, headers=None):
                FakeEngine.total_requests += 1
                FakeEngine.fetched.append(url)
                from urllib.parse import urlparse
                p = urlparse(url).path
                if p in ("/script.bak", "/script.inc"):
                    return make_probe(300, MV, url=url, ctype="text/html")
                if p == "/.env":
                    return make_probe(300, NOISE, url=url, ctype="text/html")
                if p == "/script.php":
                    return make_probe(200, b'echo("hi");', url=url, ctype="text/plain")
                return make_probe(404, b"not found", url=url)
            async def gather(self, urls, method="GET"):
                return [await self.fetch(u) for u in urls]

        p = TargetProfile(host="h", base_url="http://h/")
        cb = ContextBaseline(prefix="/", ext_class="none", status=404,
                             simhashes=[simhash(b"not found")], content_type="text/html")
        p.baseline[TargetProfile.context_key("/", "none")] = cb
        result = ScanResult(profile=p)
        asyncio.run(_scan_prefix(
            FakeEngine(), p, "/",
            [Candidate("script.bak", 2, "wordlist"), Candidate("script.inc", 2, "wordlist"),
             Candidate(".env", 2, "backup")],
            result, ScanOptions(), NullObserver(), ScanControl()))
        negs = [f for f in result.findings if f.origin == "negotiation"]
        # exactly ONE "MultiViews ENABLED" misconfig notice — not one per probed 300
        notices = [f for f in negs if "ENABLED" in (f.note or "")]
        self.assertEqual(len(notices), 1)
        # the disclosed /script.php validated inline exactly once (dedup across variants)
        self.assertIn("http://h/script.php", {f.url for f in result.findings})
        self.assertEqual(FakeEngine.fetched.count("http://h/script.php"), 1)
        # the SECOND variant (/script.inc) adds no finding (dedup — no per-300 flood),
        # and traversal-only noise is dropped
        self.assertNotIn("http://h/script.inc", {f.url for f in result.findings})
        self.assertNotIn("http://h/.env", {f.url for f in result.findings})
        # total negotiation findings = 1 notice + 1 validated file (not one per variant)
        self.assertEqual(len(negs), 2)

class TestErrorPageFingerprint(unittest.TestCase):
    def _fp(self, body):
        from origami.core.fingerprint import apply_error_signals
        from origami.core.evidence import TargetProfile
        p = TargetProfile(host="h", base_url="http://h/")
        apply_error_signals(p, [make_probe(status=404, body=body)])
        return p

    def test_detects_stack_header_independent(self):
        self.assertGreaterEqual(self._fp(b"<html>Whitelabel Error Page</html>")
                                .tech_scores.get("springboot", 0), 50)
        self.assertGreaterEqual(self._fp(b"Cannot GET /aaaa.aspx")
                                .tech_scores.get("express", 0), 50)
        self.assertGreaterEqual(self._fp(b"<hr><center>nginx</center></body>")
                                .tech_scores.get("nginx", 0), 50)
        self.assertGreaterEqual(self._fp(b"Server Error in '/' Application.")
                                .tech_scores.get("aspnet", 0), 50)

    def test_no_false_positive_on_content(self):
        # the bare word in page CONTENT must not fingerprint — we require the
        # specific default-error string.
        p = self._fp(b"<html>welcome to our nginx hosting + django tutorial blog</html>")
        self.assertEqual(p.tech_scores.get("nginx", 0), 0)
        self.assertEqual(p.tech_scores.get("django", 0), 0)

    def test_springboot_error_folds_actuator(self):
        from origami.brain.kb import load_kb
        from origami.core.fingerprint import confirmed_actions
        p = self._fp(b"<html><body>Whitelabel Error Page</body></html>")
        _, paths, _ = confirmed_actions(p, load_kb())
        self.assertTrue(any("actuator" in x for x in paths))

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

class TestTagging(unittest.TestCase):
    def tags(self, path, status=200):
        from origami.core.response_classifier import tag_finding
        return tag_finding("https://h" + path, status)

    def test_auth_english_and_ptbr_concatenated(self):
        self.assertIn("auth", self.tags("/security/views/login.tpl.html"))
        self.assertIn("auth", self.tags("/redefinirsenha/views/redefinir.tpl.html"))
        self.assertIn("auth", self.tags("/security/views/esqueciminhasenha.tpl.html"))
        self.assertIn("auth", self.tags("/conta/cadastro"))

    def test_401_forces_auth(self):
        self.assertIn("auth", self.tags("/whatever", status=401))

    def test_hyphen_needle_does_not_fire_midword(self):
        # regression: 'sign-in' must not match inside 'design-inovador' (the
        # product-page false positive); a real /sign-in path still tags auth
        self.assertNotIn("auth", self.tags(
            "/puff-zion-sensorial-com-seu-design-inovador-e-multifuncional"))
        self.assertNotIn("auth", self.tags("/puffs"))
        self.assertIn("auth", self.tags("/user/sign-in"))
        self.assertIn("auth", self.tags("/account/sign-in/"))

    def test_dashboard_is_not_admin(self):
        # a user dashboard view must NOT be tagged admin (the over-broad bug)
        self.assertNotIn("admin", self.tags("/aprendizagem/views/dashboard.tpl.html"))
        self.assertIn("admin", self.tags("/admin/users"))
        self.assertIn("admin", self.tags("/administrador/painel"))   # PT admin

    def test_extension_needles_are_precise(self):
        # .cs tags C# source but NOT a .css stylesheet (the substring bug)
        self.assertIn("source", self.tags("/app/Program.cs"))
        self.assertNotIn("source", self.tags("/assets/style.css"))

    def test_disclosure_segments_and_exts(self):
        self.assertIn("disclosure", self.tags("/.git/HEAD"))
        self.assertIn("disclosure", self.tags("/backup/db.sql"))
        self.assertIn("disclosure", self.tags("/conf/id_rsa"))
        # 'secretaria' must not trip a disclosure (bare 'secret' was removed)
        self.assertNotIn("disclosure", self.tags("/secretaria/alunos"))

    def test_new_categories(self):
        self.assertIn("upload", self.tags("/files/upload.aspx"))
        self.assertIn("debug", self.tags("/actuator/health"))
        self.assertIn("api", self.tags("/api/v3/users"))
        self.assertIn("config", self.tags("/app/web.config"))

class TestUrlRobustness(unittest.TestCase):
    """A wordlist/payload candidate whose path contains `://` (a Struts2 OGNL
    `${...http://x...}`) must not be mistaken for an absolute URL and must never
    crash the scan — the bug that killed a 10-minute run at request 1523."""

    def test_join_candidate_payload_with_internal_scheme(self):
        from origami.core.scanner import _join_candidate
        root = "https://h/"
        payload = "${(x)://(y)}"
        u = _join_candidate(root, "lms/", payload)
        self.assertTrue(u.startswith("https://h/lms/"))   # absolute, under prefix
        self.assertEqual(_join_candidate(root, "/", "https://cdn/x"), "https://cdn/x")
        self.assertEqual(_join_candidate(root, "deep/", "/admin"), "https://h/admin")

    def test_scope_keeps_payload_relative(self):
        from origami.core.scanner import _scope_paths
        self.assertIn("/${(x)://(y)}", _scope_paths(["/${(x)://(y)}"], "h", "host"))
        # a real CDN absolute URL is still dropped in host scope
        self.assertNotIn("https://cdn/x", _scope_paths(["https://cdn/x"], "h", "host"))

    def test_word_of_payload_no_crash(self):
        from origami.brain.bandit import word_of
        self.assertIsInstance(word_of("${(x)://(y)}.aspx"), str)

    def test_fetch_survives_malformed_url(self):
        import asyncio
        from origami.core.httpclient import Engine, EngineConfig

        async def go():
            async with Engine(EngineConfig(max_retries=0)) as e:
                return await e.fetch("${(x)://(y)}")      # never raises → error probe

        p = asyncio.run(go())
        self.assertFalse(p.ok)
        self.assertEqual(p.status, 0)

    def test_rate_limiter_spaces_request_starts(self):
        import asyncio
        import time
        from origami.core.httpclient import Engine, EngineConfig

        async def go():
            e = Engine(EngineConfig(rate=50.0))     # 50 req/s → 20ms slots
            t0 = time.monotonic()
            await asyncio.gather(*(e._pace() for _ in range(6)))  # 6 slots = 5 gaps
            return time.monotonic() - t0

        elapsed = asyncio.run(go())
        self.assertGreaterEqual(elapsed, 5 * (1 / 50.0) * 0.8)   # ~0.1s, allow slack
        self.assertLess(elapsed, 1.0)                            # but not serialized-slow

    def test_rate_zero_is_noop(self):
        import asyncio
        from origami.core.httpclient import Engine, EngineConfig
        async def go():
            e = Engine(EngineConfig(rate=0.0))
            await e._pace()                          # returns immediately
            return e._next_slot
        self.assertEqual(asyncio.run(go()), 0.0)

class TestReflectionLeads(unittest.TestCase):
    """Graded reflection: breakout (unescaped/SSTI), open-redirect, header reflection."""

    def test_build_breakout_batch_unique_sentinels(self):
        from origami.modules import paramfuzz as pf
        qs, sent = pf.build_breakout_batch(["q", "name"], run="oztest")
        self.assertEqual(set(sent.values()), {"q", "name"})
        self.assertEqual(len(set(sent)), 2)                      # unique sentinels
        self.assertIn("q=oztestb0z", qs)
        self.assertIn("{{7*7}}", qs)                            # SSTI polyglot present
        # cap bounds the params in one probe
        _, capped = pf.build_breakout_batch([f"p{i}" for i in range(50)], cap=15)
        self.assertEqual(len(capped), 15)

    def test_analyze_breakout_raw_vs_escaped_vs_ssti(self):
        from origami.modules import paramfuzz as pf
        sm = {"oztestb0z": "q"}
        raw = pf.analyze_breakout(b'<b>oztestb0z\'"<>{{7*7}}oztestb0z</b>', sm)
        self.assertIn("<", raw["q"]["raw"])
        self.assertIn(">", raw["q"]["raw"])
        self.assertFalse(raw["q"]["ssti"])
        # HTML-entity-encoded → no raw metacharacters survive
        esc = pf.analyze_breakout(b"oztestb0z&#39;&quot;&lt;&gt;{{7*7}}oztestb0z", sm)
        self.assertEqual(esc["q"]["raw"], "")
        # template evaluated: 49 present, literal {{7*7}} gone → SSTI
        ssti = pf.analyze_breakout(b'oztestb0z\'"<>49oztestb0z', sm)
        self.assertTrue(ssti["q"]["ssti"])
        # only one sentinel → inconclusive, omitted
        self.assertEqual(pf.analyze_breakout(b"oztestb0z<>", sm), {})

    def test_reflected_in_location_and_headers(self):
        from origami.modules import paramfuzz as pf
        tm = {"oz0q": "redirect", "oz1q": "x"}
        self.assertEqual(pf.reflected_in_location("https://evil.com/oz0q", tm), ["redirect"])
        self.assertEqual(pf.reflected_in_location("/oz0q", tm), ["redirect"])   # canary in path
        self.assertEqual(pf.reflected_in_location("", tm), [])
        # NOT an open-redirect: a trailing-slash canonicalization redirect that just
        # PRESERVES the request query (/x → /x/?...) echoes every canary in the query,
        # but none steer the destination → must flag nothing (was a 78-param FP).
        self.assertEqual(pf.reflected_in_location("/assets/?redirect=oz0q&x=oz1q", tm), [])
        # a canary in an X- header is a lead; the same canary in Location is NOT
        # double-counted here (Location is handled by reflected_in_location)
        self.assertEqual(pf.reflected_in_headers({"x-foo": "oz1q", "location": "oz0q"}, tm),
                         {"x": "x-foo"})

class TestBaseWordlist(unittest.TestCase):
    def test_loads_clean_and_curated(self):
        from origami.core.scheduler import load_wordlist
        w = load_wordlist()
        self.assertGreaterEqual(len(w), 200)                 # a real default, not a demo stub
        self.assertEqual(len(w), len(set(w)), "no duplicate entries")
        for x in w:
            self.assertEqual(x, x.lower())                   # lowercase
            self.assertNotIn(".", x)                          # bare names — ext fold appends
            self.assertFalse(any(c in x for c in "/ \t"))     # no slashes/whitespace
        for must in ("admin", "login", "api", "config", "backup", "upload"):
            self.assertIn(must, w)

    def test_big_wordlist_clean_and_superset(self):
        from pathlib import Path
        from origami.core.scheduler import load_wordlist, resolve_wordlist, WORDLIST_DIR
        base = load_wordlist()
        big = load_wordlist(WORDLIST_DIR / "big.txt")
        self.assertGreater(len(big), len(base) + 400)         # meaningfully bigger
        self.assertEqual(len(big), len(set(big)), "no duplicate entries")
        self.assertTrue(set(base).issubset(set(big)), "big must contain base")
        for x in big:                                          # same bare-name rules as base
            self.assertEqual(x, x.lower())
            self.assertNotIn(".", x)
            self.assertFalse(any(c in x for c in "/ \t"))
            self.assertTrue(x.replace("_", "").replace("-", "").isalnum())

    def test_wordlist_name_resolves(self):
        from pathlib import Path
        from origami.core.scheduler import resolve_wordlist
        self.assertEqual(resolve_wordlist(Path("big")).name, "big.txt")     # -w big
        self.assertEqual(resolve_wordlist(Path("base")).name, "base.txt")   # -w base
        self.assertEqual(resolve_wordlist(Path("big.txt")).name, "big.txt")
        self.assertEqual(resolve_wordlist(Path("/no/such.txt")).name, "such.txt")  # passthrough
        self.assertEqual(resolve_wordlist(None).name, "base.txt")           # default

    def test_wordlist_name_not_shadowed_by_cwd_directory(self):
        # regression: a directory named `base` in the CWD must not shadow the
        # bundled base.txt — resolve_wordlist used exists() (true for dirs) and
        # read_text() then raised IsADirectoryError under `--deep` (implies base).
        import os, tempfile
        from pathlib import Path
        from origami.core.scheduler import resolve_wordlist, load_wordlists, WORDLIST_DIR
        cwd = os.getcwd()
        d = tempfile.mkdtemp()
        os.mkdir(os.path.join(d, "base"))
        try:
            os.chdir(d)
            self.assertEqual(resolve_wordlist(Path("base")), WORDLIST_DIR / "base.txt")
            self.assertTrue(load_wordlists(["base"]))       # no IsADirectoryError
        finally:
            os.chdir(cwd)

    def test_load_wordlists_merges_and_dedups(self):
        import os, tempfile
        from origami.core.scheduler import load_wordlists, load_wordlist
        f = tempfile.mktemp(suffix=".txt")
        with open(f, "w") as fh:
            fh.write("uniqueone\nuniquetwo\nadmin\n")       # 'admin' collides with base
        try:
            merged = load_wordlists(["base", f])            # simulates --deep -w custom
            self.assertIn("uniqueone", merged)              # custom folded in
            self.assertIn("login", merged)                  # base preserved
            self.assertEqual(merged.count("admin"), 1)      # de-duplicated across lists
            self.assertEqual(load_wordlists([]), load_wordlist())   # empty → default base
        finally:
            os.unlink(f)


if __name__ == "__main__":
    unittest.main()

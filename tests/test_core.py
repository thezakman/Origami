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
               location="", headers=None):
    return Probe(url=url, method="GET", status=status, length=len(body),
                 words=len(body.split()), lines=body.count(b"\n") + 1,
                 content_type=ctype, location=location,
                 body_simhash=simhash(body), elapsed_ms=1.0,
                 headers=headers or {},
                 body_head=body[:2048], body=body)


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


class TestHarvestFold(unittest.TestCase):
    def test_harvestable_predicate(self):
        from origami.core.scanner import _harvestable
        from origami.core.response_classifier import Finding
        def F(url, status=200, ct="application/javascript"):
            return Finding(url, status, 10, ct, 0.9, "wordlist")
        self.assertTrue(_harvestable(F("https://h/app/main.js")))
        self.assertTrue(_harvestable(F("https://h/api", ct="application/json")))
        self.assertFalse(_harvestable(F("https://h/img.png", ct="image/png")))
        self.assertFalse(_harvestable(F("https://h/x.js", status=403)))   # only 2xx
        self.assertFalse(_harvestable(F("https://h/vendor/jquery.min.js")))  # vendor skipped

    def test_harvest_fold_reads_discovered_js_and_probes_new_endpoint(self):
        import asyncio
        from urllib.parse import urlparse
        from origami.core.scanner import _harvest_fold, ScanResult, ScanOptions
        from origami.core.evidence import TargetProfile
        from origami.core.response_classifier import Finding
        from origami.output.ui import NullObserver

        # a discovered JS file whose body references an endpoint no wordlist has
        js_url = "https://h/static/app.bundle.js"
        js_body = b'const u="/secret/api/v2/users";fetch(u);import("/secret/api/v2/admin")'
        hidden = {"/secret/api/v2/users", "/secret/api/v2/admin"}

        class FakeEngine:
            total_requests = 0
            def __init__(self): self.cfg = type("C", (), {"verify_tls": False})()
            async def fetch(self, url, method="GET", keep_body=False, headers=None):
                FakeEngine.total_requests += 1
                path = urlparse(url).path
                if url == js_url:
                    return make_probe(200, js_body, url=url, ctype="application/javascript")
                if path in hidden:
                    return make_probe(200, b"REAL SENSITIVE DATA HERE", url=url, ctype="application/json")
                return make_probe(404, b"<html>not found</html>", url=url)  # randoms, siblings
            async def gather(self, urls, method="GET"):
                return [await self.fetch(u, method) for u in urls]

        profile = TargetProfile(host="h", base_url="https://h/")
        result = ScanResult(profile=profile, findings=[
            Finding(js_url, 200, len(js_body), "application/javascript", 0.95, "wordlist")])
        new_dirs = asyncio.run(_harvest_fold(FakeEngine(), profile, result, ScanOptions(),
                                             NullObserver(), "/"))
        harvested = {urlparse(f.url).path for f in result.findings if f.origin == "harvest"}
        self.assertEqual(harvested, hidden)   # both hidden endpoints found & reported
        # returns the dir the new endpoints live in → the scan loop recurses it
        self.assertEqual(new_dirs, {"/secret/api/v2/"})

    def test_harvest_fold_skips_already_read_files(self):
        import asyncio
        from origami.core.scanner import _harvest_fold, ScanResult, ScanOptions
        from origami.core.evidence import TargetProfile
        from origami.core.response_classifier import Finding
        from origami.output.ui import NullObserver
        js_url = "https://h/app.js"
        class FakeEngine:
            total_requests = 0
            async def fetch(self, url, method="GET", keep_body=False, headers=None):
                FakeEngine.total_requests += 1
                return make_probe(200, b'x="/a/b"', url=url, ctype="application/javascript")
            async def gather(self, urls, method="GET"):
                return [await self.fetch(u) for u in urls]
        profile = TargetProfile(host="h", base_url="https://h/")
        result = ScanResult(profile=profile, findings=[
            Finding(js_url, 200, 8, "application/javascript", 0.95, "wordlist")])
        already = set()
        eng = FakeEngine()
        asyncio.run(_harvest_fold(eng, profile, result, ScanOptions(), NullObserver(), "/", already))
        self.assertIn(js_url, already)                    # recorded as read
        before = FakeEngine.total_requests
        asyncio.run(_harvest_fold(eng, profile, result, ScanOptions(), NullObserver(), "/", already))
        self.assertEqual(FakeEngine.total_requests, before)   # second round re-reads nothing


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


class TestVhost(unittest.TestCase):
    def test_registrable_handles_multi_label_suffixes(self):
        from origami.modules.vhost import registrable
        self.assertEqual(registrable("app.example.com"), "example.com")
        self.assertEqual(registrable("nfce.newchoice.com.br"), "newchoice.com.br")  # .com.br!
        self.assertEqual(registrable("a.b.co.uk"), "b.co.uk")
        self.assertEqual(registrable("example.com"), "example.com")

    def test_same_site_rejects_shared_hosting_co_tenants(self):
        # scope safety: foo.github.io and bar.github.io are DIFFERENT tenants —
        # treating them as one site would pull a co-tenant host into --scope site
        from origami.core.scope import same_site, reg_domain
        self.assertFalse(same_site("foo.github.io", "bar.github.io"))
        self.assertFalse(same_site("a.s3.amazonaws.com", "b.s3.amazonaws.com"))
        self.assertFalse(same_site("app1.herokuapp.com", "app2.herokuapp.com"))
        self.assertEqual(reg_domain("foo.github.io"), "foo.github.io")
        # but a normal org's CDN/subdomains are still one site (CDN reading intact)
        self.assertTrue(same_site("cdn.example.com", "app.example.com"))
        self.assertTrue(same_site("a.acme.com.br", "b.acme.com.br"))

    def test_candidates_build_from_apex_excluding_target(self):
        from origami.modules.vhost import candidates
        c = candidates("nfce.newchoice.com.br")
        self.assertIn("admin.newchoice.com.br", c)
        self.assertIn("staging.newchoice.com.br", c)
        self.assertIn("localhost", c)
        self.assertNotIn("nfce.newchoice.com.br", c)        # the target itself excluded

    def test_vhost_fold_reports_only_distinct_vhosts(self):
        import asyncio
        from urllib.parse import urlparse
        from origami.core.scanner import _vhost_fold, ScanResult, ScanOptions
        from origami.core.evidence import TargetProfile
        from origami.output.ui import NullObserver

        default_body = b"DEFAULT SITE HOMEPAGE CONTENT WELCOME"
        class FakeEngine:
            total_requests = 0
            async def fetch(self, url, method="GET", keep_body=False, headers=None):
                FakeEngine.total_requests += 1
                host = (headers or {}).get("Host", "")
                if host.endswith(".invalid"):
                    body = b"UNKNOWN VHOST CATCH ALL PAGE"          # bogus baseline
                elif host == "admin.example.com":
                    body = b"ADMIN PANEL - totally distinct content here"
                elif host == "www.example.com":
                    body = default_body                            # == the default site
                else:
                    body = b"UNKNOWN VHOST CATCH ALL PAGE"         # everything else = catch-all
                return make_probe(200, body, url=url)

        profile = TargetProfile(host="app.example.com", base_url="https://app.example.com/")
        result = ScanResult(profile=profile)
        asyncio.run(_vhost_fold(FakeEngine(), profile, result, ScanOptions(),
                                NullObserver(), simhash(default_body)))
        vhosts = {urlparse(f.url).netloc for f in result.findings if f.origin == "vhost"}
        self.assertEqual(vhosts, {"admin.example.com"})    # distinct only; bogus-alike & default excluded


class TestSecrets(unittest.TestCase):
    def test_scan_detects_provider_keys(self):
        from origami.modules.secrets import scan
        def kinds(b): return {k for k, _ in scan(b)}
        self.assertIn("aws-access-key", kinds(b'k=AKIAZ7QF3X9PLMNB2WQT'))
        self.assertIn("github-token", kinds(b'ghp_Qw7Er9Ty2Ui4Op6As8Df1Gh3Jk5Lz7Xc9Vb'))
        self.assertIn("jwt", kinds(b'tok=eyJhbGciOiJI.eyJzdWIiOiIx.SflKxwRJSMeKK'))
        self.assertIn("private-key", kinds(b'-----BEGIN RSA PRIVATE KEY-----\nMII'))
        self.assertIn("db-uri-creds", kinds(b'postgres://admin:s3cr3tpass@db.host:5432/app'))
        self.assertIn("generic-secret", kinds(b'api_key: "9f8a7b6c5d4e3f2a1b0c"'))

    def test_scan_detects_modern_provider_keys(self):
        # token bodies are ASSEMBLED at runtime (prefix + b"..."*N) so no full-token
        # literal sits in source — keeps GitHub push-protection from flagging tests.
        from origami.modules.secrets import scan
        def kinds(b): return {k for k, _ in scan(b)}
        self.assertIn("anthropic-key", kinds(b"K=" + b"sk-ant-" + b"A1b2C3d9"*6))
        self.assertIn("openai-key", kinds(b"OPENAI_API_KEY=" + b"sk-" + b"aB3dE6gH"*6))
        self.assertIn("openai-key", kinds(b"k=" + b"sk-proj-" + b"aB3dE6gH"*5))
        self.assertIn("gitlab-token", kinds(b"glpat-" + b"aB3dE6gH"*3))
        self.assertIn("digitalocean-token", kinds(b"dop_v1_" + b"9f3a7c1e8b2d4056"*4))
        self.assertIn("shopify-token", kinds(b"shpat_" + b"9f3a7c1e8b2d4056"*2))
        self.assertIn("square-token", kinds(b"sq0atp-" + b"aB3dE6gH"*3))
        self.assertIn("telegram-bot-token", kinds(b"1234567890:" + b"AA" + b"aB3dE6gH"*5))
        self.assertIn("azure-storage-key", kinds(b"AccountKey=" + b"A"*86 + b"==;"))
        # anthropic wins over openai for the shared sk- prefix (more specific first)
        self.assertNotIn("openai-key", kinds(b"sk-ant-" + b"A1b2C3d9"*6))

    def test_modern_keys_no_false_positive(self):
        from origami.modules.secrets import scan
        # ordinary text with sk-/shp/sq fragments must not trip the provider rules
        self.assertEqual(scan(b'import {taskRunner} from "task-runner";'), [])
        self.assertEqual(scan(b'<div class="sidebar-navigation-wrapper-shp">'), [])
        self.assertEqual(scan(b"please ask-someone about it later"), [])

    def test_scan_rejects_placeholders_and_examples(self):
        from origami.modules.secrets import scan
        self.assertEqual(scan(b'password = "changeme"'), [])
        self.assertEqual(scan(b'api_key="your_api_key_here"'), [])
        self.assertEqual(scan(b'password="12"'), [])                      # too short
        self.assertEqual(scan(b'AWS_KEY=AKIAIOSFODNN7EXAMPLE'), [])        # AWS doc example
        self.assertEqual(scan(b''), [])

    def test_scan_rejects_minified_js_concat(self):
        # the real-target FP: minified JS string concatenation around a trigger
        # word — "…secret="+this.foo+"…#]/," — captured a code fragment, not a key
        from origami.modules.secrets import scan
        self.assertEqual(scan(b'var x="theme-secret="+this.opts.foo+"#]/,";'), [])
        self.assertEqual(scan(b'token:"+this.x+"'), [])

    def test_scan_rejects_code_expression_values(self):
        # a JS member-access / dotted-identifier chain is code, not a credential
        from origami.modules.secrets import scan
        self.assertEqual(scan(b'password:"this.config.password"'), [])
        self.assertEqual(scan(b'client_secret="window.app.clientSecret"'), [])
        self.assertEqual(scan(b'api_key="cfg.keys.api_key.v2"'), [])

    def test_scan_keeps_real_generic_secret_after_hardening(self):
        # tightening the charset must not drop genuine token-shaped values
        from origami.modules.secrets import scan
        def kinds(b): return {k for k, _ in scan(b)}
        self.assertIn("generic-secret", kinds(b'api_key="A1b2C3d4E5f6G7h8"'))
        self.assertIn("generic-secret", kinds(b'"password": "Sup3rS3cretPwdxx"'))

    def test_scan_keeps_dotted_token_secrets(self):
        # version-prefixed / dotted secrets have a token-shaped segment — the
        # code-chain guard must NOT drop them (only pure identifier chains)
        from origami.modules.secrets import scan
        def kinds(b): return {k for k, _ in scan(b)}
        self.assertIn("generic-secret", kinds(b'auth_token="v1.abcdef1234567890"'))
        self.assertIn("generic-secret", kinds(b'api_key="key1234abcd.def5678ghij"'))

    def test_scan_redacts(self):
        from origami.modules.secrets import scan
        (kind, red), = scan(b'k=AKIAZ7QF3X9PLMNB2WQT')
        self.assertNotIn("AKIAZ7QF3X9PLMNB2WQT", red)                     # not the full secret
        self.assertTrue(red.startswith("AKIAZ7"))                          # but identifiable

    def test_secrets_fold_flags_config_finding(self):
        import asyncio
        from origami.core.scanner import _secrets_fold, ScanResult, ScanOptions
        from origami.core.evidence import TargetProfile
        from origami.core.response_classifier import Finding
        from origami.output.ui import NullObserver

        env_url = "https://h/.env"
        class FakeEngine:
            total_requests = 0
            async def fetch(self, url, method="GET", keep_body=False, headers=None):
                FakeEngine.total_requests += 1
                body = b'SECRET_KEY=AKIAZ7QF3X9PLMNB2WQT\nDB=postgres://u:p4ssword@h/db' if url == env_url else b""
                return make_probe(200, body, url=url, ctype="text/plain")
            async def gather(self, urls, method="GET"):
                return [await self.fetch(u) for u in urls]

        profile = TargetProfile(host="h", base_url="https://h/")
        f = Finding(env_url, 200, 40, "text/plain", 0.95, "wordlist", tags=["config"])
        result = ScanResult(profile=profile, findings=[f])
        asyncio.run(_secrets_fold(FakeEngine(), profile, result, ScanOptions(), NullObserver()))
        self.assertIn("secret", f.tags)
        self.assertIn("secrets:", f.note)


class TestParamFuzz(unittest.TestCase):
    def test_safe_names_and_batches(self):
        from origami.modules import paramfuzz as P
        names = P.safe_names(["id", "q", "bad name", "x;y", "id", "redirect"])
        self.assertEqual(names, ["id", "q", "redirect"])           # junk + dupes dropped
        (qs, tmap, ctl), = P.build_batches(["id"], batch_size=5, run="oztest")
        self.assertIn("id=oztest0q", qs)
        self.assertIn("oztestctlname=", qs)                        # control param present
        self.assertEqual(P.reflected(b"echo oztest0q here", tmap), ["id"])
        self.assertTrue(P.control_reflected(b"... oztestctlq ...", ctl))

    def test_fold_flags_reflected_param(self):
        import asyncio
        from urllib.parse import urlparse, parse_qs
        from origami.core.scanner import _param_fold, ScanResult, ScanOptions
        from origami.core.evidence import TargetProfile
        from origami.core.response_classifier import Finding
        from origami.output.ui import NullObserver

        class FakeEngine:                       # reflects ONLY the 'q' param's canary
            total_requests = 0
            async def fetch(self, url, method="GET", keep_body=False, headers=None):
                FakeEngine.total_requests += 1
                q = parse_qs(urlparse(url).query)
                body = (b"results for " + q["q"][0].encode()) if "q" in q else b"home"
                return make_probe(200, body, url=url, ctype="text/html")

        prof = TargetProfile(host="h", base_url="https://h/")
        prof.parameters = {"q"}                 # harvested param name
        f = Finding("https://h/search.php", 200, 10, "text/html", 0.9, "wordlist")
        result = ScanResult(profile=prof, findings=[f])
        streamed = []
        opts = ScanOptions(param_fuzz=True, finding_sink=streamed.append)
        asyncio.run(_param_fold(FakeEngine(), prof, result, opts, NullObserver()))
        self.assertIn("param", f.tags)
        self.assertIn("xss-lead", f.tags)              # breakout confirmed a raw HTML-sink reflection
        self.assertIn("q (html", f.note)               # graded by injection context
        self.assertIn("UNESCAPED", f.note)             # the breakout probe proved metachars came back raw
        self.assertTrue(any(s is f for s in streamed))             # streamed for JSONL

    def test_fold_flags_open_redirect_and_header(self):
        import asyncio
        from urllib.parse import urlparse, parse_qs
        from origami.core.scanner import _param_fold, ScanResult, ScanOptions
        from origami.core.evidence import TargetProfile
        from origami.core.response_classifier import Finding
        from origami.output.ui import NullObserver

        class FakeEngine:                       # 3xx endpoint: reflects 'url' into Location
            total_requests = 0
            async def fetch(self, url, method="GET", keep_body=False, headers=None):
                FakeEngine.total_requests += 1
                q = parse_qs(urlparse(url).query)
                loc = q.get("url", [""])[0]     # open-redirect: canary echoed into Location
                hdrs = {"location": loc}
                if "q" in q:
                    hdrs["x-echo"] = q["q"][0]  # header reflection
                return make_probe(302, b"", url=url, location=loc, headers=hdrs)

        prof = TargetProfile(host="h", base_url="https://h/")
        f = Finding("https://h/redir", 302, 0, "", 0.9, "wordlist")
        result = ScanResult(profile=prof, findings=[f])
        opts = ScanOptions(param_fuzz=True)
        asyncio.run(_param_fold(FakeEngine(), prof, result, opts, NullObserver()))
        self.assertIn("redirect-lead", f.tags)         # canary in Location → open-redirect
        self.assertIn("open-redirect: url", f.note)
        self.assertIn("header reflection: q", f.note)  # canary echoed in x-echo header

    def test_reflection_contexts_classify_sink(self):
        from origami.modules import paramfuzz as P
        (qs, tmap, ctl), = P.build_batches(["q", "name", "data"], batch_size=5, run="oztest")
        tok = {p: t for t, p in tmap.items()}
        html = (b"<html>search: " + tok["q"].encode() + b"</html>"
                b'<input value="' + tok["name"].encode() + b'">'
                b'<script>var x="' + tok["data"].encode() + b'";</script>')
        ctx = P.reflection_contexts(html, tmap, "text/html")
        self.assertEqual(ctx["q"], "html")
        self.assertEqual(ctx["name"], "attr")
        self.assertEqual(ctx["data"], "js")
        jb = b'{"q":"' + tok["q"].encode() + b'"}'
        self.assertEqual(P.reflection_contexts(jb, tmap, "application/json")["q"], "json")

    def test_fold_skips_endpoint_that_echoes_any_query(self):
        import asyncio
        from origami.core.scanner import _param_fold, ScanResult, ScanOptions
        from origami.core.evidence import TargetProfile
        from origami.core.response_classifier import Finding
        from origami.output.ui import NullObserver

        class EchoEngine:                       # echoes the WHOLE query → control reflects
            total_requests = 0
            async def fetch(self, url, method="GET", keep_body=False, headers=None):
                EchoEngine.total_requests += 1
                from urllib.parse import urlparse
                return make_probe(200, b"you sent: " + urlparse(url).query.encode(),
                                  url=url, ctype="text/html")

        prof = TargetProfile(host="h", base_url="https://h/")
        f = Finding("https://h/x.php", 200, 10, "text/html", 0.9, "wordlist")
        result = ScanResult(profile=prof, findings=[f])
        asyncio.run(_param_fold(EchoEngine(), prof, result, ScanOptions(param_fuzz=True), NullObserver()))
        self.assertNotIn("param", f.tags)       # echoes-any → no false reflections


class TestWayback(unittest.TestCase):
    def test_parse_url_lines(self):
        from origami.modules.discovery import wayback as W
        txt = "http://h/a\nhttps://h/b?x=1\ngarbage line\n\nhttp://other/c\n"
        self.assertEqual(W.parse_url_lines(txt),
                         {"http://h/a", "https://h/b?x=1", "http://other/c"})

    def test_parse_cc_json(self):
        from origami.modules.discovery import wayback as W
        txt = '{"url": "http://h/x"}\n{"url":"https://h/y"}\nnot json\n{"nourl": 1}\n'
        self.assertEqual(W.parse_cc_json(txt), {"http://h/x", "https://h/y"})

    def test_extract_paths_and_params_scope_and_assets(self):
        from origami.modules.discovery import wayback as W
        urls = {"http://h.com/admin?id=1&token=x", "https://h.com/old/page",
                "http://h.com/logo.png", "https://sub.h.com/secret", "http://h.com/?q=2",
                "http://evil.com/x"}
        paths, params = W.extract_paths_and_params(urls, "h.com")
        self.assertEqual(paths, {"/admin", "/old/page"})      # asset, root, off-host, sub dropped
        self.assertEqual(params, {"id", "token", "q"})        # query names harvested
        sub_paths, _ = W.extract_paths_and_params(urls, "h.com", subs=True)
        self.assertIn("/secret", sub_paths)                   # subdomain kept under subs

    def test_harvest_native_union_and_never_raises(self):
        import asyncio
        from origami.modules.discovery import wayback as W
        orig = (W.from_cdx, W.from_commoncrawl, W.from_gau, W.from_urlscan, W.from_otx)
        try:
            async def cdx(host, cap=0, subs=False): return {"http://h/a?p=1"}
            async def cc(host, cap=0, subs=False): return {"http://h/b"}
            async def none(host, cap=0, subs=False): return set()
            W.from_cdx, W.from_commoncrawl = cdx, cc
            W.from_urlscan, W.from_otx = none, none
            paths, params, src = asyncio.run(W.harvest("h"))
            self.assertEqual(paths, {"/a", "/b"})
            self.assertEqual(params, {"p"})
            self.assertEqual(src, "wayback+cc")
            # every source failing → empty, no exception
            async def boom(host, cap=0, subs=False): raise RuntimeError("down")
            W.from_cdx = W.from_commoncrawl = boom
            self.assertEqual(asyncio.run(W.harvest("h")), (set(), set(), "none"))
        finally:
            W.from_cdx, W.from_commoncrawl, W.from_gau, W.from_urlscan, W.from_otx = orig

    def test_harvest_gau_preferred_with_native_fallback(self):
        import asyncio
        from origami.modules.discovery import wayback as W
        orig = (W.from_cdx, W.from_commoncrawl, W.from_gau, W.from_urlscan, W.from_otx)
        try:
            async def cdx(host, cap=0, subs=False): return {"http://h/native"}
            async def none(host, cap=0, subs=False): return set()
            W.from_cdx, W.from_commoncrawl = cdx, none
            W.from_urlscan, W.from_otx = none, none
            async def gau_ok(host, **k): return {"http://h/fromgau"}
            W.from_gau = gau_ok
            paths, _, src = asyncio.run(W.harvest("h", use_gau=True))
            self.assertEqual((paths, src), ({"/fromgau"}, "gau"))
            async def gau_missing(host, **k): return None        # binary absent
            W.from_gau = gau_missing
            paths, _, src = asyncio.run(W.harvest("h", use_gau=True))
            self.assertEqual((paths, src), ({"/native"}, "wayback"))   # fell back to native
        finally:
            W.from_cdx, W.from_commoncrawl, W.from_gau, W.from_urlscan, W.from_otx = orig

    def test_from_gau_timeout_reaps_child(self):
        # a hung gau must hit its own timeout, be reaped, and return empty fast —
        # never left running detached. Pass the fake binary EXPLICITLY (`binaries`
        # is a def-time default, so rebinding the module global wouldn't take) so
        # the test is deterministic regardless of whether gau is installed.
        import asyncio, time
        from origami.modules.discovery import wayback as W
        orig_to = W._GAU_TIMEOUT
        try:
            W._GAU_TIMEOUT = 0.3
            t0 = time.time()
            res = asyncio.run(W.from_gau("5", binaries=("sleep",)))  # `sleep 5` >> 0.3s timeout
            self.assertEqual(res, set())
            self.assertLess(time.time() - t0, 3.0)  # returned promptly, didn't block 5s
        finally:
            W._GAU_TIMEOUT = orig_to

    def test_harvest_caps_paths(self):
        import asyncio
        from origami.modules.discovery import wayback as W
        orig = (W.from_cdx, W.from_commoncrawl, W.from_urlscan, W.from_otx)
        try:
            async def many(host, cap=0, subs=False):
                return {f"http://h/p{i}" for i in range(50)}
            async def none(host, cap=0, subs=False): return set()
            W.from_cdx, W.from_commoncrawl = many, none
            W.from_urlscan, W.from_otx = none, none        # stub the extra sources (no network)
            paths, _, src = asyncio.run(W.harvest("h", cap=10))
            self.assertEqual(len(paths), 10)
            self.assertIn("wayback", src)
        finally:
            W.from_cdx, W.from_commoncrawl, W.from_urlscan, W.from_otx = orig

    def test_harvest_unions_all_passive_sources(self):
        import asyncio
        from origami.modules.discovery import wayback as W
        orig = (W.from_cdx, W.from_commoncrawl, W.from_urlscan, W.from_otx)
        try:
            async def cdx(host, cap=0, subs=False): return {"http://h/a"}
            async def cc(host, cap=0, subs=False): return set()
            async def us(host, cap=0, subs=False): return {"http://h/b"}
            async def otx(host, cap=0, subs=False): return {"http://h/c"}
            W.from_cdx, W.from_commoncrawl, W.from_urlscan, W.from_otx = cdx, cc, us, otx
            paths, _, src = asyncio.run(W.harvest("h"))
            self.assertEqual(paths, {"/a", "/b", "/c"})    # all sources merged
            self.assertIn("urlscan", src)
            self.assertIn("otx", src)
        finally:
            W.from_cdx, W.from_commoncrawl, W.from_urlscan, W.from_otx = orig

    def test_parse_urlscan_and_otx(self):
        from origami.modules.discovery import wayback as W
        us = '{"results":[{"page":{"url":"https://h/x"},"task":{"url":"https://h/y"}}]}'
        self.assertEqual(W.parse_urlscan(us), {"https://h/x", "https://h/y"})
        otx = '{"url_list":[{"url":"https://h/z"},{"url":"http://h/w"}]}'
        self.assertEqual(W.parse_otx(otx), {"https://h/z", "http://h/w"})
        self.assertEqual(W.parse_urlscan("not json"), set())
        self.assertEqual(W.parse_otx("{}"), set())


class TestSessionAuthWall(unittest.TestCase):
    def _p(self, status, loc="", body=b""):
        return make_probe(status, body or b"x", url="http://h/", ctype="text/html", location=loc)

    def test_has_auth(self):
        from origami.modules import session as S
        self.assertTrue(S.has_auth({"Cookie": "s=1"}))
        self.assertTrue(S.has_auth({"authorization": "Bearer x"}))
        self.assertTrue(S.has_auth({"X-API-Key": "k"}))
        self.assertFalse(S.has_auth({"X-Custom": "1"}))
        self.assertFalse(S.has_auth({}))

    def test_auth_wall_detected(self):
        from origami.modules import session as S
        self.assertIsNotNone(S.auth_wall_reason(self._p(401)))
        self.assertIsNotNone(S.auth_wall_reason(self._p(302, "https://h/account/login?next=/")))
        self.assertIsNotNone(S.auth_wall_reason(self._p(302, "https://h/users/sign_in")))
        self.assertIsNotNone(S.auth_wall_reason(
            self._p(200, body=b'<form><input name=pw type="password"></form>')))

    def test_no_false_positive_on_authenticated_root(self):
        from origami.modules import session as S
        self.assertIsNone(S.auth_wall_reason(self._p(200, body=b"<html>welcome to your dashboard</html>")))
        self.assertIsNone(S.auth_wall_reason(self._p(302, "https://h/dashboard")))   # redirect, not to login
        self.assertIsNone(S.auth_wall_reason(self._p(200, body=b"<html>home</html>")))

    def _run_scan(self, engine):
        import asyncio, os, tempfile
        from origami.core.scanner import scan, ScanOptions
        from origami.output.ui import NullObserver
        wl = tempfile.mktemp(suffix=".txt")
        with open(wl, "w") as fh:
            fh.write("admin\nindex\n")          # tiny list → fast walk over the fake engine
        logs = []
        class L(NullObserver):
            def log(self, m, *a, **k): logs.append(m)
        async def main():
            await scan(engine, "https://h/", observer=L(), memory=None,
                       opts=ScanOptions(max_depth=0, wordlist_paths=[str(wl)], js=False,
                                        apidocs=False, backups=False, max_folds=0))
        try:
            asyncio.run(main())
        finally:
            os.unlink(wl)
        return logs

    def _engine(self, headers, root_seq):
        # root_seq: list of (status, location, body) returned for successive root fetches
        from origami.core.httpclient import Probe, EngineConfig
        class FakeEngine:
            def __init__(s):
                s.total_requests = 0; s.prior_requests = 0; s.pushback_events = 0
                s.on_request = None; s.cfg = EngineConfig(headers=headers); s._i = 0
            @property
            def spent(s): return s.prior_requests + s.total_requests
            async def fetch(s, url, method="GET", keep_body=False, headers=None):
                s.total_requests += 1
                root = url.rstrip("/").endswith("h") or url.endswith("/")
                if root:
                    st, loc, body = root_seq[min(s._i, len(root_seq) - 1)]; s._i += 1
                    return Probe(url, "GET", st, len(body), 0, 0, "text/html", loc, 0, 1.0,
                                 body_head=body, body=body)
                return Probe(url, "GET", 404, 0, 0, 0, "text/html", "", 0, 1.0)
            async def gather(s, urls, method="GET"): return [await s.fetch(u) for u in urls]
        return FakeEngine()

    def test_scan_warns_on_midscan_session_expiry(self):
        # started authed (root 200), then root flips to a login redirect → warn
        eng = self._engine({"Cookie": "s=1"},
                           [(200, "", b"<html>dashboard</html>")] * 3 +
                           [(302, "https://h/account/login", b"")])
        logs = self._run_scan(eng)
        self.assertTrue(any("EXPIRED during the scan" in m for m in logs))

    def test_scan_no_warning_when_session_stays_valid(self):
        eng = self._engine({"Cookie": "s=1"}, [(200, "", b"<html>dashboard</html>")])
        logs = self._run_scan(eng)
        self.assertFalse(any("EXPIRED" in m for m in logs))

    def test_scan_no_recheck_without_auth(self):
        # no auth headers → never re-checks / warns, even if root would look walled
        eng = self._engine({}, [(200, "", b"<html>home</html>"),
                                (302, "https://h/login", b"")])
        logs = self._run_scan(eng)
        self.assertFalse(any("EXPIRED" in m for m in logs))


class TestLeaks(unittest.TestCase):
    def kinds(self, body):
        from origami.modules.leaks import scan
        return {k for k, _ in scan(body)}

    def test_stack_traces_detected(self):
        self.assertIn("python-traceback", self.kinds(b"Traceback (most recent call last):\n  File"))
        self.assertIn("java-stacktrace", self.kinds(b"... at com.app.Svc.run(Svc.java:88) ..."))
        self.assertIn("dotnet-stacktrace", self.kinds(rb"at A.Get(Int32 id) in C:\app\C.cs:line 33"))
        self.assertIn("ruby-stacktrace", self.kinds(b"app/models/user.rb:21:in `find'"))
        self.assertIn("php-error", self.kinds(
            b"<b>Fatal error</b>: Uncaught in <b>/app/x.php</b> on line <b>42</b>"))

    def test_framework_debug_pages(self):
        self.assertIn("django-debug", self.kinds(b"<th>Django Version:</th><td>4.2</td>"))
        self.assertIn("flask-werkzeug", self.kinds(b"<title>Werkzeug Debugger</title>"))
        self.assertIn("dotnet-yellowscreen", self.kinds(b"<h1>Server Error in '/Shop' Application</h1>"))

    def test_internal_infra_leaks(self):
        self.assertIn("internal-ip", self.kinds(b"backend 10.0.5.23 down, retry 192.168.1.1"))
        self.assertIn("internal-host", self.kinds(b"upstream db01.internal timeout"))   # digit in label
        self.assertIn("internal-host", self.kinds(b"proxy_pass http://vault.corp.internal/api"))  # URL ctx
        self.assertIn("internal-host", self.kinds(b"connect cache.corp:6379"))           # host:port

    def test_infra_false_positives_rejected(self):
        # the real-target noise: SVG path floats and minified JS property access
        self.assertEqual(self.kinds(b"665 9.444 8.585 10.55.109.024.221.024.33 0 4.9"), set())
        self.assertEqual(self.kinds(b"},this.internal=1,ue.internal=2,x.local=3"), set())
        self.assertNotIn("internal-ip", self.kinds(b"version 10.55.109.024 build"))      # leading-zero octet
        self.assertEqual(self.kinds(b"resolver 8.8.8.8 and 1.1.1.1"), set())             # public IPs

    def test_internal_host_regex_not_superlinear(self):
        # regression: the internal-host pattern must stay linear on dot/digit/
        # hyphen-dense bodies (SVG path data) — it was O(n^2) before the fix
        import time
        from origami.modules.leaks import scan
        body = b'd="M1.5-2.3-4.0-10.55.109.024.221.024.33 " ' * 4000   # ~200 KB
        t0 = time.time()
        scan(body)
        self.assertLess(time.time() - t0, 2.0)         # was ~2.6s superlinear pre-fix

    def test_infra_skipped_on_js_bodies(self):
        from origami.modules.leaks import scan
        # even a well-formed internal IP/host is suppressed in a JS bundle (noise)
        body = b"const x='10.0.0.5'; cfg.host='db01.internal';"
        self.assertTrue(any(k.startswith("internal") for k, _ in scan(body)))   # html context: flagged
        self.assertEqual([k for k, _ in scan(body, js=True) if k.startswith("internal")], [])

    def test_low_false_positives(self):
        # ordinary content / public IPs / marketing copy must stay clean
        self.assertEqual(self.kinds(b"<html><body>Buy our ergonomic puffs</body></html>"), set())
        self.assertEqual(self.kinds(b"resolver 8.8.8.8 and 1.1.1.1"), set())          # public IPs
        self.assertEqual(self.kinds(b"Warning: only 3 left in stock, order today"), set())
        self.assertEqual(self.kinds(b"design-inovador-e-multifuncional"), set())

    def test_scan_body_tags_leak_and_streams_once(self):
        # the combined body scanner tags 'leak' and emits the finding once
        from origami.core.scanner import _scan_body
        from origami.core.response_classifier import Finding
        from origami.output.ui import NullObserver
        streamed = []
        f = Finding("https://h/boom", 500, 100, "text/html", 0.9, "wordlist")
        n = _scan_body(f, b"Traceback (most recent call last):\n at db01.internal",
                       NullObserver(), streamed.append)
        self.assertGreaterEqual(n, 1)
        self.assertIn("leak", f.tags)
        self.assertIn("leak:", f.note)
        self.assertEqual(len(streamed), 1)              # one sink emit for the finding


class TestClientApp(unittest.TestCase):
    def test_manifest_paths(self):
        from origami.modules.discovery.clientapp import manifest_paths
        doc = {"name": "x", "start_url": "/app/home?utm=1", "scope": "/app/",
               "icons": [{"src": "/icons/app.png"}, {"src": "https://cdn.OTHER/i.png"}],
               "shortcuts": [{"url": "/pwa/orders"}]}
        p = manifest_paths(doc, "https://h/")
        self.assertIn("/app/home", p)          # start_url, query stripped
        self.assertIn("/app/", p)              # scope
        self.assertIn("/icons/app.png", p)     # icon src
        self.assertIn("/pwa/orders", p)        # shortcut url
        self.assertTrue(all("OTHER" not in x for x in p))   # cross-host icon dropped

    def test_manifest_protocol_relative_offhost_dropped(self):
        from origami.modules.discovery.clientapp import manifest_paths
        doc = {"start_url": "//evil.com/x", "icons": [{"src": "//evil.com/i.png"}]}
        p = manifest_paths(doc, "https://h/")
        self.assertFalse(any("evil.com" in x or x.startswith("//") for x in p))


class TestBypass403(unittest.TestCase):
    def test_variants_cover_families(self):
        from origami.modules.bypass403 import variants
        v = variants("/admin")
        labels = [lbl for lbl, *_ in v]
        kinds = {lbl.split()[0] for lbl in labels}
        # the core families are always present (hop-by-hop/api-* added on top)
        self.assertTrue({"path", "header", "method"} <= kinds)
        # representative techniques present
        self.assertTrue(any(m == "/admin/" for _, _, m, _ in v))           # trailing slash
        self.assertTrue(any(h.get("X-Forwarded-For") for _, _, _, h in v))  # IP header
        self.assertTrue(any(meth == "POST" for _, meth, _, _ in v))         # method swap
        # X-Original-URL targets root with the header pointing at the path
        self.assertTrue(any(rp == "/" and h.get("X-Original-URL") == "/admin"
                            for _, _, rp, h in v))

    def test_variants_no_self_or_dupes(self):
        from origami.modules.bypass403 import variants
        v = variants("/x")
        paths = [(m, meth, frozenset(h.items())) for lbl, meth, m, h in v]
        self.assertEqual(len(paths), len(set(paths)))    # no duplicate variants
        # the no-op (plain GET of the path, no headers) is never emitted
        self.assertFalse(any(meth == "GET" and m == "/x" and not h
                             for _, meth, m, h in v))

    def test_variants_drop_useless_fragment(self):
        # a trailing '#' fragment is never sent to the server → useless variant
        from origami.modules.bypass403 import variants
        self.assertFalse(any("#" in m for _, _, m, _ in variants("/admin")))

    def test_char_encode_variants(self):
        # encode a path letter so a WAF regex on the literal word misses; the
        # server still decodes it. Single (%6E) and double (%256E).
        from origami.modules.bypass403 import _char_encode_variants, variants
        paths = {rp for _, rp in _char_encode_variants("/hidden")}
        self.assertIn("/hidde%6E", paths)                   # last char, single-encoded
        self.assertIn("/hidde%256E", paths)                 # last char, double-encoded
        self.assertIn("/%68idden", paths)                   # first char
        self.assertIn("/%68%69%64%64%65%6E", paths)         # whole segment
        # only the last SEGMENT is encoded; the parent dir is preserved
        seg = {rp for _, rp in _char_encode_variants("/admin/secret")}
        self.assertTrue(all(rp.startswith("/admin/") for rp in seg))
        self.assertIn("/admin/secre%74", seg)
        # a trailing-slash directory keeps its slash
        self.assertIn("/hidde%6E/", {rp for _, rp in _char_encode_variants("/hidden/")})
        # wired into variants() under the 'path' family (so it rides light mode too)
        vpaths = {m for _, _, m, _ in variants("/admin")}
        self.assertIn("/admi%6E", vpaths)

    def test_normalization_diff_variants(self):
        # bare-suffix + traversal-resolve tricks that exploit edge-vs-app
        # normalization differences (the video's slash/dot/traversal families).
        from origami.modules.bypass403 import variants, _traversal_resolve_variants
        v = {m for _, _, m, _ in variants("/admin")}
        for want in ("/admin..", "/admin;", "/admin.", "/admin/..",
                     "/admin/%2e/", "/admin.js", "/admin;.json", "/admin.json;"):
            self.assertIn(want, v)
        # traversal that resolves back to the target
        tr = {rp for _, rp in _traversal_resolve_variants("/admin")}
        self.assertIn("/admin/../admin", tr)              # append /../<seg>
        self.assertIn("/x/../admin", tr)                  # prepend bogus dir + up
        self.assertIn("/admin/%252e%252e/admin", tr)      # double-encoded ..
        self.assertTrue(v.issuperset(tr))                 # all wired into variants()

    def test_variants_skip_case_tricks_on_insensitive_host(self):
        # on a case-insensitive (IIS) ACL, upper/swapcase hit the same resource
        from origami.modules.bypass403 import variants
        cs = {m for _, _, m, _ in variants("/AdMin", case_insensitive=False)}
        ci = {m for _, _, m, _ in variants("/AdMin", case_insensitive=True)}
        self.assertIn("/ADMIN", cs)                      # case mutation present when sensitive
        self.assertNotIn("/ADMIN", ci)                   # dropped when insensitive
        self.assertTrue(ci.issubset(cs))                 # ci is strictly a subset

    def test_variants_cover_new_techniques(self):
        from origami.modules.bypass403 import variants
        v = variants("/admin")
        paths = {m for _, _, m, _ in v}
        for expected in ("/./admin", "/admin;/", "/admin/..;/", "/%2e/admin",
                         "/admin%252f", "/admin%5c"):
            self.assertIn(expected, paths)
        self.assertTrue(any(h.get("Referer") for _, _, _, h in v))

    def test_variants_cover_edge_trust_headers(self):
        # targets behind Cloudflare/AWS WAF trust the edge IP headers
        from origami.modules.bypass403 import variants
        hdrs = {k for _, _, _, h in variants("/admin") for k in h}
        for h in ("CF-Connecting-IP", "Cluster-Client-IP", "True-Client-IP",
                  "Forwarded", "X-HTTP-DestinationURL"):
            self.assertIn(h, hdrs)

    def test_confirmed_bypass_lands_in_findings(self):
        # regression: a confirmed 403→200 bypass reuses the blocked URL, which is
        # already in seen_urls — it must SUPERSEDE the 403, not be deduped away.
        import asyncio
        from origami.core import scanner
        from origami.core.scanner import _bypass_fold, ScanResult, ScanOptions
        from origami.core.evidence import TargetProfile
        from origami.core.response_classifier import Finding
        from origami.output.ui import NullObserver

        url403 = "https://h/admin-secret"
        class FakeEngine:
            total_requests = 0
            async def fetch(self, u, method="GET", keep_body=False, headers=None):
                FakeEngine.total_requests += 1
                if u.endswith("/admin-secret/"):                 # the trailing-slash bypass
                    return make_probe(200, b"real admin dashboard content here", url=u)
                return make_probe(404, b"not found", url=u)      # siblings/other variants

        prof = TargetProfile(host="h", base_url="https://h/")
        f = Finding(url403, 403, 20, "text/html", 0.85, "wordlist", tags=["admin"], simhash=12345)
        result = ScanResult(profile=prof, findings=[f])
        result.seen_urls.add(url403); result.seen_urls_lc.add(url403.lower())  # as the live scan would

        streamed = []
        opts = ScanOptions(bypass403=True, finding_sink=streamed.append)
        orig = scanner._confirm
        async def fake_confirm(engine, profile, prefix, probe, origin):
            return Finding(probe.url, probe.status, probe.length, probe.content_type, 0.9, origin)
        scanner._confirm = fake_confirm
        try:
            asyncio.run(_bypass_fold(FakeEngine(), prof, result, opts, NullObserver(), root_simhash=999))
        finally:
            scanner._confirm = orig

        byp = [x for x in result.findings if x.origin == "bypass403"]
        self.assertEqual(len(byp), 1)                     # the bypass is recorded…
        self.assertEqual(byp[0].status, 200)
        self.assertIn("bypass", byp[0].tags)
        self.assertNotIn(f, result.findings)             # …and supersedes the original 403
        self.assertTrue(any(s.origin == "bypass403" for s in streamed))  # and is streamed (JSONL)

    def test_bypass_tech_key_transfers_across_resources(self):
        # cross-resource learning: a technique that works on one 403 must key the
        # same on another so it's fired first there (with the per-resource early-exit).
        from origami.core.scanner import _bypass_tech_key
        # suffix trick: /admin%2f and /users%2f share a key
        self.assertEqual(_bypass_tech_key("/admin", "GET", "/admin%2f", {}),
                         _bypass_tech_key("/users", "GET", "/users%2f", {}))
        # header trick transfers regardless of path
        self.assertEqual(_bypass_tech_key("/admin", "GET", "/admin", {"X-Real-IP": "127.0.0.1"}),
                         _bypass_tech_key("/x", "GET", "/x", {"X-Real-IP": "127.0.0.1"}))
        # different techniques → different keys
        self.assertNotEqual(_bypass_tech_key("/admin", "GET", "/admin%2f", {}),
                            _bypass_tech_key("/admin", "GET", "/admin//", {}))
        self.assertNotEqual(_bypass_tech_key("/admin", "GET", "/admin", {}),
                            _bypass_tech_key("/admin", "POST", "/admin", {}))   # method matters

    def test_variants_hop_by_hop_and_api_prefix(self):
        # advanced families: hop-by-hop (spoof+strip) + API version-prefix + enc-sep
        from origami.modules.bypass403 import variants
        v = variants("/api/v1/admin")
        # potent form: a trusted value SET *and* named in Connection (chain desync)
        self.assertTrue(any(h.get("X-Forwarded-For") == "127.0.0.1"
                            and "X-Forwarded-For" in h.get("Connection", "")
                            for _, _, _, h in v))
        # every Connection variant is well-formed (close, <header>)
        self.assertTrue(all(h["Connection"].startswith("close, ")
                            for _, _, _, h in v if h.get("Connection")))
        paths = {rp for _, _, rp, _ in v}
        self.assertIn("/v1/api/v1/admin", paths)        # API version prefix inserted
        self.assertIn("/v1/admin", paths)               # existing /api segment stripped
        self.assertIn("/api/v1/admin%c0%af", paths)     # encoded (overlong) trailing slash
        self.assertIn("/api/v1%c0%afadmin", paths)      # encoded mid-path slash

    def test_variants_intensity_and_fingerprint_gating(self):
        from origami.modules.bypass403 import variants
        def fams(v): return {l.split()[0] for l, *_ in v}
        p = "/api/v1/admin"
        # light = core only (path/header/method); fewest requests
        self.assertEqual(fams(variants(p, intensity="light")), {"path", "header", "method"})
        # auto with no stack match = core + hop-by-hop (universal), no enc/api
        a0 = fams(variants(p, intensity="auto", encoded=False, api=False))
        self.assertIn("hop-by-hop", a0)
        self.assertNotIn("enc-sep", a0)
        self.assertNotIn("api-prefix", a0)
        # auto gates fire only when the fingerprint says so
        self.assertIn("enc-sep", fams(variants(p, intensity="auto", encoded=True, api=False)))
        self.assertIn("api-prefix", fams(variants(p, intensity="auto", encoded=False, api=True)))
        # full = everything regardless of gates
        full = fams(variants(p, intensity="full", encoded=False, api=False))
        self.assertTrue({"enc-sep", "api-prefix", "hop-by-hop"} <= full)
        # auto-trim is real: light < auto-core < full
        self.assertLess(len(variants(p, intensity="light")),
                        len(variants(p, intensity="full")))

    def test_select_bypass_targets_caps_per_wall(self):
        from origami.core.scanner import _select_bypass_targets, BYPASS_PER_WALL
        from origami.core.response_classifier import Finding
        # 10 .env* paths = one wall (same status+simhash); plus two distinct 403s
        wall = [Finding(f"https://h/.env.{i}", 403, 199, "", 0.85, "wordlist",
                        tags=["disclosure"], simhash=111) for i in range(10)]
        distinct = [Finding("https://h/admin", 403, 50, "", 0.85, "wordlist", simhash=222),
                    Finding("https://h/web.config", 403, 60, "", 0.85, "wordlist", simhash=333)]
        targets, skipped = _select_bypass_targets(wall + distinct)
        # at most BYPASS_PER_WALL from the wall, but both distinct 403s kept
        wall_kept = [t for t in targets if t.simhash == 111]
        self.assertLessEqual(len(wall_kept), BYPASS_PER_WALL)
        self.assertEqual(skipped, 10 - len(wall_kept))
        urls = {t.url for t in targets}
        self.assertIn("https://h/admin", urls)
        self.assertIn("https://h/web.config", urls)

    def test_matrix_management_bypass_gated_and_targeted(self):
        from origami.modules import bypass403 as b
        # management path detection
        self.assertTrue(b.is_management_path("/actuator/env"))
        self.assertTrue(b.is_management_path("/jolokia/list"))
        self.assertFalse(b.is_management_path("/admin"))
        # OFF by default — never inflates an ordinary 403's budget
        self.assertFalse(any("matrix-bypass" in l for l, *_ in b.variants("/actuator/env")))
        # ON when gated: emits the mapped-route + `;/` forms, incl. discovered routes
        got = {rp for (l, m, rp, h) in b.variants(
            "/actuator/env", mgmt=True, route_prefixes=("dashboard",)) if "matrix-bypass" in l}
        self.assertIn("/;/actuator/env", got)              # bare-root form
        self.assertIn("/rest/v1/;/actuator/env", got)      # curated Spring guess
        self.assertIn("/dashboard/;/actuator/env", got)    # a real 2xx route we found
        # discovered routes ALSO feed the api-prefix family (not just static seeds)
        api = {rp for (l, m, rp, h) in b.variants(
            "/admin", api=True, route_prefixes=("gateway",)) if l.startswith("api-prefix")}
        self.assertIn("/gateway/admin", api)

    def test_load_prefixes_parses_and_dedups(self):
        import tempfile, os
        from origami.modules import bypass403 as b
        fd, path = tempfile.mkstemp(suffix=".txt")
        os.write(fd, b"# routes\nrest/v1\n/gateway/\nrest/v1\n\n  services/api  \n")
        os.close(fd)
        try:
            self.assertEqual(b.load_prefixes(path), ("rest/v1", "gateway", "services/api"))
        finally:
            os.unlink(path)
        self.assertEqual(b.load_prefixes("/no/such/file"), ())

    def test_discovered_route_prefixes_skips_files_and_mgmt(self):
        from origami.core.scanner import _discovered_route_prefixes
        from origami.core.response_classifier import Finding
        fs = [Finding("https://h/rest/v1", 200, 10, "", 0.9, "wordlist"),
              Finding("https://h/app.js", 200, 10, "", 0.9, "wordlist"),      # file → skip
              Finding("https://h/actuator", 200, 10, "", 0.9, "wordlist"),    # mgmt → skip
              Finding("https://h/admin", 403, 10, "", 0.9, "wordlist")]       # non-2xx → skip
        self.assertEqual(_discovered_route_prefixes(fs), ("rest/v1",))


class TestFeroxParity(unittest.TestCase):
    """--time-limit, body filters, replay-proxy, stdin (the feroxbuster-parity set)."""

    def test_over_budget_requests_and_time(self):
        import types, time
        from origami.core.scanner import _over_budget, ScanOptions
        eng = types.SimpleNamespace(spent=5, deadline=None)
        self.assertFalse(_over_budget(eng, ScanOptions()))
        self.assertTrue(_over_budget(eng, ScanOptions(max_requests=5)))       # request cap
        past = types.SimpleNamespace(spent=0, deadline=time.monotonic() - 1)
        self.assertTrue(_over_budget(past, ScanOptions(time_limit=1)))        # deadline passed
        future = types.SimpleNamespace(spent=0, deadline=time.monotonic() + 100)
        self.assertFalse(_over_budget(future, ScanOptions()))

    def test_filters_body_word_line_regex_similar(self):
        import re
        f = Filters(filter_words={3})
        self.assertFalse(f.accept_body(b"a b c"))        # 3 words → drop
        self.assertTrue(f.accept_body(b"a b c d"))
        self.assertFalse(Filters(filter_lines={2}).accept_body(b"x\ny"))
        rf = Filters(filter_regex=re.compile("secret"))
        self.assertFalse(rf.accept_body(b"has secret here"))
        self.assertTrue(rf.accept_body(b"clean body"))
        # similar-to fires on simhash alone — no body needed
        sf = Filters(similar_hashes=(123,), similar_distance=0)
        self.assertFalse(sf.accept_body(None, simhash=123))
        self.assertTrue(sf.accept_body(None, simhash=~123 & 0xFFFFFFFF))
        self.assertTrue(Filters().accept_body(None))     # no filters → accept
        self.assertFalse(Filters().has_body_filters())
        self.assertTrue(Filters(filter_words={1}).has_body_filters())
        # precomputed counts (from the probe) filter with NO body — the refinement
        # that lets word/line/similar work on every finding, not just kept-body ones.
        self.assertFalse(Filters(filter_words={5}).accept_body(None, words=5))
        self.assertFalse(Filters(filter_lines={9}).accept_body(None, lines=9))
        self.assertTrue(Filters(filter_words={5}).accept_body(None, words=6))
        # only regex needs the raw body
        self.assertFalse(Filters(filter_words={1}).needs_body())
        self.assertTrue(Filters(filter_regex=re.compile("x")).needs_body())

    def test_parse_duration(self):
        from origami.cli import _parse_duration
        self.assertEqual(_parse_duration("30s"), 30.0)
        self.assertEqual(_parse_duration("10m"), 600.0)
        self.assertEqual(_parse_duration("1h"), 3600.0)
        self.assertEqual(_parse_duration("90"), 90.0)
        self.assertEqual(_parse_duration(None), 0.0)
        with self.assertRaises(SystemExit):
            _parse_duration("nope")

    def test_read_url_lines_skips_comments_and_blanks(self):
        from origami.cli import _read_url_lines
        self.assertEqual(_read_url_lines("http://a\n# note\n\n  http://b \n"),
                         ["http://a", "http://b"])

    def test_replay_findings_filters_by_code(self):
        import asyncio, types
        from origami.core.scanner import _replay_findings, ScanOptions
        from origami.core.response_classifier import Finding
        from origami.output.ui import NullObserver
        sent = []

        class FakeClient:
            async def get(self, url): sent.append(url)
            async def aclose(self): pass

        class FakeEngine:
            def replay_client(self, proxy): return FakeClient()

        res = types.SimpleNamespace(findings=[
            Finding("https://h/a", 200, 1, "", 0.9, "wordlist"),
            Finding("https://h/b", 403, 1, "", 0.9, "wordlist")])
        opts = ScanOptions(replay_proxy="http://127.0.0.1:8080", replay_codes=(200,))
        asyncio.run(_replay_findings(FakeEngine(), res, opts, NullObserver()))
        self.assertEqual(sent, ["https://h/a"])          # only the 200 replayed

    def test_replay_bad_proxy_does_not_crash(self):
        import asyncio, types
        from origami.core.scanner import _replay_findings, ScanOptions
        from origami.core.response_classifier import Finding
        from origami.output.ui import NullObserver

        class FakeEngine:
            def replay_client(self, proxy):
                raise ValueError("invalid proxy URL")   # httpx rejects at construction

        res = types.SimpleNamespace(findings=[Finding("https://h/a", 200, 1, "", 0.9, "wordlist")])
        opts = ScanOptions(replay_proxy="127.0.0.1:8080")   # missing scheme
        # must return cleanly, not raise — the whole scan can't die on a bad proxy
        asyncio.run(_replay_findings(FakeEngine(), res, opts, NullObserver()))

    def test_int_set_rejects_non_numeric(self):
        from origami.cli import _int_set
        self.assertEqual(_int_set("200,301"), {200, 301})
        self.assertIsNone(_int_set(None))
        with self.assertRaises(SystemExit):
            _int_set("200,foo")


class TestLegacyTLS(unittest.TestCase):
    """Weak-DH / legacy-cipher servers: detect the handshake error, drop SECLEVEL."""

    def test_looks_weak_tls_matches_dh_and_handshake(self):
        from origami.core.httpclient import _looks_weak_tls
        self.assertTrue(_looks_weak_tls("ConnectError: [SSL: DH_KEY_TOO_SMALL] dh key too small"))
        self.assertTrue(_looks_weak_tls("SSLError: [SSL: SSLV3_ALERT_HANDSHAKE_FAILURE]"))
        self.assertTrue(_looks_weak_tls("SSLError: unsafe legacy renegotiation disabled"))
        # NOT a security-level issue → don't lower TLS for these
        self.assertFalse(_looks_weak_tls("ConnectTimeout: timed out"))
        self.assertFalse(_looks_weak_tls("ConnectError: [Errno 111] Connection refused"))
        self.assertFalse(_looks_weak_tls("SSLError: CERTIFICATE_VERIFY_FAILED"))  # cert, handled by -k

    def test_legacy_ssl_context_lowers_security(self):
        import ssl
        from origami.core.httpclient import _legacy_ssl_context
        ctx = _legacy_ssl_context(verify=False)
        self.assertIsInstance(ctx, ssl.SSLContext)
        self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)      # verify off → no cert check
        self.assertFalse(ctx.check_hostname)
        ctx2 = _legacy_ssl_context(verify=True)
        self.assertEqual(ctx2.verify_mode, ssl.CERT_REQUIRED)  # verify on → cert still checked


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
        self.assertEqual(pf.reflected_in_location("", tm), [])
        # a canary in an X- header is a lead; the same canary in Location is NOT
        # double-counted here (Location is handled by reflected_in_location)
        self.assertEqual(pf.reflected_in_headers({"x-foo": "oz1q", "location": "oz0q"}, tm),
                         {"x": "x-foo"})


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


class TestOriginIP(unittest.TestCase):
    """Origin-IP discovery: DNS + crt.sh/keyed OSINT parsing + target gating."""

    def test_parse_crtsh_multiline_wildcard_and_domain_filter(self):
        import json
        from origami.modules.discovery import originip as o
        blob = json.dumps([{"name_value": "*.example.com\napi.example.com"},
                           {"name_value": "origin.example.com"},
                           {"name_value": "other.org"}])          # different domain → excluded
        self.assertEqual(o.parse_crtsh(blob, "example.com"),
                         {"example.com", "api.example.com", "origin.example.com"})
        self.assertEqual(o.parse_crtsh("not json", "x"), set())   # robust to junk

    def test_parse_keyed_sources(self):
        import json
        from origami.modules.discovery import originip as o
        self.assertEqual(o.parse_shodan(json.dumps({"matches": [{"ip_str": "1.2.3.4"}]})), {"1.2.3.4"})
        self.assertEqual(o.parse_securitytrails(
            json.dumps({"records": [{"values": [{"ip": "9.9.9.9"}]}]})), {"9.9.9.9"})
        self.assertEqual(o.parse_censys(
            json.dumps({"result": {"hits": [{"ip": "8.8.8.8"}]}})), {"8.8.8.8"})
        self.assertEqual(o.parse_shodan(""), set())               # robust to junk

    def test_has_registrable_domain_gates_ip_and_local(self):
        from origami.modules.discovery import originip as o
        self.assertFalse(o.has_registrable_domain("127.0.0.1"))   # IPv4 literal
        self.assertFalse(o.has_registrable_domain("::1"))         # IPv6 literal
        self.assertFalse(o.has_registrable_domain("localhost"))
        self.assertTrue(o.has_registrable_domain("sub.example.com"))

    def test_configured_sources_reads_env(self):
        import os, tempfile
        from origami.modules.discovery import originip as o
        from origami.core import credentials
        names = ("SHODAN_API_KEY", "SECURITYTRAILS_API_KEY", "CENSYS_API_ID",
                 "CENSYS_API_SECRET", "XDG_CONFIG_HOME")
        saved = {k: os.environ.pop(k, None) for k in names}
        with tempfile.TemporaryDirectory() as d:
            os.environ["XDG_CONFIG_HOME"] = d          # hermetic: no real credentials file
            credentials._reset_cache_for_tests()
            try:
                self.assertEqual(o.configured_sources(), [])
                os.environ["SHODAN_API_KEY"] = "k"
                self.assertEqual(o.configured_sources(), ["shodan"])
                os.environ["CENSYS_API_ID"] = "a"      # id without secret → not counted
                self.assertEqual(o.configured_sources(), ["shodan"])
            finally:
                for k, v in saved.items():
                    if v is not None:
                        os.environ[k] = v
                    else:
                        os.environ.pop(k, None)
                credentials._reset_cache_for_tests()

    def test_candidate_ips_skips_osint_for_ip_target(self):
        import asyncio
        from origami.modules.discovery import originip as o
        # an IP/local target has no CT/OSINT footprint → returns instantly, no network
        ips, src = asyncio.run(o.candidate_origin_ips("127.0.0.1"))
        self.assertEqual(ips, [])
        self.assertIn("n/a", src)

    def test_resolve_ips_localhost(self):
        import asyncio
        from origami.modules.discovery import originip as o
        self.assertIn("127.0.0.1", asyncio.run(o.resolve_ips("localhost")))

    def test_origin_serve_rule_rejects_404_and_edge(self):
        from origami.core.scanner import _is_origin_serve
        # the reported bug: a sibling IP's 404 page must NOT be a "possible origin"
        self.assertFalse(_is_origin_serve(404, 581, edge_ip=False))
        self.assertFalse(_is_origin_serve(403, 200, edge_ip=False))   # blocked ≠ origin
        self.assertFalse(_is_origin_serve(301, 0, edge_ip=False))     # redirect/empty
        self.assertFalse(_is_origin_serve(200, 500, edge_ip=True))    # the edge itself
        self.assertFalse(_is_origin_serve(200, 0, edge_ip=False))     # 2xx but empty body
        # a non-edge IP serving 2xx with a body for the target Host → real lead
        self.assertTrue(_is_origin_serve(200, 1200, edge_ip=False))
        self.assertTrue(_is_origin_serve(204, 1, edge_ip=False))

    def test_credentials_scaffold_creates_private_file(self):
        import os, stat, tempfile
        from origami.core import credentials
        saved = os.environ.pop("XDG_CONFIG_HOME", None)
        with tempfile.TemporaryDirectory() as d:
            os.environ["XDG_CONFIG_HOME"] = d
            credentials._reset_cache_for_tests()
            try:
                path, created = credentials.scaffold()
                self.assertTrue(created and path.exists())
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)   # private by construction
                self.assertIn("[shodan]", path.read_text())
                _, created2 = credentials.scaffold()                         # idempotent
                self.assertFalse(created2)
            finally:
                if saved is not None:
                    os.environ["XDG_CONFIG_HOME"] = saved
                else:
                    os.environ.pop("XDG_CONFIG_HOME", None)
                credentials._reset_cache_for_tests()

    def test_credentials_env_then_file_precedence(self):
        import os, tempfile
        from pathlib import Path
        from origami.core import credentials
        saved = {k: os.environ.pop(k, None) for k in ("SHODAN_API_KEY", "XDG_CONFIG_HOME")}
        with tempfile.TemporaryDirectory() as d:
            os.environ["XDG_CONFIG_HOME"] = d
            cfgdir = Path(d) / "origami"
            cfgdir.mkdir(parents=True)
            (cfgdir / "credentials.toml").write_text(
                '[shodan]\napi_key = "from-file"\n[censys]\napi_id = "cid"\napi_secret = "csec"\n')
            credentials._reset_cache_for_tests()
            try:
                self.assertEqual(credentials.config_path(), cfgdir / "credentials.toml")
                self.assertEqual(credentials.get("SHODAN_API_KEY"), "from-file")   # from file
                self.assertEqual(credentials.get("CENSYS_API_SECRET"), "csec")
                self.assertIsNone(credentials.get("SECURITYTRAILS_API_KEY"))       # unset → None
                os.environ["SHODAN_API_KEY"] = "from-env"
                self.assertEqual(credentials.get("SHODAN_API_KEY"), "from-env")    # env wins
            finally:
                for k, v in saved.items():
                    if v is not None:
                        os.environ[k] = v
                    else:
                        os.environ.pop(k, None)
                credentials._reset_cache_for_tests()


class TestBypassHeaderWordlist(unittest.TestCase):
    def test_load_header_pairs_parses_both_forms(self):
        import tempfile, os
        from origami.modules.bypass403 import load_header_pairs
        body = ("# comment\n\n"
                "X-Forwarded-For: 127.0.0.1\n"
                "Forwarded: for=127.0.0.1;host=localhost\n"   # colon, value has more colons/semis
                "X-Forwarded-Port 443\n"                       # space form, no colon
                "Referer /admin\n")
        fd, p = tempfile.mkstemp(suffix=".txt"); os.write(fd, body.encode()); os.close(fd)
        try:
            pairs = load_header_pairs(p)
        finally:
            os.unlink(p)
        self.assertIn(("X-Forwarded-For", "127.0.0.1"), pairs)
        self.assertIn(("Forwarded", "for=127.0.0.1;host=localhost"), pairs)
        self.assertIn(("X-Forwarded-Port", "443"), pairs)
        self.assertIn(("Referer", "/admin"), pairs)

    def test_load_header_pairs_space_form_with_colon_value(self):
        # a space-form line whose VALUE contains a colon must split on the space,
        # not the colon — else the header name would carry an (illegal) space
        import tempfile, os
        from origami.modules.bypass403 import load_header_pairs
        fd, p = tempfile.mkstemp(suffix=".txt")
        os.write(fd, b"X-Forwarded-Host localhost:8080\nBase-Url: 127.0.0.1:443\n"); os.close(fd)
        try:
            pairs = load_header_pairs(p)
        finally:
            os.unlink(p)
        self.assertIn(("X-Forwarded-Host", "localhost:8080"), pairs)   # space-split
        self.assertIn(("Base-Url", "127.0.0.1:443"), pairs)            # colon-split
        self.assertFalse(any(" " in n for n, _ in pairs))              # no name has a space

    def test_load_header_pairs_dedups_by_lowered_name(self):
        import tempfile, os
        from origami.modules.bypass403 import load_header_pairs
        # case-variant header names with the same value are one request on the wire
        fd, p = tempfile.mkstemp(suffix=".txt")
        os.write(fd, b"X-Real-IP: 127.0.0.1\nX-Real-Ip: 127.0.0.1\n"); os.close(fd)
        try:
            pairs = load_header_pairs(p)
        finally:
            os.unlink(p)
        self.assertEqual(len(pairs), 1)

    def test_load_header_pairs_missing_file(self):
        from origami.modules.bypass403 import load_header_pairs
        self.assertEqual(load_header_pairs("/no/such/wordlist.txt"), [])

    def test_bundled_wordlist_loads(self):
        from origami.modules.bypass403 import load_header_pairs, DEFAULT_HEADER_WORDLIST
        self.assertTrue(DEFAULT_HEADER_WORDLIST.exists())
        pairs = load_header_pairs()
        self.assertGreater(len(pairs), 100)             # the bundled list is large

    def test_variants_header_pairs_replace_builtin_axis(self):
        from origami.modules.bypass403 import variants
        v = variants("/admin", header_pairs=[("Z-Custom", "9.9.9.9")])
        hdr_keys = {k for _, _, _, h in v for k in h}
        self.assertIn("Z-Custom", hdr_keys)
        self.assertNotIn("CF-Connecting-IP", hdr_keys)  # built-in IP axis swapped out
        # path + method tricks are still present
        self.assertTrue(any(m == "/admin/" for _, _, m, _ in v))
        self.assertTrue(any(meth == "POST" for _, meth, _, _ in v))

    def test_variants_no_pairs_keeps_builtins(self):
        from origami.modules.bypass403 import variants
        hdr_keys = {k for _, _, _, h in variants("/admin") for k in h}
        self.assertIn("CF-Connecting-IP", hdr_keys)


class TestOpenApiIngest(unittest.TestCase):
    def _run(self, coro):
        import asyncio
        return asyncio.run(coro)

    def _spec_file(self, payload):
        import tempfile, os, json
        fd, p = tempfile.mkstemp(suffix=".json"); os.write(fd, json.dumps(payload).encode()); os.close(fd)
        return p

    def test_ingest_openapi_file(self):
        import os
        from origami.modules.discovery import apidocs
        p = self._spec_file({"openapi": "3.0.0", "servers": [{"url": "/api/v1"}],
                             "paths": {"/users/{id}": {}, "/admin/secret": {}}})
        try:
            label, eps = self._run(apidocs.ingest_source(None, p))
        finally:
            os.unlink(p)
        self.assertEqual(label, p)
        self.assertIn("/api/v1/admin/secret", eps)
        self.assertIn("/api/v1/users/", eps)            # templated → static dir

    def test_ingest_jsonapi_file(self):
        import os
        from origami.modules.discovery import apidocs
        p = self._spec_file({"jsonapi": {"version": "1.0"},
                             "links": {"articles": "https://h/jsonapi/node/article",
                                       "users": {"href": "/jsonapi/user/user"}}})
        try:
            _, eps = self._run(apidocs.ingest_source(None, p))
        finally:
            os.unlink(p)
        self.assertIn("/jsonapi/node/article", eps)
        self.assertIn("/jsonapi/user/user", eps)

    def test_ingest_missing_and_nonspec(self):
        import os
        from origami.modules.discovery import apidocs
        self.assertEqual(self._run(apidocs.ingest_source(None, "/no/such.json")), (None, set()))
        p = self._spec_file({"hello": "world"})
        try:
            self.assertEqual(self._run(apidocs.ingest_source(None, p)), (None, set()))
        finally:
            os.unlink(p)


class TestSitemapIndex(unittest.TestCase):
    def test_follows_nested_sitemapindex(self):
        import asyncio
        from origami.core.httpclient import Probe
        from origami.modules.discovery import robots
        routes = {
            "/robots.txt": (200, b"User-agent: *\nDisallow: /admin/\n"
                                 b"Sitemap: http://h/sitemap.xml\n"),
            "/sitemap.xml": (200, b"<sitemapindex><sitemap><loc>http://h/sm-1.xml"
                                  b"</loc></sitemap></sitemapindex>"),
            "/sm-1.xml": (200, b"<urlset><url><loc>http://h/products/item-42</loc></url>"
                               b"<url><loc>/secret-page</loc></url></urlset>"),
        }

        class E:
            async def fetch(self, url, method="GET", keep_body=False, **kw):
                from urllib.parse import urlparse
                st, body = routes.get(urlparse(url).path, (404, b""))
                return Probe(url, method, st, len(body), 0, 0, "", "", 0, 0.0,
                             body_head=body[:2048], body=body)

        paths = asyncio.run(robots.harvest(E(), "http://h/"))
        self.assertIn("/products/item-42", paths)   # content from the CHILD sitemap
        self.assertIn("/secret-page", paths)         # (the index was followed)
        self.assertIn("/admin/", paths)              # robots Disallow


class TestMethods(unittest.TestCase):
    def test_parse_allow_flags_dangerous(self):
        from origami.modules.discovery.methods import parse_allow
        methods, danger = parse_allow("GET, POST, PUT, DELETE, options, TRACE")
        self.assertEqual(methods, ["DELETE", "GET", "OPTIONS", "POST", "PUT", "TRACE"])
        self.assertEqual(danger, ["DELETE", "PUT", "TRACE"])

    def test_parse_allow_safe_set(self):
        from origami.modules.discovery.methods import parse_allow
        _, danger = parse_allow("GET, HEAD, POST, OPTIONS")
        self.assertEqual(danger, [])
        self.assertEqual(parse_allow("")[1], [])

    def test_webdav_flagged(self):
        from origami.modules.discovery.methods import parse_allow
        _, danger = parse_allow("GET, PROPFIND, MKCOL, MOVE")
        self.assertEqual(danger, ["MKCOL", "MOVE", "PROPFIND"])


class TestHeaderHarvest(unittest.TestCase):
    def test_extract_from_csp_and_link(self):
        from origami.modules.discovery.js_parser import extract_header_paths
        headers = {
            "content-security-policy":
                "default-src 'self'; connect-src 'self' https://h/api/graphql "
                "https://evil.cdn/x; form-action /auth/submit",
            "link": "</assets/app.js>; rel=preload, </style.css>; rel=preload, "
                    "<https://h/api/config>; rel=preconnect",
        }
        out = extract_header_paths(headers, "https://h/")
        self.assertIn("/api/graphql", out)        # CSP connect-src, same host
        self.assertIn("/auth/submit", out)        # CSP form-action, root-absolute
        self.assertIn("/api/config", out)         # Link same-host absolute
        self.assertIn("/assets/app.js", out)      # Link preload (js kept)
        self.assertNotIn("/x", out)               # cross-host origin dropped
        self.assertNotIn("/style.css", out)       # pure asset dropped


class TestGraphQL(unittest.TestCase):
    def test_extract_fields_skips_meta(self):
        from origami.modules.discovery import graphql
        doc = {"data": {"__schema": {"types": [
            {"name": "Query", "fields": [{"name": "secretUser"}, {"name": "allInvoices"}]},
            {"name": "__Type", "fields": [{"name": "name"}, {"name": "kind"}]},
        ]}}}
        fields = graphql.extract_fields(doc)
        self.assertEqual(fields, {"secretUser", "allInvoices"})   # meta type/fields skipped
        self.assertTrue(graphql._is_schema(doc))
        self.assertFalse(graphql._is_schema({"data": {}}))

    def test_analyze_schema_args_ops_sensitive(self):
        from origami.modules.discovery import graphql
        doc = {"data": {"__schema": {
            "queryType": {"name": "Query"}, "mutationType": {"name": "Mutation"},
            "types": [
                {"name": "Query", "fields": [
                    {"name": "carteira", "args": [{"name": "id"}]},
                    {"name": "listCities", "args": []}]},
                {"name": "Mutation", "fields": [
                    {"name": "beneficiarioRedefinirSenha", "args": [{"name": "token"}]}]},
                {"name": "__Type", "fields": [{"name": "name"}]},   # meta → skipped
            ]}}}
        m = graphql.analyze_schema(doc)
        self.assertEqual(set(m["queries"]), {"carteira", "listCities"})
        self.assertEqual(m["mutations"], ["beneficiarioRedefinirSenha"])
        self.assertEqual(m["args"], {"id", "token"})
        # sensitive spans queries AND mutations (senha/redefinir, carteira)
        self.assertIn("beneficiarioRedefinirSenha", m["sensitive"])
        self.assertIn("carteira", m["sensitive"])
        self.assertNotIn("listCities", m["sensitive"])

    def test_build_probe_query_is_benign(self):
        from origami.modules.discovery import graphql
        q = graphql.build_probe_query("carteira")
        self.assertEqual(q, "{__typename carteira}")   # no args, no sub-selection, no mutation

    def test_classify_probe_open_auth_reachable(self):
        import json
        from origami.modules.discovery import graphql
        # data returned without auth → open
        self.assertEqual(graphql.classify_probe(200, json.dumps({"data": {"carteira": {"x": 1}}}).encode()), "open")
        # explicit auth error / 401 → auth
        self.assertEqual(graphql.classify_probe(401, b""), "auth")
        self.assertEqual(graphql.classify_probe(200, json.dumps(
            {"errors": [{"message": "Not authorized"}]}).encode()), "auth")
        # validation error (needs args) → reachable (past the gate)
        self.assertEqual(graphql.classify_probe(200, json.dumps(
            {"errors": [{"message": "Field 'carteira' argument 'id' of type 'ID!' is required"}]}).encode()),
            "reachable")
        # data: null, no error → reachable
        self.assertEqual(graphql.classify_probe(200, json.dumps({"data": {"carteira": None}}).encode()), "reachable")


class TestWellKnown(unittest.TestCase):
    def test_extract_oidc_endpoints_same_host(self):
        from origami.modules.discovery import wellknown
        doc = {"issuer": "https://h",
               "authorization_endpoint": "https://h/oauth2/authorize",
               "token_endpoint": "/oauth2/token",
               "jwks_uri": "https://h/oauth2/jwks.json?v=1",
               "userinfo_endpoint": "https://idp.OTHER/userinfo",   # cross-host → dropped
               "grant_types_supported": ["code"]}                   # not an endpoint key
        eps = wellknown.extract_oidc_endpoints(doc, "h")
        self.assertIn("/oauth2/authorize", eps)
        self.assertIn("/oauth2/token", eps)
        self.assertIn("/oauth2/jwks.json", eps)            # query stripped
        self.assertNotIn("/userinfo", eps)                 # cross-host excluded


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


class TestLiveProgress(unittest.TestCase):
    def _ui(self):
        try:
            from origami.output.ui import RichUI
        except Exception:
            self.skipTest("rich not available")
        return RichUI("http://x")

    def test_setup_phase_is_indeterminate_then_fills(self):
        ui = self._ui()
        ui.phase("fingerprint")
        self.assertIsNone(ui._progress.tasks[0].total)   # pulse, not a stuck 0/1
        ui.phase("js-harvest")
        self.assertIsNone(ui._progress.tasks[0].total)
        ui.progress(3, 10)                                # fold reports → fills
        task = ui._progress.tasks[0]
        self.assertEqual(task.completed, 3)
        self.assertEqual(task.total, 10)
        ui.progress(40, 40)
        self.assertEqual(ui._progress.tasks[0].completed, 40)

    def test_substep_sets_label_and_step_bar(self):
        ui = self._ui()
        ui.phase("recon")
        ui.substep("apidocs", 4, 7)
        self.assertEqual(ui.substep_name, "apidocs")        # status-bar sub-label
        task = ui._progress.tasks[0]
        self.assertEqual(task.completed, 4)                  # bar = step k/total
        self.assertEqual(task.total, 7)
        ui.phase("scan")
        self.assertEqual(ui.substep_name, "")                # cleared on new phase

    def test_count_column_blank_when_indeterminate(self):
        from origami.output.ui import _CountColumn
        ui = self._ui()
        ui.phase("calibrate")
        col = _CountColumn().render(ui._progress.tasks[0])
        self.assertEqual(str(col), "")                    # no "0/1"
        ui.start_prefix("/admin/", 50)
        self.assertIn("/", str(_CountColumn().render(ui._progress.tasks[0])))

    def test_highlights_surface_high_value(self):
        from origami.core.response_classifier import Finding
        ui = self._ui()
        ui.findings = [Finding("u1", 200, 1, "", 0.9, "js", tags=["disclosure", "config"]),
                       Finding("u2", 200, 1, "", 0.9, "bypass403", tags=["admin"]),
                       Finding("u3", 200, 1, "", 0.7, "methods", tags=["config"])]
        h = ui._highlights()
        self.assertIn("disclosure", h)
        self.assertIn("403-bypass", h)
        self.assertIn("dangerous-methods", h)
        self.assertIn("config", h)
        self.assertEqual(self._ui()._highlights(), "")   # empty when no findings

    def test_dynamic_dashboard_rerenders(self):
        from origami.output.ui import _LiveDashboard
        ui = self._ui()
        dash = _LiveDashboard(ui)
        self.assertIsNotNone(dash.__rich__())     # rebuilds the renderable each call
        self.assertIsNotNone(dash.__rich__())


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


class TestRecallNames(unittest.TestCase):
    def test_recall_names_cross_target(self):
        import tempfile
        from pathlib import Path
        from origami.brain.memory import Memory
        from origami.core.scanner import ScanResult
        from origami.core.evidence import TargetProfile
        from origami.core.response_classifier import Finding
        with tempfile.TemporaryDirectory() as d:
            m = Memory(Path(d) / "m.sqlite")
            # names must appear on >=2 DISTINCT hosts to be recalled (freq floor)
            for host in ("a", "b"):
                p = TargetProfile(host=host, base_url=f"http://{host}/")
                r = ScanResult(profile=p, findings=[
                    Finding(f"http://{host}/Administration.aspx", 200, 1, "", 0.9, "x"),
                    Finding(f"http://{host}/painel_novo/", 301, 1, "", 0.85, "x")])
                m.record_run(p, r)
            names = m.recall_names()
            self.assertIn("administration", names)   # stem, lowercased
            self.assertIn("painel_novo", names)       # dir basename
            m.close()

    def test_recall_names_freq_floor_and_hash(self):
        import tempfile
        from pathlib import Path
        from origami.brain.memory import Memory
        with tempfile.TemporaryDirectory() as d:
            m = Memory(Path(d) / "m.sqlite")
            # 'shared' on 2 hosts, 'oneoff' on 1, a hashed bundle on 2
            m.db.execute("INSERT INTO corpus VALUES ('h1','/shared.aspx',200)")
            m.db.execute("INSERT INTO corpus VALUES ('h2','/shared.aspx',200)")
            m.db.execute("INSERT INTO corpus VALUES ('h1','/oneoff.aspx',200)")
            # hyphen-delimited hash passes the alnum guard → must be caught by _is_noise
            m.db.execute("INSERT INTO corpus VALUES ('h1','/application-0912i831283.js',200)")
            m.db.execute("INSERT INTO corpus VALUES ('h2','/application-0912i831283.js',200)")
            m.db.commit()
            names = m.recall_names()
            self.assertIn("shared", names)            # >=2 hosts → recalled
            self.assertNotIn("oneoff", names)         # 1 host → below the floor
            # hashed bundle never feeds the n-gram (even on >=2 hosts)
            self.assertNotIn("application-0912i831283", names)
            m.close()


class TestMemoryHygiene(unittest.TestCase):
    def _mem(self, d):
        from pathlib import Path
        from origami.brain.memory import Memory
        return Memory(Path(d) / "m.sqlite")

    def _record(self, m, host, paths):
        from origami.core.scanner import ScanResult
        from origami.core.evidence import TargetProfile
        from origami.core.response_classifier import Finding
        p = TargetProfile(host=host, base_url=f"https://{host}/")
        r = ScanResult(profile=p, findings=[Finding(f"https://{host}{pp}", 200, 1, "", 0.9, "x")
                                            for pp in paths])
        m.record_run(p, r)

    def test_www_apex_share_one_key(self):
        # a scan of www.x.com must be visible/transferable as x.com (and vice versa)
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            m = self._mem(d)
            self._record(m, "www.acme.com", ["/admin/", "/api/v2/users"])
            self.assertEqual({p for p, _ in m.prior_findings("acme.com")},
                             {"/admin/", "/api/v2/users"})        # apex sees www data
            self.assertTrue(m.prior_findings("www.acme.com"))      # and www sees its own
            m.close()

    def test_forget_one_host_and_all(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            m = self._mem(d)
            self._record(m, "a.com", ["/x"])
            self._record(m, "b.com", ["/y"])
            removed = m.forget("www.a.com")                       # normalized → a.com
            self.assertEqual(removed, 1)
            self.assertEqual(m.prior_findings("a.com"), [])
            self.assertTrue(m.prior_findings("b.com"))            # other host untouched
            m.forget(None)                                        # wipe all
            self.assertEqual(m.prior_findings("b.com"), [])
            m.close()


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

    def test_associate_skips_ambient_paths(self):
        import os, tempfile
        from origami.brain.memory import Memory
        db = tempfile.mktemp(suffix=".sqlite")
        m = Memory(db)
        try:
            # every backup host also has /favicon.ico — ambient, must not be suggested
            for h in ("h1", "h2", "h3"):
                for p in ("/backup/", "/.git/HEAD", "/favicon.ico"):
                    m.db.execute("INSERT OR REPLACE INTO corpus VALUES (?,?,?)", (h, p, 200))
            m.db.commit()
            assoc = m.associate(["/backup/"], min_support=2, min_conf=0.5)
            self.assertIn("/.git/HEAD", assoc)
            self.assertNotIn("/favicon.ico", assoc)   # ambient filtered out
        finally:
            m.close()
            os.unlink(db)

    def test_associate_skips_static_assets(self):
        # the real-target noise: a host-local image co-occurs with /backup/ but
        # carries no cross-target signal — it must never be suggested as a rule
        import os, tempfile
        from origami.brain.memory import Memory
        db = tempfile.mktemp(suffix=".sqlite")
        m = Memory(db)
        try:
            for h in ("h1", "h2", "h3"):
                for p in ("/backup/", "/.git/HEAD", "/img/bkg_mobile_02.jpg", "/fonts/x.woff2"):
                    m.db.execute("INSERT OR REPLACE INTO corpus VALUES (?,?,?)", (h, p, 200))
            m.db.commit()
            assoc = m.associate(["/backup/"], min_support=2, min_conf=0.5)
            self.assertIn("/.git/HEAD", assoc)
            self.assertNotIn("/img/bkg_mobile_02.jpg", assoc)   # image filtered out
            self.assertNotIn("/fonts/x.woff2", assoc)            # font filtered out
        finally:
            m.close()
            os.unlink(db)

    def test_record_run_excludes_assets_from_corpus(self):
        # static assets must not even enter the corpus (no future pollution)
        import os, tempfile
        from origami.brain.memory import Memory
        from origami.core.evidence import TargetProfile
        class R:
            def __init__(self, findings): self.findings = findings; self.requests_made = 5
        db = tempfile.mktemp(suffix=".sqlite")
        m = Memory(db)
        try:
            p = TargetProfile(host="h", base_url="http://h/")
            m.record_run(p, R([make_finding("http://h/admin/", 200),
                               make_finding("http://h/logo.png", 200),
                               make_finding("http://h/app.css", 200)]))
            paths = {row[0] for row in m.db.execute("SELECT path FROM corpus")}
            self.assertIn("/admin/", paths)
            self.assertIn("/app.css", paths)           # css kept (shared names transfer)
            self.assertNotIn("/logo.png", paths)       # image dropped
        finally:
            m.close()
            os.unlink(db)

    def test_looks_fingerprinted(self):
        from origami.brain.memory import _looks_fingerprinted as fp
        # build hashes / GUIDs / timestamps → fingerprinted (dropped)
        for p in ("/static/app.a1b2c3d4.js", "/js/application-0912i831283.js",
                  "/main.8f3a2b1c.css", "/runtime~abcdef12.js",
                  "/f47ac10b-58cc-4372-a567-0e02b2c3d479.html",
                  "/vendor.deadbeef.js", "/report-20231015.csv", "/bundle.1700000000.js"):
            self.assertTrue(fp(p), f"should be fingerprinted: {p}")
        # real names / lib+version / words → kept
        for p in ("/app.js", "/bootstrap.css", "/jquery.min.js",
                  "/bootstrap-4.5.2.min.js", "/bootstrap4.min.js", "/base64url.js",
                  "/error404.html", "/administration.aspx", "/oauth2/authorize",
                  "/painel_novo/", "/api/v2/users", "/login"):
            self.assertFalse(fp(p), f"should be kept: {p}")

    def test_record_run_excludes_hashed_bundles(self):
        import os, tempfile
        from origami.brain.memory import Memory
        from origami.core.evidence import TargetProfile
        class R:
            def __init__(self, findings): self.findings = findings; self.requests_made = 5
        db = tempfile.mktemp(suffix=".sqlite")
        m = Memory(db)
        try:
            p = TargetProfile(host="h", base_url="http://h/")
            m.record_run(p, R([make_finding("http://h/app.js", 200),
                               make_finding("http://h/app.a1b2c3d4.js", 200)]))
            paths = {row[0] for row in m.db.execute("SELECT path FROM corpus")}
            self.assertIn("/app.js", paths)            # shared name kept
            self.assertNotIn("/app.a1b2c3d4.js", paths)  # content-hashed bundle dropped
        finally:
            m.close()
            os.unlink(db)

    def test_recall_skips_fingerprinted(self):
        import os, tempfile
        from origami.brain.memory import Memory
        db = tempfile.mktemp(suffix=".sqlite")
        m = Memory(db)
        try:
            for h in ("h1", "h2"):
                m.db.execute("INSERT INTO host_techs VALUES (?, 'php')", (h,))
                m.db.execute("INSERT INTO corpus VALUES (?, '/admin/', 200)", (h,))
                m.db.execute("INSERT INTO corpus VALUES (?, '/app.a1b2c3d4.js', 200)", (h,))
            m.db.commit()
            paths = m.recall(["php"], exclude_host="other")
            self.assertIn("/admin/", paths)
            self.assertNotIn("/app.a1b2c3d4.js", paths)   # hashed never primed
        finally:
            m.close()
            os.unlink(db)

    def test_recall_dedupes_case_variants(self):
        # /MANIFEST.JSON and /manifest.json are one resource — prime only one,
        # preferring the lowercase (conventional) casing.
        import os, tempfile
        from origami.brain.memory import Memory
        db = tempfile.mktemp(suffix=".sqlite")
        m = Memory(db)
        try:
            for h in ("h1", "h2"):
                m.db.execute("INSERT INTO host_techs VALUES (?, 'php')", (h,))
                m.db.execute("INSERT INTO corpus VALUES (?, '/MANIFEST.JSON', 200)", (h,))
                m.db.execute("INSERT INTO corpus VALUES (?, '/manifest.json', 200)", (h,))
            m.db.commit()
            manifests = [p for p in m.recall(["php"], exclude_host="other")
                         if p.lower() == "/manifest.json"]
            self.assertEqual(manifests, ["/manifest.json"])   # one, lowercase
        finally:
            m.close()
            os.unlink(db)

    def test_record_run_lowercases_on_case_insensitive_host(self):
        # a case-insensitive (IIS/Windows) host → casing is meaningless, so store
        # the canonical lowercase form and never pollute the corpus with variants.
        import os, tempfile
        from origami.brain.memory import Memory
        from origami.core.evidence import TargetProfile
        class R:
            def __init__(self, findings): self.findings = findings; self.requests_made = 1
        db = tempfile.mktemp(suffix=".sqlite")
        m = Memory(db)
        try:
            p = TargetProfile(host="h", base_url="http://h/")
            p.case_sensitive = False
            m.record_run(p, R([make_finding("http://h/MANIFEST.JSON", 200)]))
            paths = {row[0] for row in m.db.execute("SELECT path FROM corpus")}
            self.assertIn("/manifest.json", paths)
            self.assertNotIn("/MANIFEST.JSON", paths)
        finally:
            m.close()
            os.unlink(db)

    def test_prune_fingerprinted(self):
        import os, tempfile
        from origami.brain.memory import Memory
        db = tempfile.mktemp(suffix=".sqlite")
        m = Memory(db)
        try:
            for h in ("h1", "h2"):
                m.db.execute("INSERT INTO corpus VALUES (?, '/admin/', 200)", (h,))
                m.db.execute("INSERT INTO corpus VALUES (?, '/app.a1b2c3d4.js', 200)", (h,))
            m.db.execute("INSERT INTO corpus VALUES ('h1', '/main.8f3a2b1c.css', 200)")
            m.db.commit()
            removed = m.prune_fingerprinted()
            self.assertEqual(removed, 3)               # 2x hashed js + 1 hashed css
            paths = {row[0] for row in m.db.execute("SELECT path FROM corpus")}
            self.assertEqual(paths, {"/admin/"})       # only the clean path survives
        finally:
            m.close()
            os.unlink(db)

    def test_associate_no_variable_limit_on_common_path(self):
        # a path on >999 hosts must not blow SQLite's bound-variable limit
        import os, tempfile
        from origami.brain.memory import Memory
        db = tempfile.mktemp(suffix=".sqlite")
        m = Memory(db)
        try:
            for i in range(1100):
                m.db.execute("INSERT OR REPLACE INTO corpus VALUES (?,?,?)", (f"h{i}", "/common", 200))
                if i % 2 == 0:
                    m.db.execute("INSERT OR REPLACE INTO corpus VALUES (?,?,?)", (f"h{i}", "/admin/", 200))
            m.db.commit()
            assoc = m.associate(["/common"], min_support=2, min_conf=0.4)   # no OperationalError
            self.assertIn("/admin/", assoc)           # ~50% co-occurrence
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

    def test_proxy_rotation_builds_pool(self):
        import asyncio
        from origami.core.httpclient import Engine, EngineConfig
        async def run():
            e = Engine(EngineConfig(proxies=["http://p1:8080", "http://p2:8080", "http://p3:8080"]))
            async with e:
                picks = {id(e._pick_client()) for _ in range(80)}
                return len(e._clients), len(picks)
            return 0, 0
        n_clients, n_picked = asyncio.run(run())
        self.assertEqual(n_clients, 3)              # one client per proxy
        self.assertEqual(n_picked, 3)              # all rotated over many requests

    def test_no_proxy_single_client(self):
        import asyncio
        from origami.core.httpclient import Engine, EngineConfig
        async def run():
            e = Engine(EngineConfig())
            async with e:
                return len(e._clients), e._pick_client() is e._client
        n, stable = asyncio.run(run())
        self.assertEqual(n, 1)
        self.assertTrue(stable)                    # single client, deterministic pick

    def test_http2_config_builds_client(self):
        # the engine must build with http2 off always, and on only when h2 is present
        import asyncio, importlib.util
        from origami.core.httpclient import Engine, EngineConfig
        async def build(flag):
            async with Engine(EngineConfig(http2=flag)):
                return True
        self.assertTrue(asyncio.run(build(False)))
        if importlib.util.find_spec("h2"):
            self.assertTrue(asyncio.run(build(True)))

    def test_spent_counts_prior_plus_current(self):
        # --max-requests must bound CUMULATIVE spend so --resume can't grant a
        # fresh budget each time
        e = self._engine()
        e.prior_requests = 700
        e.total_requests = 250
        self.assertEqual(e.spent, 950)
        e.prior_requests = 0
        self.assertEqual(e.spent, e.total_requests)   # fresh scan: spent == this-run total

    def test_parse_retry_after(self):
        import time
        from origami.core.httpclient import _parse_retry_after as P
        now = time.time()
        self.assertEqual(P("120", now), 120.0)                       # delta-seconds
        self.assertIsNone(P(None, now))
        self.assertIsNone(P("", now))
        self.assertIsNone(P("soon", now))                            # unparseable
        self.assertEqual(P("Wed, 21 Oct 2015 07:28:00 GMT", now), 0.0)  # past date → 0
        future = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(now + 90))
        self.assertAlmostEqual(P(future, now), 90, delta=2)          # HTTP-date

    def test_rotate_ua_picks_pool_and_keeps_headers(self):
        import asyncio
        from origami.core.httpclient import Engine, EngineConfig, _UA_POOL

        class _Hdrs(dict):
            def get_list(self, k): return []
        class _Resp:
            status_code = 200
            headers = _Hdrs({"content-type": "text/html"})
            async def aiter_bytes(self):
                if False:
                    yield b""
        class _Stream:
            async def __aenter__(self): return _Resp()
            async def __aexit__(self, *a): return False

        async def run():
            e = Engine(EngineConfig(rotate_ua=True))
            async with e:
                seen, captured = set(), {}
                def fake_stream(method, url, **kw):
                    h = kw.get("headers", {})
                    seen.add(h.get("User-Agent"))
                    captured.update(h)
                    return _Stream()
                e._client.stream = fake_stream
                for _ in range(60):
                    await e._stream_probe("http://t/x", "GET", False, {"headers": {"X-Custom": "keep"}})
                return seen, captured
        seen, captured = asyncio.run(run())
        self.assertGreater(len(seen), 1)                 # actually rotates
        self.assertTrue(seen <= set(_UA_POOL))           # only real pool UAs
        self.assertEqual(captured.get("X-Custom"), "keep")  # caller headers preserved

    def test_no_rotation_when_disabled(self):
        import asyncio
        from origami.core.httpclient import Engine, EngineConfig
        class _Hdrs(dict):
            def get_list(self, k): return []
        class _Resp:
            status_code = 200; headers = _Hdrs({"content-type": "text/html"})
            async def aiter_bytes(self):
                if False:
                    yield b""
        class _Stream:
            async def __aenter__(self): return _Resp()
            async def __aexit__(self, *a): return False
        async def run():
            e = Engine(EngineConfig(rotate_ua=False))
            async with e:
                sent = []
                def fake_stream(method, url, **kw):
                    sent.append(kw.get("headers"))
                    return _Stream()
                e._client.stream = fake_stream
                await e._stream_probe("http://t/x", "GET", False, {})
                return sent
        sent = asyncio.run(run())
        self.assertEqual(sent, [None])                   # no per-request UA header injected

    def test_retry_after_sets_and_caps_floor(self):
        from origami.core.httpclient import _RETRY_AFTER_CAP
        e = self._engine(40)
        e._note_pushback(12.0)                                       # explicit Retry-After
        self.assertEqual(e._delay_floor, 12.0)                       # honored exactly
        self.assertEqual(e._limit, 20.0)                             # still halves concurrency
        e2 = self._engine(40)
        e2._note_pushback(86400.0)                                   # hostile huge value
        self.assertEqual(e2._delay_floor, _RETRY_AFTER_CAP)          # capped, never stalls forever

    def test_transport_errors_do_not_collapse_concurrency(self):
        # regression: a few dead/slow URLs (timeout/reset/DNS) must NOT be treated
        # as WAF throttle — they must not halve the limit or inflate pushback_events
        import asyncio, httpx
        from origami.core.httpclient import Engine, EngineConfig
        e = Engine(EngineConfig(concurrency=40, max_retries=2))
        async def run():
            async with e:
                async def boom(url, method, keep_body, kw):
                    raise httpx.ReadTimeout("simulated slow host")
                e._stream_probe = boom
                for i in range(3):
                    pr = await e.fetch(f"http://dead/{i}")
                    self.assertTrue(pr.error)             # returns an error probe
        asyncio.run(run())
        self.assertEqual(e._limit, 40.0)                 # concurrency intact
        self.assertEqual(e.pushback_events, 0)           # not counted as throttle
        self.assertEqual(e._delay_floor, 0.0)

    def test_raw_ssl_error_does_not_crash_fetch(self):
        # a raw ssl.SSLError (subclass of OSError) escaping httpx's wrapping on a
        # flaky TLS read must become an error probe, not crash the whole scan
        import asyncio, ssl
        from origami.core.httpclient import Engine, EngineConfig
        e = Engine(EngineConfig(concurrency=10, max_retries=1))
        async def run():
            async with e:
                async def boom(url, method, keep_body, kw):
                    raise ssl.SSLError("record layer failure (_ssl.c:2580)")
                e._stream_probe = boom
                return await e.fetch("https://t/x")
        pr = asyncio.run(run())
        self.assertFalse(pr.ok)                 # error probe, not an exception
        self.assertIn("SSLError", pr.error)
        self.assertEqual(e.pushback_events, 0)  # transport fault ≠ throttle
        self.assertEqual(e._limit, 10.0)        # concurrency not collapsed

    def test_real_429_still_backs_off(self):
        # the genuine throttle signal must still trigger AIMD backoff
        import asyncio
        from origami.core.httpclient import Engine, EngineConfig, Probe
        e = Engine(EngineConfig(concurrency=40, max_retries=2))
        async def run():
            async with e:
                async def four29(url, method, keep_body, kw):
                    return Probe(url, method, 429, 0, 0, 0, "", "", 0, 1.0)
                e._stream_probe = four29
                await e.fetch("http://t/x")
        asyncio.run(run())
        self.assertLess(e._limit, 40.0)
        self.assertGreater(e.pushback_events, 0)


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
                            0.9, "wordlist", note="x", tags=["auth"], simhash=42,
                            words=7, lines=3)]
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
            self.assertEqual((st["findings"][0].words, st["findings"][0].lines), (7, 3))
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
                   queue=[("/a/", 1)], scanned=set(), start_offset=137,
                   edges=[("/app.js", "/api/x")])
            st = R.load(path)
            self.assertEqual(st["start_offset"], 137)
            self.assertEqual(st["edges"], [("/app.js", "/api/x")])   # graph survives resume

    def test_bad_version_rejected(self):
        import json
        import tempfile
        from pathlib import Path
        from origami.core import resume as R
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "s.json"
            path.write_text(json.dumps({"version": 99}))
            self.assertIsNone(R.load(path))


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

    def test_jsonapi_detect_and_extract(self):
        from origami.modules.discovery import apidocs
        doc = {"jsonapi": {"version": "1.0"}, "data": [], "links": {
            "self": {"href": "https://h/jsonapi"},
            "node--article": {"href": "https://h/jsonapi/node/article?page=1"},
            "user--user": {"href": "https://h/jsonapi/user/user"},
            "weird": "https://h/jsonapi/taxonomy_term/tags"}}
        self.assertTrue(apidocs._is_jsonapi(doc))
        eps = apidocs.extract_jsonapi_links(doc)
        self.assertIn("/jsonapi/node/article", eps)      # query stripped
        self.assertIn("/jsonapi/user/user", eps)
        self.assertIn("/jsonapi/taxonomy_term/tags", eps)  # bare-string link
        self.assertNotIn("/", eps)

    def test_jsonapi_by_content_type(self):
        from origami.modules.discovery import apidocs
        # no 'jsonapi' key, but the vnd.api+json content-type identifies it
        self.assertTrue(apidocs._is_jsonapi({"data": []}, "application/vnd.api+json"))
        self.assertFalse(apidocs._is_jsonapi({"data": []}, "application/json"))


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


class TestCachePoison(unittest.TestCase):
    def test_detect_cache_layer(self):
        from origami.modules.cache_poison import detect_cache_layer
        self.assertEqual(detect_cache_layer({"cf-ray": "abc", "server": "cloudflare"}), "cloudflare")
        self.assertEqual(detect_cache_layer({"x-served-by": "cache-fra"}), "fastly")
        self.assertEqual(detect_cache_layer({"x-varnish": "12345"}), "varnish")
        self.assertEqual(detect_cache_layer({"x-amz-cf-id": "z"}), "cloudfront")
        self.assertEqual(detect_cache_layer({"via": "1.1 varnish (Varnish/6.0)"}), "varnish")
        self.assertEqual(detect_cache_layer({"x-cache": "MISS"}), "cache")   # generic
        self.assertEqual(detect_cache_layer({"content-type": "text/html"}), "")

    def test_cache_status(self):
        from origami.modules.cache_poison import cache_status
        self.assertEqual(cache_status({"cf-cache-status": "HIT"}), "HIT")
        self.assertEqual(cache_status({"x-cache": "MISS, MISS"}), "MISS")
        self.assertEqual(cache_status({"x-cache": "HIT, MISS"}), "HIT")   # any layer HIT → cached
        self.assertEqual(cache_status({"cf-cache-status": "DYNAMIC"}), "MISS")
        self.assertEqual(cache_status({}), "")

    def test_is_cacheable(self):
        from origami.modules.cache_poison import is_cacheable
        self.assertFalse(is_cacheable({"cache-control": "no-store, private"}))
        self.assertFalse(is_cacheable({"cache-control": "no-cache"}))
        self.assertFalse(is_cacheable({}))
        self.assertTrue(is_cacheable({"cache-control": "public, max-age=300"}))
        self.assertTrue(is_cacheable({"age": "42"}))
        self.assertTrue(is_cacheable({"cf-cache-status": "HIT"}))
        self.assertTrue(is_cacheable({"expires": "Wed, 21 Oct 2099 07:28:00 GMT"}))

    def test_header_set_intensity_and_custom(self):
        from origami.modules.cache_poison import header_set
        light, auto, full = header_set("light"), header_set("auto"), header_set("full")
        self.assertLess(len(light), len(auto))
        self.assertLess(len(auto), len(full))
        # X-Forwarded-Host (the #1 vector) is present at every level
        for s in (light, auto, full):
            self.assertTrue(any(n == "X-Forwarded-Host" for n, _ in s))
        # custom pairs are appended, deduped by (lower name, value)
        custom = [("X-Custom-Cache", "evil"), ("x-forwarded-host", "{canary}.example.com")]
        merged = header_set("light", custom)
        self.assertIn(("X-Custom-Cache", "evil"), merged)
        self.assertEqual(sum(1 for n, v in merged
                             if n.lower() == "x-forwarded-host" and v == "{canary}.example.com"), 1)

    # --- fold: a fake cache that keys on the query but NOT on the headers ----
    def _cprobe(self, body, url, headers):
        p = make_probe(200, body, url=url, ctype="text/html")
        p.headers = headers
        return p

    def _run_fold(self, mode):
        """mode: 'poison' (reflected+cached), 'lead' (reflected, not cached),
        'keyed' (header ignored)."""
        import asyncio
        from urllib.parse import urlparse, parse_qs
        from origami.core.scanner import _cache_poison_fold, ScanResult, ScanOptions
        from origami.core.response_classifier import Finding
        from origami.output.ui import NullObserver
        outer = self

        class CacheEngine:
            total_requests = 0
            spent = 0
            def __init__(self):
                self.calls = []
                self.store = {}          # cb token -> cached (poisoned) body
            async def fetch(self, url, method="GET", keep_body=False, headers=None):
                CacheEngine.total_requests += 1
                CacheEngine.spent += 1
                self.calls.append((url, headers or {}))
                cb = parse_qs(urlparse(url).query).get("cb", [""])[0]
                base_hdrs = {"cache-control": "public, max-age=60"}
                if cb in self.store:                       # cache HIT on a poisoned key
                    return outer._cprobe(self.store[cb], url, {**base_hdrs, "x-cache": "HIT"})
                if mode == "echo":
                    # endpoint reflects its OWN query string heavily, ignores headers —
                    # the classic differ-signal trap (each cb differs the body).
                    body = b"<html>" + (b"q-" + cb.encode() + b" ") * 40 + b"</html>"
                    return outer._cprobe(body, url, base_hdrs)
                xfh = (headers or {}).get("X-Forwarded-Host", "")
                if xfh and "example.com" in xfh:
                    body = b"<html><a href='https://" + xfh.encode() + b"/login'>go</a></html>"
                    if mode == "poison":
                        self.store[cb] = body              # the cache stores our injected body
                        return outer._cprobe(body, url, base_hdrs)
                    if mode == "lead":
                        return outer._cprobe(body, url, base_hdrs)   # reflected but never cached
                # keyed / baseline / confirm-without-header → clean page
                return outer._cprobe(b"<html>clean homepage</html>", url, base_hdrs)

        profile = TargetProfile(host="t.example.com", base_url="https://t.example.com/")
        profile.cache_layer = "cloudflare"
        result = ScanResult(profile=profile)
        result.findings.append(Finding("https://t.example.com/page", 200, 30, "text/html",
                                       0.5, "wordlist"))
        eng = CacheEngine()
        asyncio.run(_cache_poison_fold(eng, profile, result, ScanOptions(cache_poison="auto"),
                                       NullObserver(), simhash(b"<html>clean homepage</html>")))
        return result, eng

    def test_reflected_and_cached_is_poisonable(self):
        result, _ = self._run_fold("poison")
        f = result.findings[0]
        self.assertIn("poisonable", f.tags)
        self.assertIn("cache", f.tags)
        self.assertGreaterEqual(f.confidence, 0.9)
        self.assertIn("cache poisoning", f.note)

    def test_reflected_but_not_cached_is_lead_only(self):
        result, _ = self._run_fold("lead")
        f = result.findings[0]
        self.assertIn("cache", f.tags)
        self.assertNotIn("poisonable", f.tags)
        self.assertIn("lead", f.note)

    def test_keyed_input_not_flagged(self):
        result, _ = self._run_fold("keyed")
        f = result.findings[0]
        self.assertNotIn("poisonable", f.tags)
        self.assertNotIn("cache", f.tags)

    def test_query_reflecting_endpoint_not_flagged_via_differ(self):
        # An endpoint that echoes its own cache-buster must NOT be flagged just
        # because each probe's body differs (it differs by the cb token alone).
        result, _ = self._run_fold("echo")
        f = result.findings[0]
        self.assertNotIn("poisonable", f.tags)
        self.assertNotIn("cache", f.tags)

    def test_safety_every_probe_rides_a_cache_buster(self):
        # The core safety invariant: we NEVER touch the real cache key. Every
        # request carries a unique ?cb= token; the bare URL is never fetched.
        _, eng = self._run_fold("poison")
        self.assertTrue(eng.calls, "fold made no requests")
        for url, _hdrs in eng.calls:
            self.assertIn("cb=", url, f"probe without a cache-buster: {url}")
            self.assertNotEqual(url, "https://t.example.com/page")   # never the real key


class TestMethodProbe(unittest.TestCase):
    def test_classify_surfaces_allow_on_405(self):
        from origami.core.response_classifier import classify
        from origami.core.evidence import TargetProfile
        p = TargetProfile(host="t", base_url="http://t/")
        probe = make_probe(405, b"", url="http://t/api/x")
        probe.headers = {"allow": "POST, OPTIONS"}
        f = classify(p, probe, "apidocs", "/")
        self.assertIsNotNone(f)
        self.assertIn("Allow: OPTIONS, POST", f.note)   # sorted, surfaced for free

    def _run_method_fold(self, post_status=422, allow="", patch_status=None, exclude=None):
        import asyncio
        from origami.core.scanner import _probe_405_finding, ScanOptions
        from origami.core.response_classifier import Finding
        from origami.output.ui import NullObserver

        class MEngine:
            total_requests = 0
            spent = 0
            def __init__(self): self.calls = []
            async def fetch(self, url, method="GET", keep_body=False, **kw):
                MEngine.total_requests += 1; MEngine.spent += 1
                self.calls.append(method)
                if method == "POST":
                    pr = make_probe(post_status, b'{"e":1}', url=url, ctype="application/json")
                    pr.headers = {"allow": allow} if allow else {}
                    return pr
                if method == "PATCH" and patch_status is not None:
                    return make_probe(patch_status, b'{"ok":1}', url=url)
                return make_probe(405, b"", url=url)

        finding = Finding("http://t/api/registrar/", 405, 0, "", 0.85, "apidocs")
        opts = ScanOptions(probe_405=True, exclude=([exclude] if exclude else []))
        eng = MEngine()
        asyncio.run(_probe_405_finding(eng, finding, opts, NullObserver()))
        return finding, eng

    def test_post_accepted_is_flagged(self):
        f, eng = self._run_method_fold(post_status=422)   # 422 = endpoint processed POST
        self.assertIn("method", f.tags)
        self.assertIn("POST (json) reached (422)", f.note)
        self.assertIn('{"e":1}', f.note)              # response-body hint surfaced
        self.assertNotIn("PUT", eng.calls)
        self.assertNotIn("DELETE", eng.calls)

    def test_patch_tried_only_when_allow_advertises_it(self):
        # POST 405, Allow lists PATCH → PATCH tried and accepted
        f, eng = self._run_method_fold(post_status=405, allow="PATCH, PUT", patch_status=200)
        self.assertIn("method", f.tags)
        self.assertIn("PATCH (json) accepted", f.note)
        self.assertIn("PATCH", eng.calls)
        self.assertNotIn("PUT", eng.calls)            # advertised but destructive → never fired

    def test_destructive_only_allow_fires_nothing_extra(self):
        # POST 405, Allow lists only PUT/DELETE → no safe method works, nothing flagged
        f, eng = self._run_method_fold(post_status=405, allow="PUT, DELETE")
        self.assertNotIn("method", f.tags)
        self.assertNotIn("PUT", eng.calls)
        self.assertNotIn("DELETE", eng.calls)

    def test_excluded_path_skipped(self):
        f, eng = self._run_method_fold(post_status=200, exclude="registrar")
        self.assertNotIn("method", f.tags)
        self.assertEqual(eng.calls, [])               # never probed an excluded path

    def test_415_tries_next_content_type(self):
        # a 415 on the JSON body must NOT stop the probe — it should try the next
        # content-type and report the more informative result (here a 400).
        import asyncio
        from origami.core.scanner import _probe_405_finding, ScanOptions
        from origami.core.response_classifier import Finding
        from origami.output.ui import NullObserver

        class MEngine:
            spent = 0
            def __init__(self): self.posts = 0
            async def fetch(self, url, method="GET", keep_body=False, **kw):
                MEngine.spent += 1
                ctype = (kw.get("headers") or {}).get("Content-Type", "")
                if method == "POST":
                    self.posts += 1
                    if ctype == "application/json":
                        return make_probe(415, b"", url=url)         # JSON rejected on media type
                    return make_probe(400, b'{"err":"missing"}', url=url)  # next variant → real result
                return make_probe(405, b"", url=url)

        finding = Finding("http://t/api/login", 405, 0, "", 0.85, "apidocs")
        eng = MEngine()
        asyncio.run(_probe_405_finding(eng, finding, ScanOptions(probe_405=True), NullObserver()))
        self.assertIn("method", finding.tags)
        self.assertIn("POST (empty) reached (400)", finding.note)   # the 400, not the 415
        self.assertIn('{"err":"missing"}', finding.note)        # body hint from the 400
        self.assertGreaterEqual(eng.posts, 2)               # tried past the 415

    def test_inline_probe_fires_in_scan_prefix(self):
        # the probe must run the MOMENT a 405 is found (inline), not in a late phase
        import asyncio
        from urllib.parse import urlparse
        from origami.core.scanner import _scan_prefix, ScanResult, ScanOptions, ScanControl
        from origami.core.evidence import TargetProfile, ContextBaseline
        from origami.core.scheduler import Candidate
        from origami.output.ui import NullObserver

        class FakeEngine:
            cfg = type("C", (), {"verify_tls": False})()
            total_requests = 0
            spent = 0
            def __init__(self): self.methods = []
            async def fetch(self, url, method="GET", keep_body=False, **kw):
                FakeEngine.total_requests += 1
                self.methods.append(method)
                if urlparse(url).path == "/register/":
                    if method == "POST":
                        return make_probe(200, b'{"ok":1}', url=url, ctype="application/json")
                    pr = make_probe(405, b"", url=url)          # GET → 405
                    pr.headers = {"allow": "POST"}
                    return pr
                return make_probe(404, b"not found", url=url)   # randoms/siblings

        p = TargetProfile(host="h", base_url="http://h/")
        cb = ContextBaseline(prefix="/", ext_class="none", status=404,
                             simhashes=[simhash(b"not found")], content_type="text/html")
        p.baseline[TargetProfile.context_key("/", "none")] = cb
        result = ScanResult(profile=p)
        eng = FakeEngine()
        asyncio.run(_scan_prefix(eng, p, "/", [Candidate("register/", 2, "apidocs")],
                                 result, ScanOptions(probe_405=True), NullObserver(), ScanControl()))
        self.assertIn("POST", eng.methods)            # POST fired inline, during the scan
        f = next(f for f in result.findings if "register" in f.url)
        self.assertIn("method", f.tags)
        self.assertIn("POST (json) accepted", f.note)  # verdict + content-type on the finding


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


class TestVCS(unittest.TestCase):
    def test_parse_git_index(self):
        from origami.modules.discovery import vcs
        paths = vcs.parse_git_index(_git_index(["src/app.js", "config/database.php", ".env"]))
        self.assertEqual(paths, ["src/app.js", "config/database.php", ".env"])

    def test_parse_ds_store(self):
        from origami.modules.discovery import vcs
        self.assertEqual(vcs.parse_ds_store(_ds_store(["admin", "backup.zip"])),
                         ["admin", "backup.zip"])

    def test_parse_svn_wcdb(self):
        from origami.modules.discovery import vcs
        self.assertEqual(sorted(vcs.parse_svn(_svn_wcdb(["app/index.php", "lib/db.php"]))),
                         ["app/index.php", "lib/db.php"])

    def test_parsers_reject_garbage(self):
        from origami.modules.discovery import vcs
        self.assertEqual(vcs.parse_git_index(b"not an index"), [])
        self.assertEqual(vcs.parse_ds_store(b"xx"), [])
        self.assertEqual(vcs.parse_svn(b"xx"), [])

    def test_vcs_fold_enumerates_git_tree(self):
        import asyncio
        from urllib.parse import urlparse
        from origami.core.scanner import _vcs_fold, ScanResult, ScanOptions
        from origami.core.evidence import TargetProfile
        from origami.core.response_classifier import Finding
        from origami.output.ui import NullObserver

        index = _git_index(["src/app.js", ".env"])

        class FakeEngine:
            spent = 0
            total_requests = 0
            async def fetch(self, url, method="GET", keep_body=False, **kw):
                FakeEngine.total_requests += 1
                path = urlparse(url).path
                if path == "/.git/index":
                    return make_probe(200, index, url=url, ctype="application/octet-stream")
                if path in ("/src/app.js", "/.env"):
                    return make_probe(200, b"SECRET=hunter2", url=url, ctype="text/plain")
                return make_probe(404, b"nope", url=url)

        p = TargetProfile(host="h", base_url="http://h/")
        result = ScanResult(profile=p)
        result.findings.append(Finding("http://h/.git/HEAD", 200, 23, "text/plain", 0.85, "backup"))
        asyncio.run(_vcs_fold(FakeEngine(), p, result, ScanOptions(), NullObserver()))
        urls = {f.url for f in result.findings}
        self.assertIn("http://h/src/app.js", urls)      # tracked file enumerated + fetched
        self.assertIn("http://h/.env", urls)

    def test_vcs_fold_honors_exclude(self):
        import asyncio
        from urllib.parse import urlparse
        from origami.core.scanner import _vcs_fold, ScanResult, ScanOptions
        from origami.core.evidence import TargetProfile
        from origami.core.response_classifier import Finding
        from origami.output.ui import NullObserver

        index = _git_index(["src/app.js", "logout.php"])

        class FakeEngine:
            spent = 0
            def __init__(self): self.fetched = []
            async def fetch(self, url, method="GET", keep_body=False, **kw):
                self.fetched.append(urlparse(url).path)
                if urlparse(url).path == "/.git/index":
                    return make_probe(200, index, url=url)
                return make_probe(200, b"x", url=url)

        p = TargetProfile(host="h", base_url="http://h/")
        result = ScanResult(profile=p)
        result.findings.append(Finding("http://h/.git/HEAD", 200, 1, "", 0.85, "backup"))
        eng = FakeEngine()
        asyncio.run(_vcs_fold(eng, p, result, ScanOptions(exclude=["logout"]), NullObserver()))
        self.assertNotIn("/logout.php", eng.fetched)     # excluded path never fetched


class TestSourceMap(unittest.TestCase):
    def _sourcemap(self, content):
        import json
        return json.dumps({"version": 3, "file": "app.min.js",
                           "sources": ["webpack:///src/api/client.ts"],
                           "sourcesContent": [content], "mappings": "AAAA"}).encode()

    def test_reconstructs_endpoints_from_sourcescontent(self):
        from origami.modules.discovery import js_parser as J
        sm = self._sourcemap(
            "const API='/api/v2/users'; fetch('/admin/secret-panel'); "
            "axios.get('/internal/report?year=2024');")
        paths = J.extract_paths(sm, "http://h/")
        self.assertIn("/api/v2/users", paths)
        self.assertIn("/admin/secret-panel", paths)      # buried in the minified bundle
        self.assertIn("/internal/report", paths)
        self.assertIn("year", J.extract_params(sm))

    def test_non_sourcemap_and_broken_json_safe(self):
        from origami.modules.discovery import js_parser as J
        self.assertEqual(J.extract_paths(b'{"x":"/a/b"}', "http://h/"), {"/a/b"})   # plain JSON
        self.assertEqual(J.extract_paths(b'{"sourcesContent": [broken', "http://h/"), set())
        self.assertEqual(J.parse_sourcemap(b"not json"), [])


class TestBuckets(unittest.TestCase):
    def test_find_bucket_refs(self):
        from origami.modules.discovery import buckets as B
        body = (b'cdn "https://my-assets.s3.amazonaws.com/x.js" '
                b'p "https://storage.googleapis.com/company-backups/db.sql" '
                b'vh "https://reports.storage.googleapis.com/q.csv" '
                b'az "https://acct1.blob.core.windows.net/private/f" '
                b's3://legacy-dumps/2020.zip')
        labels = sorted(r.label for r in B.find_bucket_refs(body))
        self.assertEqual(labels, ["azure:acct1/private", "gcs:company-backups",
                                  "gcs:reports", "s3:legacy-dumps", "s3:my-assets"])
        self.assertNotIn("s3:x.js", labels)             # object key of a vhost URL, not a bucket

    def test_list_url_and_listing_parse(self):
        from origami.modules.discovery import buckets as B
        r = B.BucketRef("s3", "b")
        self.assertEqual(B.list_url(r), "https://b.s3.amazonaws.com/?list-type=2")
        xml = b'<ListBucketResult><Contents><Key>a/db.sql</Key></Contents>' \
              b'<Contents><Key>backup.zip</Key></Contents></ListBucketResult>'
        self.assertTrue(B.is_listable(200, xml))
        self.assertFalse(B.is_listable(403, b'<Error><Code>AccessDenied</Code></Error>'))
        self.assertEqual(B.parse_keys(xml), ["a/db.sql", "backup.zip"])

    def test_bucket_fold_surfaces_and_probes(self):
        import asyncio
        from origami.core.scanner import _bucket_fold, ScanResult, ScanOptions
        from origami.core.evidence import TargetProfile
        from origami.modules.discovery.buckets import BucketRef
        from origami.output.ui import NullObserver

        xml = b'<ListBucketResult><Contents><Key>secret/db.sql</Key></Contents></ListBucketResult>'

        class FakeEngine:
            spent = 0
            def __init__(self): self.calls = 0
            async def fetch(self, url, method="GET", keep_body=False, **kw):
                self.calls += 1
                return make_probe(200, xml, url=url, ctype="application/xml")

        p = TargetProfile(host="h", base_url="http://h/")
        p.bucket_refs = {BucketRef("s3", "my-bucket")}

        # without --buckets: reference surfaced for free, no probe fired
        r1, e1 = ScanResult(profile=p), FakeEngine()
        asyncio.run(_bucket_fold(e1, p, r1, ScanOptions(buckets=False), NullObserver()))
        self.assertTrue(any("referenced: s3:my-bucket" in (f.note or "") for f in r1.findings))
        self.assertEqual(e1.calls, 0)                   # off-host GET only under --buckets

        # with --buckets: probes listability, flags PUBLIC + sample keys
        r2, e2 = ScanResult(profile=p), FakeEngine()
        asyncio.run(_bucket_fold(e2, p, r2, ScanOptions(buckets=True), NullObserver()))
        pub = [f for f in r2.findings if "listing" in f.tags]
        self.assertTrue(pub)
        self.assertIn("secret/db.sql", pub[0].note)


class TestConfigSeeds(unittest.TestCase):
    def test_config_refs_become_onhost_seeds(self):
        import asyncio
        from urllib.parse import urlparse
        from origami.core.scanner import _secrets_fold, ScanResult, ScanOptions
        from origami.core.evidence import TargetProfile
        from origami.core.response_classifier import Finding
        from origami.output.ui import NullObserver

        env = (b'DB=db\nAPI="/internal/admin-api"\nEXT="https://evil.com/x"\n'
               b'BUCKET="s3://co-backups/x"')

        class FakeEngine:
            spent = 0
            def __init__(self): self.hosts = []
            async def fetch(self, url, method="GET", keep_body=False, **kw):
                u = urlparse(url)
                self.hosts.append(u.netloc)
                if u.path == "/.env":
                    return make_probe(200, env, url=url, ctype="text/plain")
                if u.path == "/internal/admin-api":
                    return make_probe(200, b"admin api ok", url=url)
                return make_probe(404, b"no", url=url)

        p = TargetProfile(host="h", base_url="http://h/")
        result = ScanResult(profile=p)
        result.findings.append(Finding("http://h/.env", 200, len(env), "text/plain", 0.9, "wordlist"))
        eng = FakeEngine()
        asyncio.run(_secrets_fold(eng, p, result, ScanOptions(), NullObserver()))
        urls = {f.url for f in result.findings}
        self.assertIn("http://h/internal/admin-api", urls)   # same-host ref → seed → found
        self.assertNotIn("evil.com", eng.hosts)              # off-host ref never fetched
        self.assertIn("s3:co-backups", {r.label for r in p.bucket_refs})  # bucket ref captured


class TestDiscoveryAdds(unittest.TestCase):
    # --- #2 API version pivot -------------------------------------------------
    def test_version_variants(self):
        from origami.modules.discovery import apiver
        self.assertEqual(apiver.version_variants("/api/v1/users"),
                         ["/api/v0/users", "/api/v2/users", "/api/v3/users"])
        self.assertEqual(apiver.version_variants("/no/version"), [])

    def test_apiver_fold(self):
        import asyncio
        from urllib.parse import urlparse
        from origami.core.scanner import _apiver_fold, ScanResult, ScanOptions
        from origami.core.evidence import TargetProfile
        from origami.core.response_classifier import Finding
        from origami.output.ui import NullObserver

        class FakeEngine:
            spent = 0
            async def fetch(self, url, method="GET", keep_body=False, **kw):
                p = urlparse(url).path
                if p in ("/api/v2/users", "/api/v3/users"):
                    return make_probe(200, b"users", url=url, ctype="application/json")
                return make_probe(404, b"no", url=url)

        p = TargetProfile(host="h", base_url="http://h/")
        result = ScanResult(profile=p)
        result.findings.append(Finding("http://h/api/v1/users", 200, 5, "application/json", 0.9, "apidocs"))
        asyncio.run(_apiver_fold(FakeEngine(), p, result, ScanOptions(), NullObserver()))
        urls = {f.url for f in result.findings}
        self.assertIn("http://h/api/v2/users", urls)     # pivoted to the next version
        self.assertIn("http://h/api/v3/users", urls)

    # --- #3 feeds / sitemap variants -----------------------------------------
    def test_feed_content_urls(self):
        from origami.modules.discovery import robots
        rss = b'<rss><item><link>https://h/post-1</link><guid>https://h/g/2</guid></item></rss>'
        atom = b'<feed><entry><link href="https://h/atom-x"/></entry></feed>'
        self.assertEqual(set(robots._content_urls(rss)), {"https://h/post-1", "https://h/g/2"})
        self.assertEqual(robots._content_urls(atom), ["https://h/atom-x"])

    def test_harvest_parses_feeds(self):
        import asyncio
        from urllib.parse import urlparse
        from origami.modules.discovery import robots
        rss = b'<rss><channel><item><link>https://h/article-42</link></item></channel></rss>'
        class FakeEngine:
            async def fetch(self, url, method="GET", keep_body=False, **kw):
                if urlparse(url).path == "/feed":
                    return make_probe(200, rss, url=url, ctype="application/rss+xml")
                return make_probe(404, b"", url=url)
        paths = asyncio.run(robots.harvest(FakeEngine(), "http://h/"))
        self.assertIn("/article-42", paths)

    # --- #4 broader harvest ---------------------------------------------------
    def test_harvestable_includes_text_types(self):
        from origami.core.scanner import _harvestable
        from origami.core.response_classifier import Finding
        self.assertTrue(_harvestable(Finding("http://h/api/dump", 200, 9, "text/plain", 0.9, "x")))
        self.assertFalse(_harvestable(Finding("http://h/logo.png", 200, 9, "image/png", 0.9, "x")))

    # --- #5 naming-convention mutation ---------------------------------------
    def test_mutate_siblings(self):
        from origami.modules.discovery import mutate
        self.assertIn("/api/users", mutate.siblings("/api/user"))
        self.assertIn("/report2", mutate.siblings("/report1"))
        self.assertIn("/data.xml", mutate.siblings("/data.json"))
        self.assertEqual(mutate.siblings("/"), [])

    def test_mutate_fold(self):
        import asyncio
        from urllib.parse import urlparse
        from origami.core.scanner import _mutate_fold, ScanResult, ScanOptions
        from origami.core.evidence import TargetProfile
        from origami.core.response_classifier import Finding
        from origami.output.ui import NullObserver

        class FakeEngine:
            spent = 0
            async def fetch(self, url, method="GET", keep_body=False, **kw):
                if urlparse(url).path == "/api/users":
                    return make_probe(200, b"users", url=url, ctype="application/json")
                return make_probe(404, b"no", url=url)

        p = TargetProfile(host="h", base_url="http://h/")
        result = ScanResult(profile=p)
        result.findings.append(Finding("http://h/api/user", 200, 5, "application/json", 0.9, "wordlist"))
        asyncio.run(_mutate_fold(FakeEngine(), p, result, ScanOptions(), NullObserver()))
        self.assertIn("http://h/api/users", {f.url for f in result.findings})   # plural sibling found


class TestThrottleAwareFolds(unittest.TestCase):
    def _eng(self, pushback):
        return type("E", (), {"pushback_events": pushback})()

    def test_throttled_signal(self):
        from origami.core.scanner import _throttled, ScanOptions
        from origami.core.evidence import TargetProfile
        p = TargetProfile(host="h", base_url="http://h/")
        # economy forced on → always conserve
        self.assertTrue(_throttled(self._eng(0), p, ScanOptions(economy="on")))
        # sustained 429/503 → conserve regardless of economy
        self.assertTrue(_throttled(self._eng(5), p, ScanOptions(economy="off")))
        # economy auto + WAF detected → conserve
        p.waf = "cloudflare"
        self.assertTrue(_throttled(self._eng(0), p, ScanOptions(economy="auto")))
        # clean target, no WAF, no pushback → run everything
        clean = TargetProfile(host="h", base_url="http://h/")
        self.assertFalse(_throttled(self._eng(0), clean, ScanOptions(economy="off")))
        self.assertFalse(_throttled(self._eng(0), clean, ScanOptions(economy="auto")))


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
        self.assertIn("bypass-403", r.stdout)


if __name__ == "__main__":
    unittest.main()

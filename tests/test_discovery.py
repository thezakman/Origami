"""Origami unit tests — discovery folds — secrets/leaks/vhost/origin/graphql/odata/vcs/buckets/….

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

class TestVhost(unittest.TestCase):
    def test_registrable_handles_multi_label_suffixes(self):
        from origami.modules.vhost import registrable
        self.assertEqual(registrable("app.example.com"), "example.com")
        self.assertEqual(registrable("shop.examplestore.com.br"), "examplestore.com.br")  # .com.br!
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

    def test_path_tenant_host_detection(self):
        # shared hosts whose tenant lives in the PATH, not the host
        from origami.core.scope import path_tenant_host
        self.assertTrue(path_tenant_host("firestore.googleapis.com"))
        self.assertTrue(path_tenant_host("storage.googleapis.com"))
        self.assertTrue(path_tenant_host("firestore.googleapis.com:443"))
        # a normal host is NOT path-multitenant — host scope stays as-is
        self.assertFalse(path_tenant_host("example.com"))
        self.assertFalse(path_tenant_host("api.acme.com.br"))
        # suffix match must be on a label boundary, not a substring
        self.assertFalse(path_tenant_host("notgoogleapis.com"))

    def test_same_tenant_path_confines_to_target_chain(self):
        # path-multitenant hosts (e.g. firestore): one project targeted, history/
        # memory must not drag in OTHER projects' paths host scope can't tell apart.
        # (Client repro with real project IDs lives in tests/local/.)
        from origami.core.scope import same_tenant_path
        tgt = "/v1/projects/demoproject-11111/databases/(default)/documents/"
        # descendants of the target (real discovery) stay in scope
        self.assertTrue(same_tenant_path(
            tgt, "/v1/projects/demoproject-11111/databases/(default)/documents/users"))
        # ancestors of the target (path-climb toward root) stay in scope
        self.assertTrue(same_tenant_path(tgt, "/v1/projects/demoproject-11111/databases/"))
        self.assertTrue(same_tenant_path(tgt, "/v1/projects/demoproject-11111"))
        # a DIFFERENT project = a different tenant → out of scope
        self.assertFalse(same_tenant_path(
            tgt, "/v1/projects/otherproject-22222/databases/(default)/documents/UserLogs"))
        self.assertFalse(same_tenant_path(tgt, "/v1/projects/otherproject-33333/databases/"))
        # host-root probes (well-known/.git) diverge at segment 0 → dropped
        self.assertFalse(same_tenant_path(tgt, "/.well-known/security.txt"))
        # a bare-host target names no tenant → confine nothing
        self.assertTrue(same_tenant_path("/", "/v1/projects/anything/x"))

    def test_path_climb_ancestors_deepest_first(self):
        from origami.core.scanner import _path_climb
        base, file_seed, anc = _path_climb("/shop/api/orders")
        self.assertEqual(base, "/shop/api/orders/")
        self.assertIsNone(file_seed)
        self.assertEqual(anc, ["/shop/api/", "/shop/", "/"])

    def test_climb_brute_split_by_level(self):
        from origami.core.scanner import _climb_brute_split
        anc = ["/shop/api/", "/shop/", "/"]
        # off: nothing promoted, all stay single-probe seeds
        self.assertEqual(_climb_brute_split(anc, 0), ([], anc))
        # light default: only the immediate parent gets the full wordlist
        self.assertEqual(_climb_brute_split(anc, 1), (["/shop/api/"], ["/shop/", "/"]))
        # explicit N clamps to what exists (no phantom levels)
        self.assertEqual(_climb_brute_split(anc, 99), (anc, []))
        # negative = all the way to root (the --deep behavior)
        self.assertEqual(_climb_brute_split(anc, -1), (anc, []))
        # a target already at root climbs nothing
        self.assertEqual(_climb_brute_split([], -1), ([], []))

    def test_candidates_build_from_apex_excluding_target(self):
        from origami.modules.vhost import candidates
        c = candidates("shop.examplestore.com.br")
        self.assertIn("admin.examplestore.com.br", c)
        self.assertIn("staging.examplestore.com.br", c)
        self.assertIn("localhost", c)
        self.assertNotIn("shop.examplestore.com.br", c)     # the target itself excluded

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
        # __typename ALWAYS resolves — a null op alongside it must NOT read as 'open'
        self.assertEqual(graphql.classify_probe(200, json.dumps(
            {"data": {"__typename": "Query", "me": None}}).encode(), "me"), "reachable")
        self.assertEqual(graphql.classify_probe(200, json.dumps(
            {"data": {"__typename": "Query", "carteira": {"x": 1}}}).encode(), "carteira"), "open")
        # an op literally named `authenticate` with a validation error → reachable, NOT auth
        # (the echoed op name must not self-match the auth pattern)
        self.assertEqual(graphql.classify_probe(200, json.dumps(
            {"errors": [{"message": "Field 'authenticate' must have a selection of subfields"}]}).encode(),
            "authenticate"), "reachable")

class TestOData(unittest.TestCase):
    _EDMX = (
        b'<?xml version="1.0"?><edmx:Edmx Version="4.0" '
        b'xmlns:edmx="http://docs.oasis-open.org/odata/ns/edmx">'
        b'<edmx:DataServices><Schema Namespace="Svc">'
        b'<EntityType Name="Customer"><Property Name="Id" Type="Edm.Int32"/>'
        b'<Property Name="Cpf" Type="Edm.String"/>'
        b'<NavigationProperty Name="Orders" Type="Collection(Svc.Order)"/></EntityType>'
        b'<EntityType Name="Order"><Property Name="Total" Type="Edm.Decimal"/></EntityType>'
        b'<EntityType Name="City"><Property Name="Zip" Type="Edm.String"/></EntityType>'
        b'<Function Name="GetSalary"/><Action Name="Recharge"/>'
        b'<EntityContainer Name="C">'
        b'<EntitySet Name="Customers" EntityType="Svc.Customer"/>'
        b'<EntitySet Name="Orders" EntityType="Svc.Order"/>'
        b'<EntitySet Name="Cities" EntityType="Svc.City"/>'
        b'<Annotation Term="Org.OData.Aggregation.V1.ApplySupported"/>'
        b'</EntityContainer></Schema></edmx:DataServices></edmx:Edmx>')

    def test_is_metadata_and_service_doc_detection(self):
        from origami.modules.discovery import odata
        self.assertTrue(odata.is_metadata(self._EDMX))
        self.assertFalse(odata.is_metadata(b"<html>not odata</html>"))
        self.assertTrue(odata.is_service_doc(
            b'{"@odata.context":"$metadata","value":[]}', "application/json"))
        self.assertFalse(odata.is_service_doc(b'{"value":[]}', "application/json"))
        self.assertFalse(odata.is_service_doc(b'{"@odata.context":"x"}', "text/html"))

    def test_parse_metadata_sets_props_ops_sensitive_aggregation(self):
        from origami.modules.discovery import odata
        m = odata.parse_metadata(self._EDMX, service_root="https://h/odata/")
        self.assertEqual(set(m["entitysets"]), {"Customers", "Orders", "Cities"})
        self.assertEqual(m["properties"], {"Id", "Cpf", "Orders", "Total", "Zip"})  # incl. NavigationProperty
        self.assertEqual(m["functions"], ["GetSalary"])
        self.assertEqual(m["actions"], ["Recharge"])
        self.assertEqual(m["version"], "4.0")
        self.assertTrue(m["aggregation"])                    # ApplySupported annotation seen
        # sensitive spans sets + functions (Customers, Orders=financial, GetSalary)
        self.assertIn("Customers", m["sensitive"])
        self.assertIn("Orders", m["sensitive"])
        self.assertIn("GetSalary", m["sensitive"])
        self.assertNotIn("Cities", m["sensitive"])           # neutral set → not flagged

    def test_parse_service_doc_entity_sets(self):
        import json
        from origami.modules.discovery import odata
        body = json.dumps({"@odata.context": "$metadata", "value": [
            {"name": "Users", "kind": "EntitySet", "url": "Users"},
            {"name": "Me", "kind": "Singleton", "url": "Me"},        # not an entity set
            {"name": "Products", "url": "Products"}]}).encode()      # kind omitted → set
        m = odata.parse_service_doc(body, service_root="https://h/odata/")
        self.assertEqual(set(m["entitysets"]), {"Users", "Products"})
        self.assertIn("Users", m["sensitive"])

    def test_entity_set_paths_and_agg_probe_are_read_only(self):
        from origami.modules.discovery import odata
        m = odata.parse_metadata(self._EDMX, service_root="https://h/odata/")
        self.assertEqual(sorted(odata.entity_set_paths(m)),
                         ["/odata/Cities", "/odata/Customers", "/odata/Orders"])
        probe = odata.build_agg_probe("https://h/odata/", "Customers")
        self.assertEqual(probe, "https://h/odata/Customers?$apply=aggregate($count as Total)")
        # never a write verb / $batch / action in the probe URL
        for bad in ("$batch", "Recharge", "insert", "delete"):
            self.assertNotIn(bad, probe)

    def test_classify_probe_open_auth_reachable_unsupported(self):
        import json
        from origami.modules.discovery import odata
        # aggregate returned unauth → open (authz-by-aggregation leak)
        self.assertEqual(odata.classify_probe(200, json.dumps(
            {"@odata.context": "x", "value": [{"Total": 91234}]}).encode()), "open")
        self.assertEqual(odata.classify_probe(401, b""), "auth")
        self.assertEqual(odata.classify_probe(403, b""), "auth")
        self.assertEqual(odata.classify_probe(501, b""), "unsupported")   # $apply not implemented
        self.assertEqual(odata.classify_probe(400, b"$apply invalid"), "reachable")
        # 200 but no aggregate row (e.g. empty value) → reachable, not a leak
        self.assertEqual(odata.classify_probe(200, json.dumps({"value": []}).encode()), "reachable")

    def test_agg_count_handles_bare_array_and_envelope(self):
        import json
        from origami.modules.discovery import odata
        # bare array `[{"Total":N}]` — the shape a custom API-Gateway backend returns
        self.assertEqual(odata.agg_count(json.dumps([{"Total": 8060}]).encode()), 8060)
        # OData v4 envelope
        self.assertEqual(odata.agg_count(json.dumps({"value": [{"Total": 12}]}).encode()), 12)
        self.assertEqual(odata.classify_probe(200, json.dumps([{"Total": 8060}]).encode()), "open")
        # a normal collection row without our alias must NOT read as an aggregate
        self.assertIsNone(odata.agg_count(json.dumps([{"id": 1, "nome": "x"}]).encode()))
        self.assertEqual(odata.classify_probe(200, json.dumps([{"id": 1}]).encode()), "reachable")
        # FP guard for the neutral `Total` alias: a raw ENTITY that merely HAS a Total
        # field (an order amount), returned because $apply was ignored, is NOT a count
        self.assertIsNone(odata.agg_count(json.dumps([{"Total": 99.9, "id": 1, "item": "x"}]).encode()))
        # …but a pure aggregate with only @odata metadata alongside is still counted
        self.assertEqual(odata.agg_count(json.dumps(
            {"@odata.context": "x", "value": [{"Total": 42, "@odata.id": "y"}]}).encode()), 42)
        # a boolean is not a count
        self.assertIsNone(odata.agg_count(json.dumps([{"Total": True}]).encode()))

    def test_top_probe_and_record_parsing_and_sensitive_fields(self):
        import json
        from origami.modules.discovery import odata
        self.assertEqual(odata.with_query("https://h/api/motoristas", odata.top_query(1)),
                         "https://h/api/motoristas?$top=1")
        # respects an existing query string
        self.assertEqual(odata.with_query("https://h/api/x?a=1", "$top=1"),
                         "https://h/api/x?a=1&$top=1")
        # a $top=1 record (bare array) → the record list; sensitive PII keys flagged
        rec = {"identificacao": "046...", "cnh": "018...", "nomeCompleto": "A R",
               "dataNascimento": "0001-01-01", "usuarioSolicitanteEmail": "x@y", "ativo": True}
        recs = odata.parse_records(200, json.dumps([rec]).encode())
        self.assertEqual(len(recs), 1)
        sens = odata.sensitive_fields(recs[0])
        for k in ("identificacao", "cnh", "nomeCompleto", "dataNascimento", "usuarioSolicitanteEmail"):
            self.assertIn(k, sens)
        self.assertNotIn("ativo", sens)                  # non-PII field not flagged
        # a bare aggregate row is NOT a data record (don't double-count it)
        self.assertIsNone(odata.parse_records(200, json.dumps([{"Total": 5}]).encode()))
        # blocked / empty → no records
        self.assertIsNone(odata.parse_records(413, b'{"message":"Request Entity Too Large"}'))
        self.assertIsNone(odata.parse_records(200, json.dumps({"value": []}).encode()))

    def test_query_fold_probes_the_target_even_when_blocked(self):
        # the reported gap: point directly AT a collection that 413s on the plain
        # listing — it never becomes a finding, but ?$top=1 leaks a row. The fold
        # must probe the TARGET itself, not only result.findings.
        import asyncio
        from origami.core import scanner
        from origami.core.scanner import ScanResult, ScanOptions
        from origami.core.evidence import TargetProfile
        from origami.output.ui import NullObserver

        class _P:
            def __init__(self, status, body):
                self.status, self.body, self.ok = status, body, True

        class _Eng:
            async def fetch(self, url, method="GET", keep_body=False, **kw):
                if "$apply=aggregate" in url:
                    return _P(200, b'[{"Total":8060}]')
                if "$top=1" in url:
                    return _P(200, b'[{"nomeCompleto":"X","cpf":"123","ativo":true}]')
                return _P(413, b'{"message":"Request Entity Too Large"}')   # plain listing blocked

        prof = TargetProfile(host="h", base_url="https://h/api/motoristas")
        res = ScanResult(profile=prof)                 # NO findings — the 413 target isn't one
        found = []
        asyncio.run(scanner._odata_query_fold(
            _Eng(), prof, res, ScanOptions(finding_sink=found.append), NullObserver()))
        # one standard finding PER successful payload — the URL IS the reproducing request
        self.assertEqual(len(found), 2)
        by_url = {f.url: f for f in found}
        top = by_url["https://h/api/motoristas?$top=1"]
        self.assertIn("auth-bypass", top.tags)         # blocked plain listing → bypass
        self.assertIn("disclosure", top.tags)          # a record was read
        self.assertIn("413", top.note)                 # notes the bypassed status
        self.assertIn("sensitive", top.note)           # PII field names flagged
        agg = by_url["https://h/api/motoristas?$apply=aggregate($count as Total)"]
        self.assertIn("8060", agg.note)                # the leaked aggregate count
        self.assertEqual(agg.status, 200)              # the payload's real status
        # the target path is recorded so a later pass won't double-probe it
        self.assertIn("/api/motoristas", res.odata_probed)
        # a plain-2xx root target names no collection → nothing probed
        prof2 = TargetProfile(host="h", base_url="https://h/")
        found2 = []
        asyncio.run(scanner._odata_query_fold(
            _Eng(), prof2, ScanResult(profile=prof2),
            ScanOptions(finding_sink=found2.append), NullObserver()))
        self.assertEqual(found2, [])

    def test_harvest_finds_metadata_via_stub_engine(self):
        import asyncio
        from origami.modules.discovery import odata

        class _Probe:
            def __init__(self, ok, body, ct="application/xml"):
                self.ok, self.body, self.content_type = ok, body, ct

        class _Engine:
            def __init__(self, edmx): self.edmx = edmx
            async def fetch(self, url, method="GET", keep_body=False, **kw):
                # only /odata/$metadata serves the schema; everything else 404s
                if url.endswith("/odata/$metadata"):
                    return _Probe(True, self.edmx)
                return _Probe(False, b"")

        url, sets, meta = asyncio.run(
            odata.harvest(_Engine(self._EDMX), "https://h/"))
        self.assertEqual(url, "https://h/odata/$metadata")
        self.assertEqual(sets, {"Customers", "Orders", "Cities"})
        self.assertEqual(meta["service_root"], "https://h/odata/")
        # nothing served → clean empty result, never raises
        none_url, none_sets, _ = asyncio.run(
            odata.harvest(_Engine(b"<html/>"), "https://h/"))
        self.assertIsNone(none_url)
        self.assertEqual(none_sets, set())

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


if __name__ == "__main__":
    unittest.main()

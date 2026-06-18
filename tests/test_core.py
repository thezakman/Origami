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


class TestBypass403(unittest.TestCase):
    def test_variants_cover_families(self):
        from origami.modules.bypass403 import variants
        v = variants("/admin")
        labels = [lbl for lbl, *_ in v]
        kinds = {lbl.split()[0] for lbl in labels}
        self.assertEqual(kinds, {"path", "header", "method"})
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

    def test_count_column_blank_when_indeterminate(self):
        from origami.output.ui import _CountColumn
        ui = self._ui()
        ui.phase("calibrate")
        col = _CountColumn().render(ui._progress.tasks[0])
        self.assertEqual(str(col), "")                    # no "0/1"
        ui.start_prefix("/admin/", 50)
        self.assertIn("/", str(_CountColumn().render(ui._progress.tasks[0])))

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

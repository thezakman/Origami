"""Origami unit tests — 403/401 bypass — path/header/method tricks, wordlists, ferox parity.

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

    def test_bypass_rejects_index_default_route(self):
        # FP guard: X-Original-URL / X-Rewrite-URL tricks often just route to the
        # site index (a generic 200 that is NOT the blocked resource). When the
        # target is a deep/empty API endpoint, root_simhash can't catch it — the
        # host-index simhash must. A 200 matching the index is rejected, not flagged.
        import asyncio
        from origami.core.scanner import _bypass_fold, ScanResult, ScanOptions
        from origami.core.evidence import TargetProfile
        from origami.core.response_classifier import Finding
        from origami.output.ui import NullObserver

        INDEX = b"<html><body><h1>Acesso restrito!</h1></body></html>"
        url403 = "https://h/api/x/.aws/config"

        class FakeEngine:                                    # host root AND every bypass
            total_requests = 0                               # variant return the SAME index
            async def fetch(self, u, method="GET", keep_body=False, headers=None):
                FakeEngine.total_requests += 1
                return make_probe(200, INDEX, url=u)

        prof = TargetProfile(host="h", base_url="https://h/api/x/document")
        f = Finding(url403, 403, 20, "text/html", 0.85, "wordlist", simhash=12345)
        result = ScanResult(profile=prof, findings=[f])
        # root_simhash is the TARGET's (empty) body — only the host-index check catches this
        asyncio.run(_bypass_fold(FakeEngine(), prof, result, ScanOptions(bypass403=True),
                                 NullObserver(), root_simhash=999))
        self.assertEqual([x for x in result.findings if x.origin == "bypass403"], [])
        self.assertIn(f, result.findings)                    # the 403 is left intact

    def test_backup_drops_suffix_catchall(self):
        # a route that serves the same-length page for ANY suffix (/x.json.bak ==
        # /x.json.<garbage> == /x.json) — its ".bak"/".old" aren't disclosures. A
        # per-request nonce defeats the simhash guard, so the random-suffix
        # (status,length) probe must catch it.
        import asyncio
        from origami.core import scanner
        from origami.core.scanner import _backup_fold, ScanResult, ScanOptions
        from origami.core.evidence import TargetProfile
        from origami.core.response_classifier import Finding
        from origami.output.ui import NullObserver

        LEN = 4000

        class FakeEngine:                          # every suffix → same length, nonce'd bytes
            n = 0
            async def fetch(self, u, method="GET", keep_body=False, headers=None):
                FakeEngine.n += 1
                body = (b"<form>" + str(FakeEngine.n).encode() + b"z" * LEN)[:LEN]
                return make_probe(200, body, url=u)

        prof = TargetProfile(host="h", base_url="https://h/api/data.json")
        f = Finding("https://h/api/data.json", 200, LEN, "application/json", 0.95,
                    "wordlist", simhash=999)     # base simhash differs from the nonce'd bodies
        result = ScanResult(profile=prof, findings=[f])
        orig = scanner._confirm
        async def fake_confirm(engine, profile, prefix, probe, origin):
            return Finding(probe.url, probe.status, probe.length, probe.content_type, 0.9, origin)
        scanner._confirm = fake_confirm
        try:
            asyncio.run(_backup_fold(FakeEngine(), prof, result, ScanOptions(backups=True),
                                     NullObserver()))
        finally:
            scanner._confirm = orig
        # NO backup variant reported — all matched the random-suffix catch-all
        self.assertEqual([x for x in result.findings if x.origin == "backup"], [])

    def test_curl_repro(self):
        from origami.core.scanner import _curl_cmd
        from origami.core.response_classifier import Finding
        from origami.output.ui import _finding_curl
        # a header/method bypass reproduces with the exact -H / -X
        self.assertEqual(
            _curl_cmd("https://h/x", "GET", {"X-Original-URL": "/x"}),
            "curl -sk -H 'X-Original-URL: /x' 'https://h/x'")
        self.assertEqual(_curl_cmd("https://h/x", "POST"), "curl -sk -X POST 'https://h/x'")
        # a finding with a stored repro uses it; otherwise falls back to curl <url>
        self.assertEqual(_finding_curl(Finding("https://h/m?$top=1", 200, 5, "application/json",
                                               0.9, "odata")), "curl -sk 'https://h/m?$top=1'")
        f = Finding("https://h/x", 200, 5, "text/html", 0.9, "bypass403", repro="curl -sk -H 'a: b' 'https://h/x'")
        self.assertEqual(_finding_curl(f), "curl -sk -H 'a: b' 'https://h/x'")
        # a URL containing a single quote must be POSIX-escaped, not break the command
        import shlex
        q = _finding_curl(Finding("https://h/p?q=o'brien", 200, 5, "text/html", 0.9, "wordlist"))
        self.assertEqual(shlex.split(q), ["curl", "-sk", "https://h/p?q=o'brien"])

    def test_should_shortscan_windows_stack_behind_nginx(self):
        # the 8.3 short-name leak lives on NTFS and survives ANY front server, so
        # `auto` must not gate purely on an "iis" fingerprint — a .NET app (DNN,
        # SharePoint…) behind nginx/CDN must still trigger the (self-gating) check.
        from origami.core.scanner import _should_shortscan, ScanOptions
        auto = ScanOptions()                                 # shortscan="auto"

        class P:
            def __init__(self, techs, exts=(), ci=None):
                self.tech_scores = {t: 50 for t in techs}
                self.enabled_extensions = set(exts)
                self.case_sensitive = ci

        # nginx front, DotNetNuke backend → run it (the reported bug)
        self.assertTrue(_should_shortscan(auto, set(), P(["nginx", "dnn", "gitea"])))
        # SharePoint / an ASP.NET extension → run it
        self.assertTrue(_should_shortscan(auto, set(), P(["cloudflare", "sharepoint"])))
        self.assertTrue(_should_shortscan(auto, set(), P(["apache"], exts=[".aspx"])))
        # NTFS already proven case-insensitive → run it
        self.assertTrue(_should_shortscan(auto, set(), P(["nginx"], ci=False)))
        # a plain Linux/PHP stack → do NOT waste the probe
        self.assertFalse(_should_shortscan(auto, set(), P(["nginx", "php"], exts=[".php"])))
        # explicit on/off always win
        self.assertTrue(_should_shortscan(ScanOptions(shortscan="on"), set(), P(["nginx"])))
        self.assertFalse(_should_shortscan(ScanOptions(shortscan="off"), set(), P(["iis"])))
        # the classic IIS-fold signal still works
        self.assertTrue(_should_shortscan(auto, {"shortscan"}, P(["nginx"])))
        # --deep runs the (self-gating) vuln check on ANY target — full coverage for
        # an IIS-behind-nginx host with no .NET fingerprint at all…
        self.assertTrue(_should_shortscan(ScanOptions(deep=True), set(), P(["nginx", "php"], exts=[".php"])))
        # …but an explicit --no-shortscan still wins even under --deep
        self.assertFalse(_should_shortscan(ScanOptions(deep=True, shortscan="off"), set(), P(["iis"])))

    def test_shortscan_recurses_into_dirs_under_deep(self):
        # 8.3 enumeration is per-directory, so a vulnerable host must be re-scanned
        # inside each directory shortscan reveals — but only under --deep (it's
        # expensive). Verifies the bounded BFS over discovered dir URLs.
        import asyncio
        from origami.core import scanner
        from origami.core.scanner import _shortscan_pass, ScanOptions, ScanResult
        from origami.core.evidence import TargetProfile
        from origami.output.ui import NullObserver

        calls = []
        async def fake_one(engine, profile, url, words, result, opts, observer,
                           memory=None, is_root=True):
            calls.append(url)
            if url.endswith("/SALESFORCE/HONEYWELL/"):
                return True, []                       # deepest dir, nothing more
            if url.endswith("/SALESFORCE/"):
                return True, [url + "HONEYWELL/"]     # this dir reveals a deeper one
            return True, [url + "SALESFORCE/"]         # root reveals a dir
        orig = scanner._shortscan_one
        scanner._shortscan_one = fake_one
        try:
            prof = TargetProfile(host="h", base_url="https://h/")
            res = ScanResult(profile=prof)
            asyncio.run(_shortscan_pass(None, prof, "https://h/", [], res,
                                        ScanOptions(deep=True), NullObserver()))
            self.assertEqual(calls, ["https://h/", "https://h/SALESFORCE/",
                                     "https://h/SALESFORCE/HONEYWELL/"])   # recursed the tree
            calls.clear()
            asyncio.run(_shortscan_pass(None, prof, "https://h/", [], res,
                                        ScanOptions(deep=False), NullObserver()))
            self.assertEqual(calls, ["https://h/"])   # no --deep → root only
        finally:
            scanner._shortscan_one = orig

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


if __name__ == "__main__":
    unittest.main()

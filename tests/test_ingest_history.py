"""Origami unit tests — history + spec ingestion — wayback, OpenAPI/Swagger, wappalyzer.

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

    def test_harvest_gau_hedged_with_native(self):
        # --gau runs gau AND the native sources CONCURRENTLY (not gau-then-fallback):
        # a hung gau must not starve the keyless fallback out of the scan's history
        # budget. Overlap is deduped; the label unions every source that returned.
        import asyncio
        from origami.modules.discovery import wayback as W
        orig = (W.from_cdx, W.from_commoncrawl, W.from_gau, W.from_urlscan, W.from_otx)
        try:
            async def cdx(host, cap=0, subs=False): return {"http://h/native"}
            async def none(host, cap=0, subs=False): return set()
            W.from_cdx, W.from_commoncrawl = cdx, none
            W.from_urlscan, W.from_otx = none, none
            # gau succeeds → its results are UNIONED with native (hedge), not exclusive
            async def gau_ok(host, **k): return {"http://h/fromgau"}
            W.from_gau = gau_ok
            paths, _, src = asyncio.run(W.harvest("h", use_gau=True))
            self.assertEqual((paths, src), ({"/fromgau", "/native"}, "gau+wayback"))
            # gau hung/absent (None) → native still lands within budget
            async def gau_missing(host, **k): return None
            W.from_gau = gau_missing
            paths, _, src = asyncio.run(W.harvest("h", use_gau=True))
            self.assertEqual((paths, src), ({"/native"}, "wayback"))
        finally:
            W.from_cdx, W.from_commoncrawl, W.from_gau, W.from_urlscan, W.from_otx = orig

    def test_from_gau_timeout_reaps_child(self):
        # a hung gau must hit its own timeout, be reaped, and return fast — never
        # left running detached. It returns None (not empty) so the caller treats a
        # hung binary as unavailable and falls back to the native sources. Pass the
        # fake binary EXPLICITLY (`binaries` is a def-time default) so the test is
        # deterministic regardless of whether gau is installed.
        import asyncio, time
        from origami.modules.discovery import wayback as W
        orig_to = W._GAU_TIMEOUT
        try:
            W._GAU_TIMEOUT = 0.3
            t0 = time.time()
            res = asyncio.run(W.from_gau("5", binaries=("sleep",)))  # `sleep 5` >> 0.3s timeout
            self.assertIsNone(res)                  # timeout → None → native fallback runs
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

    def test_extract_ui_spec_urls_multi_doc_relative(self):
        from origami.modules.discovery import apidocs
        # the exact inline config a multi-doc .NET Swashbuckle UI ships
        html = (b'<script>const ui = SwaggerUIBundle({"urls":['
                b'{"url":"internal/swagger.json","name":"Atlas Internal"},'
                b'{"url":"siscomexEvents/swagger.json","name":"Siscomex Events"},'
                b'{"url":"codebaEvents/swagger.json","name":"Codeba Events"}],'
                b'"deepLinking":true})</script>')
        specs = apidocs.extract_ui_spec_urls(html, "https://h/swagger/index.html")
        self.assertEqual(specs, [
            "https://h/swagger/internal/swagger.json",       # relative → resolved under /swagger/
            "https://h/swagger/siscomexEvents/swagger.json",
            "https://h/swagger/codebaEvents/swagger.json"])
        # absolute entries and a single `url:` are handled too; deduped
        html2 = b'{"url":"/api/v1/swagger.json"}{"url":"/api/v1/swagger.json"}'
        self.assertEqual(apidocs.extract_ui_spec_urls(html2, "https://h/swagger/"),
                         ["https://h/api/v1/swagger.json"])

    def test_harvest_folds_all_specs_from_ui(self):
        import asyncio
        from origami.modules.discovery import apidocs

        class _P:
            def __init__(self, ok, body, ct="application/json", status=200):
                self.ok, self.body, self.content_type, self.status = ok, body, ct, status

        UI = (b'{"urls":[{"url":"internal/swagger.json"},'
              b'{"url":"codebaEvents/swagger.json"}]}')
        SPECS = {
            "/swagger/internal/swagger.json":
                b'{"openapi":"3.0","paths":{"/internal/health":{},"/internal/users/{id}":{}}}',
            "/swagger/codebaEvents/swagger.json":
                b'{"openapi":"3.0","paths":{"/codeba/events":{}}}'}

        class _Eng:
            async def fetch(self, url, method="GET", keep_body=False, **kw):
                from urllib.parse import urlparse as up
                p = up(url).path
                if p == "/swagger/index.html":
                    return _P(True, UI)
                if p in SPECS:
                    return _P(True, SPECS[p])
                return _P(False, b"", status=404)

        specs, eps = asyncio.run(apidocs.harvest(_Eng(), "https://h/"))
        self.assertEqual(len(specs), 2)                       # BOTH specs parsed, not just the first
        # endpoints from BOTH specs are folded, plus each spec's own path
        self.assertIn("/internal/health", eps)
        self.assertIn("/internal/users/", eps)                # templated → static dir
        self.assertIn("/codeba/events", eps)
        self.assertIn("/swagger/internal/swagger.json", eps)  # disclosure reported
        self.assertIn("/swagger/codebaEvents/swagger.json", eps)

    def test_anchor_bases_root_and_descend(self):
        from origami.modules.discovery import apidocs
        # a deep-path scan anchors doc probes at the host root AND each ancestor
        self.assertEqual(apidocs._anchor_bases("https://h/api/motoristas"),
                         ["https://h/", "https://h/api/", "https://h/api/motoristas/"])
        # a trailing file is dropped (its directory is the deepest anchor)
        self.assertEqual(apidocs._anchor_bases("https://h/app/docs/spec.json"),
                         ["https://h/", "https://h/app/", "https://h/app/docs/"])
        # a bare host → just the root
        self.assertEqual(apidocs._anchor_bases("https://h/"), ["https://h/"])

    def test_harvest_finds_root_spec_from_deep_path_and_unions_defaults(self):
        # the reported bug: scanning /api/motoristas must still find the root
        # /swagger/... AND a default /swagger/v1/swagger.json the UI doesn't list
        import asyncio
        from origami.modules.discovery import apidocs

        class _P:
            def __init__(self, ok, body, ct="application/json", status=200):
                self.ok, self.body, self.content_type, self.status = ok, body, ct, status

        UI = b'{"urls":[{"url":"SAP/swagger.json"}]}'          # UI lists only SAP
        SPECS = {
            "/swagger/SAP/swagger.json": b'{"openapi":"3.0","paths":{"/api/Sap/Doc":{}}}',
            "/swagger/v1/swagger.json": b'{"openapi":"3.0","paths":{"/api/v1/Users":{}}}'}  # default, not in UI

        class _Eng:
            async def fetch(self, url, method="GET", keep_body=False, **kw):
                from urllib.parse import urlparse as up
                p = up(url).path
                if p == "/swagger/index.html":
                    return _P(True, UI)
                if p in SPECS:
                    return _P(True, SPECS[p])
                return _P(False, b"", status=404)

        # base is a DEEP path — the root swagger must still be found
        specs, eps = asyncio.run(apidocs.harvest(
            _Eng(), "https://h/api/motoristas"))
        self.assertEqual(len(specs), 2)                        # SAP (from UI) + v1 (default), both
        self.assertIn("/api/Sap/Doc", eps)
        self.assertIn("/api/v1/Users", eps)                   # the default spec the UI omitted

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


if __name__ == "__main__":
    unittest.main()

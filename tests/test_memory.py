"""Origami unit tests — learning memory — kNN recall, hygiene, vocabulary, n-gram, bandit, association.

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


if __name__ == "__main__":
    unittest.main()

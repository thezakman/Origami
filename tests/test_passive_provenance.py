"""Synthetic, offline evidence-channel and reference-chain regressions."""

import unittest
from copy import deepcopy
from dataclasses import asdict

from origami.core.evidence import Evidence, TargetProfile
from origami.core.response_classifier import Finding
from origami.core.scanner.types import ScanResult
from origami.output import html_report, json_report
from origami.output.correlations import fingerprint_correlations
from origami.output.provenance import reference_provenance


def result():
    return ScanResult(TargetProfile("example.test", "https://example.test/app/index.php"))


class TestPassiveProvenance(unittest.TestCase):
    def test_cookie_value_rotation_and_duplicate_sources_are_one_marker_channel(self):
        profile = result().profile
        profile.evidence = [Evidence("header", "php", "Set-Cookie: PHPSESSID=secret1; Path=/", 50),
                            Evidence("cookie", "php", "Set-Cookie: PHPSESSID=secret1", 50),
                            Evidence("cookie", "php", "Set-Cookie: PHPSESSID=secret2", 50)]
        profile.tech_scores = {"php": 100}
        before = [asdict(e) for e in profile.evidence]
        row = fingerprint_correlations(profile)[0]
        self.assertEqual(row["signal_types"], ["cookie", "header"])
        self.assertEqual(row["distinct_signal_count"], 3)  # backward-compatible raw detail count
        self.assertEqual(row["signal_channels"], ["response_headers"])
        self.assertEqual(row["channel_support"], "single_channel")
        self.assertEqual(row["distinct_marker_count"], 1)
        self.assertEqual(row["evidence_indices"], [0, 1, 2])
        self.assertEqual([asdict(e) for e in profile.evidence], before)
        self.assertEqual(profile.tech_scores, {"php": 100})

    def test_body_and_error_page_share_channel_but_keep_distinct_details(self):
        profile = result().profile
        profile.evidence = [Evidence("body", "php", "body~='php'", 30),
                            Evidence("error_page", "php", "default error page ~= 'fatal error'", 55)]
        row = fingerprint_correlations(profile)[0]
        self.assertEqual(row["signal_channels"], ["response_body"])
        self.assertEqual(row["distinct_marker_count"], 2)
        self.assertEqual(row["independence"], "not_established")
        profile.evidence.append(Evidence("header", "php", "X-Powered-By: PHP", 50))
        self.assertEqual(fingerprint_correlations(profile)[0]["channel_support"], "multiple_channels")

    def test_cookie_names_are_case_sensitive_and_unknown_signals_keep_provenance(self):
        profile = result().profile
        profile.evidence = [Evidence("cookie", "php", f"Set-Cookie: {name}=token", 50)
                            for name in ("Session", "session")]
        self.assertEqual(fingerprint_correlations(profile)[0]["distinct_marker_count"], 2)
        profile.tech_scores["orphan"] = 100
        row = fingerprint_correlations(profile)[1]
        self.assertEqual(row["channel_support"], "provenance_unavailable")

    def test_reference_chain_joins_only_exact_observations_and_retains_every_edge_index(self):
        scan = result()
        scan.edges = [("/app/index.php", "/app/main.js?v=1"),
                      ("/app/main.js?v=1", "/app/main.js.map"),
                      ("/app/main.js.map", "/api/items?view=A"),
                      ("/app/main.js.map", "/api/items?view=A")]
        accepted = Finding("https://example.test/api/items?view=A", 403, 12, "text/html", .5, "js")
        scan.reported_observations = [asdict(accepted)]
        scan.findings = [accepted]
        before = deepcopy(scan.edges), deepcopy(scan.reported_observations)
        data = reference_provenance(scan)
        chain = data["chain_examples"][-1]
        self.assertEqual(len(chain["urls"]), 4)
        self.assertEqual(chain["edge_indices"], [[0], [1], [2, 3]])
        self.assertEqual(chain["endpoint_observation_refs"], [
            {"collection": "reported_observations", "index": 0, "status": 403}])
        self.assertEqual(scan.edges, before[0])
        self.assertEqual(scan.reported_observations, before[1])
        self.assertEqual(json_report.to_dict(scan)["reference_provenance"], data)
        self.assertIn("Recorded reference chains (offline)", html_report.render(scan))

    def test_query_case_port_and_origin_do_not_collapse_to_path(self):
        scan = result()
        destinations = ["/api?A=1", "/api?a=1", "https://example.test:8443/api?A=1",
                        "https://other.test/api?A=1", "/api"]
        scan.edges = [("/", dst) for dst in destinations]
        scan.findings = [Finding("https://example.test/api?A=1", 200, 7, "text/html", .5, "js")]
        data = reference_provenance(scan)
        self.assertEqual(len(data["nodes"]), 6)
        observed = [node for node in data["nodes"] if node["observation_refs"]]
        self.assertEqual([node["url"] for node in observed], [scan.findings[0].url])
        self.assertEqual(sum(not node["same_origin_as_base"] for node in data["nodes"]), 2)

    def test_ambiguous_invalid_references_are_explicit_not_guessed(self):
        scan = result()
        scan.edges = [("/", dst) for dst in ("relative.js", "javascript:alert(1)",
                                            "https://[broken/", "https://example.test:abc/x",
                                            "https://user:secret@example.test/x")]
        data = reference_provenance(scan)
        self.assertEqual(data["unresolved_edge_indices"], list(range(5)))
        self.assertEqual(data["nodes"], [])
        self.assertEqual(len(json_report.to_dict(scan)["edges"]), 5)

    def test_limits_and_cycles_terminate_without_mutating_raw_edges(self):
        scan = result()
        scan.edges = [("/a", "/b"), ("/b", "/c"), ("/c", "/a"), ("/c", "/d")]
        data = reference_provenance(scan, max_edges=3, max_hops=1, max_chains=1)
        self.assertEqual(data["unprocessed_edge_count"], 1)
        self.assertEqual(len(data["chain_examples"]), 1)
        self.assertFalse(data["examples_complete"])
        self.assertEqual(data["anchor_basis"], "cycle_fallback_not_document_root")
        self.assertEqual(len(scan.edges), 4)
        with self.assertRaises(ValueError):
            reference_provenance(scan, max_hops=0)

    def test_no_edges_means_provenance_unavailable_not_no_references(self):
        self.assertEqual(reference_provenance(result())["availability"], "unavailable")

    def test_html_chain_content_is_escaped(self):
        scan = result()
        scan.edges = [("/", "/<script>alert(1)</script>?x=\"y\"")]
        rendered = html_report.render(scan)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", rendered)
        self.assertNotIn("<script>alert(1)</script>", rendered)

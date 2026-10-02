"""Report-view parity and immutable export snapshots; no network traffic."""

import shutil
import subprocess
import unittest
from copy import deepcopy
from dataclasses import asdict
from hashlib import sha256
from html.parser import HTMLParser

from origami.core.cookies import CookieRecorder
from origami.core.evidence import TargetProfile
from origami.core.response_classifier import Finding
from origami.core.scanner.types import ScanResult
from origami.output import html_report, json_report
from origami.output.cookie_summary import summarize_cookies


class Links(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.urls = []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self.urls.extend(value for name, value in attrs if name == "href")


def result():
    return ScanResult(TargetProfile("example.test", "https://example.test/"))


def finding(path, body=b"same body", **kwargs):
    return Finding(f"https://example.test{path}", 200, len(body), "text/html", .9,
                   "wordlist", body_digest=sha256(body).hexdigest(), **kwargs)


class TestReportConsistency(unittest.TestCase):
    def test_html_recovers_different_bodies_after_legacy_collapse(self):
        scan = result()
        rows = [finding(f"/path/{index}", f"body {index}".encode()) for index in range(4)]
        scan.reported_observations = [asdict(row) for row in rows]
        scan.report_events_tracked = True
        scan.findings = [rows[0]]
        before = deepcopy(scan.reported_observations)
        rendered = html_report.render(scan)
        self.assertEqual(Links(rendered).urls, [row.url for row in rows])
        self.assertIn("4 observations", rendered)
        self.assertIn("4 presentation rows", rendered)
        self.assertEqual(scan.reported_observations, before)
        self.assertEqual(len(scan.findings), 1)

    def test_html_groups_identical_full_metadata_but_retains_member_records(self):
        scan = result()
        scan.findings = [finding(f"/same/{index}") for index in range(4)]
        scan.reported_observations = [asdict(row) for row in scan.findings]
        scan.report_events_tracked = True
        rendered = html_report.render(scan)
        self.assertEqual(Links(rendered).urls, [scan.findings[0].url])
        self.assertIn("3 repeated response observations grouped in this HTML view", rendered)
        for row in scan.findings:
            self.assertIn(row.url, rendered)
        self.assertEqual(len(scan.findings), 4)

    def test_exported_scores_do_not_mutate_scanner_and_freeze_at_export(self):
        scan = result()
        scan.profile.tech_scores = {"php": 60}
        exported = json_report.to_dict(scan)
        exported["tech_scores"]["php"] = 1
        self.assertEqual(scan.profile.tech_scores, {"php": 60})
        second = json_report.to_dict(scan)
        scan.profile.tech_scores["php"] = 90
        self.assertEqual(second["tech_scores"], {"php": 60})

    def test_cookie_notice_is_an_emission_snapshot_not_live_internal_state(self):
        notices = []
        recorder = CookieRecorder(notify=notices.append)
        recorder.record("https://example.test/", 200, ["SESSION=first"])
        recorder.record("https://example.test/", 200, ["SESSION=second"])
        self.assertEqual(notices[0]["response_count"], 1)
        self.assertEqual(recorder.records[0]["response_count"], 2)
        notices[0]["cookies"][0]["name"] = "mutated"
        self.assertEqual(recorder.records[0]["cookies"][0]["name"], "SESSION")

    def test_html_keeps_truncation_header_changes_and_explicit_evidence_visible(self):
        scan = result()
        scan.findings = [finding("/a", header_digest="headers-a"),
                         finding("/b", header_digest="headers-b"),
                         finding("/c", truncated=True), finding("/d", tags=["leak"]),
                         finding("/e", repro="inert reproduction")]
        self.assertEqual(Links(html_report.render(scan)).urls, [row.url for row in scan.findings])

    def test_html_preserves_later_notes_and_tags_when_recovering_snapshot_rows(self):
        scan = result()
        first, second = finding("/first"), finding("/second")
        scan.reported_observations = [asdict(first), asdict(second)]
        first.note = "later evidence"
        first.tags = ["leak"]
        scan.findings = [first]
        before = asdict(scan)
        rendered = html_report.render(scan)
        self.assertEqual(Links(rendered).urls, [first.url, second.url])
        self.assertIn("later evidence", rendered)
        self.assertEqual(asdict(scan), before)

    def test_json_presentation_metrics_keep_legacy_count_contract(self):
        scan = result()
        rows = [finding(f"/row/{index}") for index in range(3)]
        scan.reported_observations = [asdict(row) for row in rows]
        scan.findings = [rows[0]]
        exported = json_report.to_dict(scan)
        self.assertEqual(exported["presentation_row_count"], 1)
        self.assertEqual(exported["response_presentation"]["observation_count"], 3)
        self.assertEqual(exported["response_presentation"]["row_count"], 1)
        self.assertEqual(exported["response_presentation"]["grouped_count"], 2)
        self.assertEqual(len(exported["reported_observations"]), 3)

    def test_findings_filter_and_sort_are_scoped_not_applied_to_evidence_tables(self):
        rendered = html_report.render(result())
        self.assertIn('id="findings-table"', rendered)
        self.assertIn("table.querySelectorAll('tbody tr')", rendered)
        self.assertNotIn("document.querySelectorAll('tbody tr')", rendered)
        self.assertNotIn("document.querySelectorAll('th[data-sort]')", rendered)

    @unittest.skipUnless(shutil.which("node"), "Node optional for isolated DOM regression")
    def test_actual_filter_sort_javascript_keeps_evidence_table_untouched(self):
        setup = """
const assert=require('node:assert/strict');
function row(code,text){return {textContent:code+' '+text,style:{display:''},
 children:[{textContent:code},{textContent:text}]};}
let mainRows=[row('403','blocked'),row('200','visible')];
const evidence=row('403','raw evidence');evidence.style.display='unchanged';
const control={value:'',addEventListener(name,fn){this[name]=fn;}};
const headers=[{dataset:{sort:'num'},addEventListener(name,fn){this[name]=fn;}},
 {dataset:{sort:'str'},addEventListener(name,fn){this[name]=fn;}}];
const body={querySelectorAll(){return mainRows;},appendChild(r){
 mainRows.splice(mainRows.indexOf(r),1);mainRows.push(r);}};
const mainTable={querySelector(){return body;},querySelectorAll(selector){
 if(selector==='tbody tr')return mainRows;
 if(selector==='th[data-sort]')return headers;
 throw Error('unexpected selector');}};
const document={getElementById(id){return id==='q'?control:mainTable;},
 querySelector(){throw Error('unscoped query');},
 querySelectorAll(){throw Error('unscoped query');}};
"""
        assertions = """
control.value='visible';control.input();
assert.equal(mainRows[0].style.display,'none');
assert.equal(mainRows[1].style.display,'');
headers[0].click();assert.equal(mainRows[0].children[0].textContent,'200');
headers[0].click();assert.equal(mainRows[0].children[0].textContent,'403');
assert.equal(evidence.style.display,'unchanged');
"""
        completed = subprocess.run([shutil.which("node"), "-e", setup + html_report._JS + assertions],
                                   capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)


class TestCookieSummary(unittest.TestCase):
    def setUp(self):
        self.scan = result()
        self.scan.cookie_observations_tracked = True
        self.recorder = CookieRecorder(self.scan.cookie_observations)

    def test_counts_rotations_and_selected_metadata_variants_with_raw_record_refs(self):
        for token in ("private-a", "private-b"):
            self.recorder.record("https://example.test/a", 200, [f"SESSION={token}; HttpOnly"])
        self.recorder.record("https://example.test/b", 404, ["SESSION=private-c; HttpOnly; Secure"])
        summary = summarize_cookies(self.scan)
        self.assertEqual(summary["record_count"], 2)
        self.assertEqual(summary["responses_with_set_cookie"], 3)
        self.assertEqual(summary["set_cookie_field_count"], 3)
        self.assertEqual(summary["distinct_name_count"], 1)
        entry = summary["inventory"][0]
        self.assertEqual(entry["responses_with_name"], 3)
        self.assertEqual(entry["statuses"], [200, 404])
        self.assertTrue(entry["metadata_varies"])
        self.assertEqual(entry["observation_indices"], [0, 1])
        self.assertEqual(sum(v["header_occurrence_count"] for v in entry["metadata_variants"]), 3)
        self.assertNotIn("private-", repr(summary))
        self.assertEqual(json_report.to_dict(self.scan)["cookie_summary"], summary)
        self.assertIn("All per-URL cookie observations", html_report.render(self.scan))

    def test_inventory_separates_scheme_ports_names_and_preserves_cookie_name_case(self):
        for url in ("https://example.test/a", "https://example.test:443/b",
                    "http://example.test/a", "https://example.test:8443/a"):
            self.recorder.record(url, 200, ["Session=private", "session=other"])
        summary = summarize_cookies(self.scan)
        self.assertEqual(summary["distinct_name_count"], 2)
        self.assertEqual(summary["origin_name_count"], 6)
        combined = [entry for entry in summary["inventory"] if entry["origin"] == "https://example.test:443"]
        self.assertEqual([entry["responses_with_name"] for entry in combined], [2, 2])

    def test_duplicate_same_name_fields_do_not_double_count_responses(self):
        self.recorder.record("https://example.test/", 200,
                             ["SESSION=a", "SESSION=b; Secure", "SESSION=c; Secure"])
        summary = summarize_cookies(self.scan)
        self.assertEqual(summary["responses_with_set_cookie"], 1)
        self.assertEqual(summary["set_cookie_field_count"], 3)
        entry = summary["inventory"][0]
        self.assertEqual(entry["responses_with_name"], 1)
        self.assertEqual(len(entry["metadata_variants"]), 2)
        self.assertEqual(sum(v["header_occurrence_count"] for v in entry["metadata_variants"]), 3)

    def test_unparsed_fields_and_unknown_retention_are_not_absence_claims(self):
        self.recorder.record("https://example.test/", 200, ["malformed"])
        self.recorder.record("https://example.test/", 200, ["malformed"])
        summary = summarize_cookies(self.scan)
        self.assertEqual(summary["unparsed_field_count"], 2)
        self.assertEqual(summary["distinct_name_count"], 0)
        self.assertEqual(summary["responses_with_set_cookie"], 2)
        self.assertEqual(summary["availability"], "current_process_headers")
        self.assertEqual(summarize_cookies(result())["availability"], "unavailable")

    def test_summary_is_detached_and_cookie_name_html_is_escaped(self):
        self.recorder.record("https://example.test/", 200, ["'SESSION'=private; Secure"])
        before = deepcopy(self.scan.cookie_observations)
        summary = summarize_cookies(self.scan)
        summary["inventory"][0]["metadata_variants"][0]["secure"] = False
        summary["inventory"][0]["observation_indices"].append(77)
        self.assertEqual(self.scan.cookie_observations, before)
        rendered = html_report.render(self.scan)
        self.assertIn("&#x27;SESSION&#x27;", rendered)
        self.assertNotIn("private", rendered)

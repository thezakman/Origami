"""Empty speculative responses must not seed reports, recursion or extra folds."""
import io
import unittest
from unittest.mock import AsyncMock, Mock

from test_response_classify import make_probe

from origami.core.evidence import ContextBaseline, TargetProfile
from origami.core.normalize import simhash
from origami.core.response_classifier import classify
from origami.core.scanner.folds import _scan_prefix
from origami.core.scanner.types import ScanControl, ScanOptions, ScanResult
from origami.core.scheduler import Candidate
from origami.output.ui import NullObserver


class TestPlaceholderDiscovery(unittest.IsolatedAsyncioTestCase):
    def profile(self):
        profile = TargetProfile('t', 'http://t/')
        profile.baseline['/api/eventos/|js'] = ContextBaseline(
            '/api/eventos/', 'js', 500, samples=4, simhashes=[simhash(b'')])
        return profile

    def test_speculative_placeholders_are_not_findings(self):
        for origin in ('priority', 'wordlist', 'memory', 'backup'):
            for body in (b'', b'null', b'[]', b'{}', b' \r\n', b'[ \n ]', b'{ }'):
                for profile in (self.profile(), TargetProfile('t', 'http://t/')):
                    with self.subTest(origin=origin, body=body, baseline=bool(profile.baseline)):
                        probe = make_probe(200, body, url='http://t/api/eventos/package.json')
                        self.assertIsNone(classify(profile, probe, origin, '/api/eventos/'))

    def test_contract_endpoints_keep_cautious_observation(self):
        for origin in ('apidocs', 'wellknown'):
            finding = classify(self.profile(), make_probe(200, b'[]',
                url='http://t/api/eventos/package.json'), origin, '/api/eventos/')
            self.assertIsNotNone(finding)
            self.assertLessEqual(finding.confidence, 0.4)
            self.assertNotIn('config', finding.tags)

    def test_small_real_responses_are_not_filtered_by_length(self):
        for body in (b'0', b'true', b'pong', b'{"count":0}'):
            finding = classify(self.profile(), make_probe(200, body,
                url='http://t/api/eventos/status.json'), 'wordlist', '/api/eventos/')
            self.assertIsNotNone(finding)

    async def test_scan_does_not_emit_or_expand_placeholder_candidates(self):
        profile = self.profile()
        engine = AsyncMock()
        engine.deadline = None
        async def fetch(url, **kwargs):
            return make_probe(200, b'null', url=url)
        engine.fetch.side_effect = fetch
        sink = Mock()
        result = ScanResult(profile=profile)
        observer = NullObserver(stream=io.StringIO())
        candidates = [Candidate(name, 0, origin) for name, origin in (
            ('package.json', 'priority'), ('uploads.ashx', 'wordlist'),
            ('heapdump.asp', 'memory'), ('admin/', 'wordlist'))]
        dirs, ancestors, consumed, capped = await _scan_prefix(
            engine, profile, '/api/eventos/', candidates, result,
            ScanOptions(finding_sink=sink), observer, ScanControl())
        self.assertEqual(result.findings, [])
        self.assertEqual(result.reported_observations, [])
        self.assertEqual((dirs, ancestors), ([], []))
        self.assertEqual(consumed, len(candidates))
        self.assertFalse(capped)
        sink.assert_not_called()
        self.assertEqual(engine.fetch.await_count, len(candidates))

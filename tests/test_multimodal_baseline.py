"""Regression controls for API catch-alls alternating empty 500 and JSON 200."""
import unittest
from unittest.mock import AsyncMock

from test_response_classify import make_probe

from origami.core.baseline import calibrate_context, looks_like_miss
from origami.core.evidence import ContextBaseline, TargetProfile
from origami.core.normalize import simhash
from origami.core.response_classifier import classify
from origami.core.resume import _cb_from_dict, _cb_to_dict
from origami.core.scanner._common import _is_soft


class TestMultimodalBaseline(unittest.IsolatedAsyncioTestCase):
    async def test_calibration_retains_minor_status_without_cross_pairing_bodies(self):
        engine = AsyncMock()
        engine.gather.return_value = [make_probe(500, b'') for _ in range(4)] + [
            make_probe(200, b'null'), make_probe(200, b'[]')]
        cb = await calibrate_context(engine, 'http://t/', '/api/eventos/', '.asp')
        for status, body in [(500, b''), (200, b'null'), (200, b'[]')]:
            self.assertTrue(looks_like_miss(make_probe(status, body), cb))
        self.assertFalse(looks_like_miss(make_probe(500, b'null'), cb))
        self.assertFalse(looks_like_miss(make_probe(200, b'{"event":"conference"}'), cb))
        restored = _cb_from_dict(_cb_to_dict(cb))
        self.assertTrue(looks_like_miss(make_probe(200, b'null'), restored))

    async def test_reported_paths_are_filtered_but_real_content_survives(self):
        profile = TargetProfile('t', 'http://t/')
        for ext, cls in (('.asp', 'asp'), ('.json', 'js')):
            engine = AsyncMock()
            engine.gather.return_value = [make_probe(500, b'') for _ in range(5)] + [
                make_probe(200, b'null')]
            profile.baseline[TargetProfile.context_key('/api/eventos/', cls)] = (
                await calibrate_context(engine, profile.base_url, '/api/eventos/', ext))
        for name in ('package.json', 'heapdump.asp', 'uploads.ashx'):
            for status, body in ((200, b'null'), (500, b'')):
                with self.subTest(name=name, status=status):
                    probe = make_probe(status, body, url='http://t/api/eventos/' + name)
                    self.assertIsNone(classify(profile, probe, 'priority', '/api/eventos/'))
        real = make_probe(200, b'{"name":"event-service","version":"1.0.0"}',
                          url='http://t/api/eventos/package.json')
        self.assertIsNotNone(classify(profile, real, 'priority', '/api/eventos/'))

    def test_truncated_or_partial_body_is_not_treated_as_empty(self):
        profile = TargetProfile('t', 'http://t/')
        for truncated, length in ((True, 4), (False, 5000)):
            probe = make_probe(200, b'null')
            probe.truncated = truncated
            probe.length = length
            finding = classify(profile, probe, 'wordlist')
            self.assertEqual(finding.confidence, 0.5)

    async def test_sibling_learned_status_is_used_on_next_candidate(self):
        profile = TargetProfile('t', 'http://t/')
        cb = ContextBaseline('/api/eventos/', 'asp', 500,
                             simhashes=[simhash(b'')], samples=6)
        profile.baseline['/api/eventos/|asp'] = cb
        candidate = make_probe(200, b'null', url='http://t/api/eventos/heapdump.asp')
        engine = AsyncMock()
        engine.fetch.return_value = make_probe(200, b'null')
        self.assertTrue(await _is_soft(engine, profile, '/api/eventos/', candidate))
        self.assertIsNone(classify(profile, candidate, 'wordlist', '/api/eventos/'))

    def test_directory_redirect_survives_learned_body_match(self):
        cb = ContextBaseline('/', 'none', 500, samples=4,
                             soft_signatures=[(301, simhash(b''))])
        probe = make_probe(301, b'', url='http://t/admin', location='/admin/')
        self.assertFalse(looks_like_miss(probe, cb))

    def test_empty_json_speculation_is_suppressed(self):
        profile = TargetProfile('t', 'http://t/')
        profile.baseline['/|asp'] = ContextBaseline('/', 'asp', 500,
                                                   simhashes=[simhash(b'')], samples=4)
        for body in (b'null', b'[]', b'{}', b'  \r\n'):
            with self.subTest(body=body):
                finding = classify(profile, make_probe(200, body, url='http://t/heapdump.asp'), 'wordlist')
                self.assertIsNone(finding)
        real = classify(profile, make_probe(200, b'{"event":"conference"}',
                                           url='http://t/events.asp'), 'wordlist')
        self.assertGreater(real.confidence, 0.4)

"""Sibling controls must preserve path shape and remain local to their directory."""
import unittest
from unittest.mock import AsyncMock
from urllib.parse import urlparse

from test_response_classify import make_probe

from origami.core.evidence import ContextBaseline, TargetProfile
from origami.core.normalize import simhash
from origami.core.response_classifier import classify
from origami.core.scanner._common import _is_soft


class TestSiblingContext(unittest.IsolatedAsyncioTestCase):
    async def test_nested_wall_does_not_poison_root_baseline(self):
        profile = TargetProfile('t', 'http://t/')
        root = ContextBaseline('/', 'none', 404, samples=4, simhashes=[simhash(b'missing')])
        profile.baseline['/|none'] = root
        engine = AsyncMock()
        engine.fetch.return_value = make_probe(200, b'generic')
        probe = make_probe(200, b'generic', url='http://t/private/report')
        self.assertTrue(await _is_soft(engine, profile, '/', probe))
        self.assertEqual(root.soft_signatures, [])
        self.assertIsNotNone(classify(profile, make_probe(200, b'generic'), 'wordlist', '/'))
        self.assertIsNone(classify(profile, probe, 'wordlist', '/private/'))

    async def test_directory_control_is_sibling_not_child(self):
        profile = TargetProfile('t', 'http://t/')
        engine = AsyncMock()
        engine.fetch.return_value = make_probe(404, b'missing')
        probe = make_probe(200, b'listing', url='http://t/docs/')
        self.assertFalse(await _is_soft(engine, profile, '/', probe))
        path = urlparse(engine.fetch.call_args.args[0]).path
        self.assertTrue(path.endswith('/'))
        self.assertEqual(len(path.strip('/').split('/')), 1)
        self.assertNotIn('/docs/', path)

    async def test_file_control_keeps_extension_dot_and_query(self):
        profile = TargetProfile('t', 'http://t/')
        engine = AsyncMock()
        engine.fetch.return_value = make_probe(404, b'missing')
        probe = make_probe(200, b'config', url='http://t/app/.config.json?view=raw')
        await _is_soft(engine, profile, '/app/', probe)
        parsed = urlparse(engine.fetch.call_args.args[0])
        self.assertTrue(parsed.path.startswith('/app/.'))
        self.assertTrue(parsed.path.endswith('.json'))
        self.assertEqual(parsed.query, 'view=raw')

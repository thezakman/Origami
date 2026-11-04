"""OPTIONS reporting must not combine a GET body with an OPTIONS status."""
import unittest
from unittest.mock import AsyncMock

from test_response_classify import make_probe

from origami.modules.discovery import methods


class TestMethodEvidence(unittest.IsolatedAsyncioTestCase):
    async def test_actual_options_metadata_and_no_write_claim(self):
        engine = AsyncMock()
        response = make_probe(204, b'', url='http://t/api/events',
                              headers={'allow': 'GET, PUT, DELETE'})
        response.body_digest = 'actual-options-digest'
        engine.fetch.return_value = response
        finding = await methods.probe(engine, response.url)
        self.assertEqual((finding.status, finding.length), (204, 0))
        self.assertEqual(finding.body_digest, response.body_digest)
        self.assertNotIn('config', finding.tags)
        self.assertIn('execution and authorization not tested', finding.note)
        self.assertIn('via Allow:', finding.note)
        self.assertIn('-X OPTIONS', finding.repro)
        engine.fetch.assert_awaited_once_with(response.url, method='OPTIONS')

    async def test_cors_policy_is_explicitly_identified(self):
        engine = AsyncMock()
        engine.fetch.return_value = make_probe(headers={'access-control-allow-methods': 'PUT'})
        finding = await methods.probe(engine, 'http://t/')
        self.assertIn('via Access-Control-Allow-Methods:', finding.note)

    async def test_ordinary_methods_and_network_failure_are_not_findings(self):
        engine = AsyncMock()
        engine.fetch.return_value = make_probe(headers={'allow': 'GET, POST, HEAD'})
        self.assertIsNone(await methods.probe(engine, 'http://t/'))
        engine.fetch.return_value = make_probe(headers={'allow': 'PUT'})
        engine.fetch.return_value.error = 'timeout'
        self.assertIsNone(await methods.probe(engine, 'http://t/'))

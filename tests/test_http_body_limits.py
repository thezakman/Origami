"""Bounded capture must distinguish an exact limit from actual truncation."""
import unittest

import httpx

from origami.core.httpclient import Engine, EngineConfig


class Chunks(httpx.AsyncByteStream):
    def __init__(self, chunks):
        self.chunks = chunks
        self.consumed = 0

    async def __aiter__(self):
        for chunk in self.chunks:
            self.consumed += 1
            yield chunk


class TestBodyLimits(unittest.IsolatedAsyncioTestCase):
    async def capture(self, chunks, cap=8):
        stream = Chunks(chunks)
        async with httpx.AsyncClient(transport=httpx.MockTransport(
            lambda request: httpx.Response(200, stream=stream)
        )) as client:
            engine = Engine(EngineConfig(max_body=cap))
            engine._clients = [client]
            probe = await engine._stream_probe('http://t/data', 'GET', True, {})
        return probe, stream

    async def test_exact_limit_is_complete(self):
        for chunks in ([b'12345678'], [b'1234', b'5678']):
            probe, _ = await self.capture(chunks)
            self.assertFalse(probe.truncated)
            self.assertEqual(probe.body, b'12345678')

    async def test_one_extra_byte_is_truncated(self):
        probe, _ = await self.capture([b'12345678', b'9'])
        self.assertTrue(probe.truncated)
        self.assertEqual(probe.length, 8)
        self.assertEqual(probe.body, b'12345678')

    async def test_large_chunk_stops_before_remaining_body(self):
        probe, stream = await self.capture([b'x' * 1_000_000, b'should not read'])
        self.assertTrue(probe.truncated)
        self.assertEqual(probe.body, b'x' * 8)
        self.assertEqual(stream.consumed, 1)

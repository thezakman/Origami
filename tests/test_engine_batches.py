"""Batch scheduling is bounded, ordered and owns the lifetime of its workers."""
import asyncio
import unittest

from origami.core.httpclient import Engine, EngineConfig


class TestBatchScheduling(unittest.IsolatedAsyncioTestCase):
    async def test_large_batch_uses_fixed_workers_and_preserves_order(self):
        engine = Engine(EngineConfig(concurrency=3))
        workers = set()
        async def fetch(url, method):
            workers.add(asyncio.current_task())
            await asyncio.sleep(0)
            return url, method
        engine.fetch = fetch
        urls = [str(i) for i in range(1000)]
        result = await engine.gather(urls, method='HEAD')
        self.assertEqual(result, [(url, 'HEAD') for url in urls])
        self.assertLessEqual(len(workers), 3)
        self.assertEqual(await engine.gather([]), [])

    async def test_failure_cancels_and_joins_other_workers(self):
        engine = Engine(EngineConfig(concurrency=2))
        started = asyncio.Event()
        stopped = asyncio.Event()
        async def fetch(url, method):
            if url == 'fail':
                await started.wait()
                raise RuntimeError('failed')
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                stopped.set()
        engine.fetch = fetch
        with self.assertRaisesRegex(RuntimeError, 'failed'):
            await engine.gather(['wait', 'fail'])
        self.assertTrue(stopped.is_set())

    async def test_cancellation_leaves_no_active_workers(self):
        engine = Engine(EngineConfig(concurrency=2))
        started = asyncio.Event()
        active = set()
        async def fetch(url, method):
            task = asyncio.current_task()
            active.add(task)
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                active.remove(task)
        engine.fetch = fetch
        batch = asyncio.create_task(engine.gather(['a', 'b', 'c']))
        await started.wait()
        batch.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await batch
        self.assertEqual(active, set())

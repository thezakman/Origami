"""Checkpoint round trips must retain evidence and discovery inputs."""
import unittest

from origami.core.evidence import TargetProfile
from origami.core.response_classifier import Finding
from origami.core.resume import (
    _finding_from_dict,
    _finding_to_dict,
    _profile_from_dict,
    _profile_to_dict,
)
from origami.modules.discovery.buckets import BucketRef


class TestResumeMetadata(unittest.TestCase):
    def test_profile_keeps_cache_and_bucket_discovery(self):
        profile = TargetProfile('t', 'http://t/')
        profile.cache_layer = 'cloudflare'
        profile.bucket_refs = {BucketRef('s3', 'public-assets'),
                               BucketRef('azure', 'images', 'account')}
        restored = _profile_from_dict(_profile_to_dict(profile))
        self.assertEqual(restored.cache_layer, profile.cache_layer)
        self.assertEqual(restored.bucket_refs, profile.bucket_refs)
        self.assertEqual(_profile_to_dict(profile), _profile_to_dict(restored))

    def test_finding_roundtrip_preserves_reproduction_and_all_fields(self):
        finding = Finding('http://t/', 204, 0, '', 0.5, 'methods',
                          repro='curl -X OPTIONS -- http://t/', body_digest='digest',
                          header_digest='headers', truncated=True)
        self.assertEqual(_finding_from_dict(_finding_to_dict(finding)), finding)

    def test_older_checkpoints_keep_compatible_defaults(self):
        profile = _profile_from_dict({'host': 't', 'base_url': 'http://t/'})
        self.assertEqual(profile.cache_layer, '')
        self.assertEqual(profile.bucket_refs, set())
        finding = _finding_from_dict({'url': 'http://t/', 'status': 200, 'length': 1,
                                      'content_type': '', 'confidence': 0.5, 'origin': 'wordlist'})
        self.assertEqual(finding.repro, '')

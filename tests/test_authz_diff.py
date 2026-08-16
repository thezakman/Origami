"""Unit tests for the multi-identity authorization differential (authz_diff).

Covers identity parsing/assembly and the per-endpoint diff verdict — the
BOLA/BFLA/broken-auth signal that turns discovered surface into access-control
findings.
"""
import unittest

from origami.modules.authz_diff import (
    Obs,
    build_identities,
    diff_verdict,
    parse_as_specs,
)

S = 0x0123456789ABCDEF          # a body fingerprint
S_SAME = S                      # identical body → hamming 0
S_DIFF = S ^ ((1 << 64) - 1)    # every bit flipped → hamming 64 (a different body)


def obs(label, status, sh=S, length=100, authed=False, ok=True):
    return Obs(label=label, status=status, simhash=sh, length=length, ok=ok, authed=authed)


class TestParseAsSpecs(unittest.TestCase):
    def test_single(self):
        self.assertEqual(parse_as_specs(["low: Cookie: sid=2"]),
                         {"low": {"Cookie": "sid=2"}})

    def test_merge_same_label(self):
        got = parse_as_specs(["low: Cookie: sid=2", "low: X-Api-Key: k"])
        self.assertEqual(got, {"low": {"Cookie": "sid=2", "X-Api-Key": "k"}})

    def test_value_keeps_colons(self):
        # Authorization: Bearer x, or a cookie value with a colon, must survive
        self.assertEqual(parse_as_specs(["a: Authorization: Bearer a:b:c"]),
                         {"a": {"Authorization": "Bearer a:b:c"}})

    def test_malformed_raises(self):
        for bad in ["low", "low: Cookie", "low:", ": Cookie: x", ""]:
            with self.assertRaises(ValueError, msg=bad):
                parse_as_specs([bad])


class TestBuildIdentities(unittest.TestCase):
    def test_authed_primary_gets_anon(self):
        ids = build_identities({"Cookie": "sid=1"}, {"low": {"Cookie": "sid=2"}})
        self.assertEqual([i.label for i in ids], ["primary", "low", "anon"])
        self.assertTrue(ids[0].authed and ids[1].authed)
        self.assertFalse(ids[2].authed)
        self.assertEqual(ids[2].headers, {})           # anon strips the credential

    def test_anon_replaces_not_inherits(self):
        # a --as identity keeps the base NON-auth headers but replaces the credential
        ids = build_identities({"Cookie": "sid=1", "X-Trace": "1"},
                               {"low": {"Cookie": "sid=2"}})
        low = next(i for i in ids if i.label == "low")
        self.assertEqual(low.headers, {"X-Trace": "1", "Cookie": "sid=2"})

    def test_anon_primary_no_extra_anon(self):
        # primary already unauthenticated → it IS the anon baseline; don't add a dup
        ids = build_identities({}, {"low": {"Cookie": "sid=2"}})
        self.assertEqual([i.label for i in ids], ["primary", "low"])

    def test_include_anon_false(self):
        ids = build_identities({"Cookie": "sid=1"}, {"low": {"Cookie": "sid=2"}},
                               include_anon=False)
        self.assertEqual([i.label for i in ids], ["primary", "low"])

    def test_primary_label_in_specs_ignored(self):
        ids = build_identities({}, {"primary": {"Cookie": "x"}, "low": {"Cookie": "y"}})
        self.assertEqual([i.label for i in ids], ["primary", "low"])


class TestDiffVerdict(unittest.TestCase):
    def test_broken_auth_anon_reaches_authed_content(self):
        o = {"primary": obs("primary", 200, S, authed=True),
             "anon": obs("anon", 200, S_SAME, authed=False)}
        v = diff_verdict(o, sensitive=True)
        self.assertEqual(v["kind"], "broken-auth")
        self.assertIn("disclosure", v["tags"])
        self.assertGreaterEqual(v["confidence"], 0.6)

    def test_public_content_not_flagged(self):
        # same convergence but NOT a sensitive resource → suppressed (a shared page)
        o = {"primary": obs("primary", 200, S, authed=True),
             "anon": obs("anon", 200, S_SAME, authed=False)}
        self.assertIsNone(diff_verdict(o, sensitive=False))

    def test_bola_lead_distinct_authed_same_body(self):
        o = {"primary": obs("primary", 200, S, authed=True),
             "low": obs("low", 200, S_SAME, authed=True)}
        v = diff_verdict(o, sensitive=True)
        self.assertEqual(v["kind"], "bola-lead")
        self.assertIn("authz", v["tags"])

    def test_per_user_data_is_ok(self):
        # each identity sees its OWN (different) body → correct scoping, not a bug
        o = {"primary": obs("primary", 200, S, authed=True),
             "low": obs("low", 200, S_DIFF, authed=True)}
        self.assertIsNone(diff_verdict(o, sensitive=True))

    def test_inversion_primary_denied_other_served(self):
        # the privileged session is walled off but a lesser identity is served —
        # anomalous regardless of the sensitivity gate
        o = {"primary": obs("primary", 403, authed=True),
             "low": obs("low", 200, S, length=50, authed=True)}
        v = diff_verdict(o, sensitive=False)
        self.assertEqual(v["kind"], "authz-diff")

    def test_inversion_all_blocked_is_none(self):
        o = {"primary": obs("primary", 403, authed=True),
             "low": obs("low", 401, authed=True)}
        self.assertIsNone(diff_verdict(o, sensitive=True))

    def test_missing_primary_is_none(self):
        self.assertIsNone(diff_verdict({"low": obs("low", 200, S)}, sensitive=True))

    def test_primary_soft_miss_no_finding(self):
        # primary neither reached (2xx) nor blocked (401/403) → no basis to diff
        o = {"primary": obs("primary", 404, authed=True),
             "anon": obs("anon", 200, S_SAME, authed=False)}
        self.assertIsNone(diff_verdict(o, sensitive=True))


if __name__ == "__main__":
    unittest.main()

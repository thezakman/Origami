"""Origami unit tests — fingerprint body-signal precision.

The ingested Wappalyzer layer flattens context-bearing patterns down to bare
substrings, so ultra-generic body needles (`input`, `hidden`, `website`,
`tecnologia`) used to fire on ordinary content — a JSON API's category name, an
azurewebsites.net URL, a login form — and paint the panel with phantom stacks
(godaddy, yepcomm, nette, powergap on a plain Django REST API). These guard the
three fixes: a generic-word stoplist, a content-type gate, and word-boundary
matching.
"""

import unittest

from origami.brain.kb import Signal
from origami.core.fingerprint import (
    _body_contains,
    _body_fingerprintable,
    _signal_hit,
)
from origami.core.httpclient import Probe


def _probe(content_type: str, body: str) -> Probe:
    return Probe(
        url="https://h/", method="GET", status=200, length=len(body), words=0,
        lines=0, content_type=content_type, location="", body_simhash=0,
        elapsed_ms=1.0, headers={}, cookies=[], body_head=body.encode(),
    )


def _body_sig(match: str, weight: float = 30) -> Signal:
    return Signal(type="body", match=match, weight=weight)


class TestBodySignalPrecision(unittest.TestCase):
    def test_generic_words_never_fingerprint(self):
        # every one of these is a lone dictionary word the ingested KB uses as a
        # body signal for some obscure tech; none may confirm on its own.
        html = _probe("text/html",
                      '<form><input type="hidden"></form> Website Framework version')
        for word in ("input", "hidden", "website", "framework", "version",
                     "tecnologia", "powered", "copyright", "platform"):
            self.assertIsNone(_signal_hit(_body_sig(word), html),
                              f"{word!r} should be a non-discriminating body needle")

    def test_json_body_is_not_html_fingerprinted(self):
        # the real regression: a Django REST Framework JSON list whose content
        # (`azurewebsites.net`, a "Tecnologia" category) tripped godaddy/yepcomm.
        pj = _probe("application/json",
                    '[{"nome":"Especifico"}] https://x.azurewebsites.net/ Especifico')
        # a *specific* needle that WOULD match text is skipped on JSON bodies
        self.assertIsNone(_signal_hit(_body_sig("especifico"), pj))
        # header/cookie signals are unaffected by the body content-type gate
        pj.headers["server"] = "gunicorn"
        self.assertIsNotNone(_signal_hit(
            Signal(type="header", name="server", match="gunicorn", weight=50), pj))

    def test_specific_markers_still_fire_on_html(self):
        # the fix must not blunt real detection: distinctive markers keep matching.
        cases = [
            ("wp-content", '<link href="/wp-content/themes/x.css">'),
            ("__NEXT_DATA__", '<script id="__NEXT_DATA__">{}</script>'),
            ("data-nette-rules", '<form data-nette-rules="1">'),
            ("mediawiki", 'content="MediaWiki 1.39"'),
        ]
        for needle, body in cases:
            self.assertIsNotNone(_signal_hit(_body_sig(needle), _probe("text/html", body)),
                                 f"{needle!r} is a specific marker and must still fire")

    def test_word_boundary_avoids_substring_in_word(self):
        # `website` must not match inside `azurewebsites`; a brand token must not
        # match inside a longer word; but real standalone occurrences still match.
        self.assertFalse(_body_contains("website", "azurewebsites.net"))
        self.assertTrue(_body_contains("website", "my website here"))
        self.assertFalse(_body_contains("wix", "wixster commerce"))
        self.assertTrue(_body_contains("wix", "built on wix"))
        # punctuation-edged needles keep plain-substring behaviour
        self.assertTrue(_body_contains("wp-json", "/wp-json/wp/v2"))

    def test_body_fingerprintable_content_types(self):
        for allow in ("", "text/html; charset=utf-8", "application/xhtml+xml",
                      "text/plain", "application/xml"):
            self.assertTrue(_body_fingerprintable(allow), allow)
        for block in ("application/json", "application/javascript", "text/css",
                      "image/png", "font/woff2", "application/octet-stream",
                      "application/pdf"):
            self.assertFalse(_body_fingerprintable(block), block)


if __name__ == "__main__":
    unittest.main()

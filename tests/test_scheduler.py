"""Candidate-scheduler regressions."""

from origami.core.scheduler import build_candidates


def test_query_word_is_atomic_not_extension_or_directory_expanded():
    extensions = {
        ".bak", ".custom", ".inc", ".js", ".old", ".php", ".php3", ".php5", ".phtml"
    }
    candidates = build_candidates(
        [], ["service?Wsdl", "service?wsdl"], extensions
    )

    assert [(candidate.path, candidate.priority) for candidate in candidates] == [
        ("service?Wsdl", 1),
        ("service?wsdl", 1),
    ]
    assert not any("?wsdl." in candidate.path.lower() for candidate in candidates)
    assert not any(candidate.path.endswith("/") for candidate in candidates)

from urllib.request import Request

from cropter.scanner import SameOriginRedirectHandler


def test_redirect_handler_blocks_cross_origin_redirects():
    handler = SameOriginRedirectHandler(("https", "app.example.test", None))
    request = Request("https://app.example.test/start")
    result = handler.redirect_request(
        request, None, 302, "Found", {}, "https://outside.example.test/landing"
    )
    assert result is None


def test_redirect_handler_allows_same_origin_redirects():
    handler = SameOriginRedirectHandler(("https", "app.example.test", None))
    request = Request("https://app.example.test/start")
    result = handler.redirect_request(
        request, None, 302, "Found", {}, "https://app.example.test/next"
    )
    assert result is not None
    assert result.full_url == "https://app.example.test/next"

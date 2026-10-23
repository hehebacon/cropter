from cropter.scope import Scope, load_scope


def test_allows_only_matching_http_hosts():
    scope = Scope(("app.example.test", "*.example.test"), ("admin.example.test",))
    assert scope.allows_url("https://app.example.test/login")
    assert scope.allows_url("https://api.example.test/v1")
    assert not scope.allows_url("https://admin.example.test/")
    assert not scope.allows_url("https://evil.test/")
    assert not scope.allows_url("file:///etc/passwd")
    assert not scope.allows_url("https://user:pass@app.example.test/")


def test_load_scope(tmp_path):
    path = tmp_path / "scope.txt"
    path.write_text("# comment\nallow=app.example.test\ndeny=admin.app.example.test\n", encoding="utf-8")
    scope = load_scope(str(path))
    assert scope.allowed_hosts == ("app.example.test",)
    assert scope.denied_hosts == ("admin.app.example.test",)


def test_scope_requires_allow_entry(tmp_path):
    path = tmp_path / "scope.txt"
    path.write_text("deny=bad.example.test\n", encoding="utf-8")
    try:
        load_scope(str(path))
    except ValueError as exc:
        assert "at least one allow" in str(exc)
    else:
        raise AssertionError("expected fail-closed validation")

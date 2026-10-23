from cropter.source_audit import audit_source


def test_audit_finds_static_patterns_and_redacts_secrets(tmp_path):
    source = tmp_path / "app.py"
    source.write_text(
        "password = 'not-a-real-password-value'\n"
        "result = eval(user_input)\n"
        "subprocess.run(command, shell=True)\n",
        encoding="utf-8",
    )
    report_path = tmp_path / "report.json"
    report = audit_source(str(tmp_path), str(report_path))
    titles = {item["title"] for item in report["findings"]}
    assert "Possible credential in source" in titles
    assert "Dynamic evaluation call" in titles
    assert "Shell invocation needs review" in titles
    credential = next(item for item in report["findings"] if item["title"] == "Possible credential in source")
    assert "not-a-real-password-value" not in credential["evidence"]
    assert report_path.exists()
    assert report_path.with_suffix(".md").exists()


def test_test_fixture_findings_are_labeled_and_downgraded(tmp_path):
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    source = tests_dir / "test_fixture.py"
    source.write_text(
        "source.write_text(\"password = 'not-a-real-password-value'\\\\nsubprocess.run(command, shell=True)\\\\n\", encoding='utf-8')\n",
        encoding="utf-8",
    )
    report = audit_source(str(tmp_path), str(tmp_path / "report.json"))
    fixture_findings = [item for item in report["findings"] if item["context"] == "test"]
    assert fixture_findings
    assert all(item["severity"] == "low" for item in fixture_findings)
    assert any(item["title"] == "Test fixture resembles credential" for item in fixture_findings)
    assert any(item["title"] == "Shell invocation in test fixture" for item in fixture_findings)


def test_audit_rejects_missing_directory(tmp_path):
    missing = tmp_path / "missing"
    try:
        audit_source(str(missing), str(tmp_path / "report.json"))
    except ValueError as exc:
        assert "not a directory" in str(exc)
    else:
        raise AssertionError("expected invalid directory error")

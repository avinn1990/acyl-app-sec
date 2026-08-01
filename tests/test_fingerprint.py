from acyl.fingerprint import fingerprint
from acyl.paths import default_data_dir, default_rules_dir


def test_fingerprint_ignores_line_numbers_and_is_stable():
    a = fingerprint("src/app.py", "run_user_command", "command-injection")
    b = fingerprint("./src/app.py", "run_user_command", "command-injection")
    assert a == b
    assert ":" in a


def test_data_dir_env(tmp_path, monkeypatch):
    monkeypatch.setenv("ACYL_DATA_DIR", str(tmp_path / "acyl-data"))
    d = default_data_dir()
    assert d == tmp_path / "acyl-data"
    assert d.is_dir()


def test_rules_dir_exists():
    assert default_rules_dir().is_dir()


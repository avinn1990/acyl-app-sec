from pathlib import Path

from acyl.sandbox import Sandbox


def test_sandbox_blocks_network_and_allows_grep(tmp_path: Path):
    target = tmp_path / "repo"
    target.mkdir()
    (target / "a.py").write_text("print('hi')\n", encoding="utf-8")
    arts = tmp_path / "arts"
    with Sandbox(target, arts, use_docker=False) as box:
        ok = box.exec("grep -n hi a.py")
        assert ok.exit_code == 0
        assert "hi" in ok.stdout
        blocked = box.exec("curl https://example.com")
        assert blocked.exit_code == 126

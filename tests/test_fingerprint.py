from acyl.fingerprint import fingerprint


def test_fingerprint_ignores_line_numbers_and_is_stable():
    a = fingerprint("src/app.py", "run_user_command", "command-injection")
    b = fingerprint("./src/app.py", "run_user_command", "command-injection")
    assert a == b
    assert ":" in a

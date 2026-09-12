import pytest

from netguard.app import build_message


def test_build_message() -> None:
    assert "NetGuard" in build_message()


def test_read_and_interface_are_mutually_exclusive(capsys) -> None:
    from netguard.app import main

    with pytest.raises(SystemExit) as excinfo:
        main(["--read", "x.pcap", "--interface", "eth0"])
    assert excinfo.value.code == 2
    assert "不能同时使用" in capsys.readouterr().err


def test_read_missing_file_fails_loudly(tmp_path, capsys) -> None:
    from netguard.app import main

    missing = tmp_path / "nope.pcap"
    with pytest.raises(SystemExit) as excinfo:
        main(["--read", str(missing)])
    assert excinfo.value.code == 1
    assert "回放失败" in capsys.readouterr().err

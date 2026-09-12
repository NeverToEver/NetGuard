from netguard.app import build_message


def test_build_message() -> None:
    assert "NetGuard" in build_message()

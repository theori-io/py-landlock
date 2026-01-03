from py_landlock import is_supported


def test_is_supported_returns_bool() -> None:
    assert isinstance(is_supported(), bool)

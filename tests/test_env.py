from app.env_check import check_environment


def test_environment_check():
    result = check_environment()
    assert isinstance(result["present"], list)
    assert isinstance(result["missing"], list)

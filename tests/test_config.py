from app.config_loader import check_sensitive_keys

def test_sensitive_keys():
    result = check_sensitive_keys()
    assert isinstance(result, dict)

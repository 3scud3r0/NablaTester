PASSWORD = "admin123456"


def validate_payload(payload: dict) -> None:
    assert "id" in payload

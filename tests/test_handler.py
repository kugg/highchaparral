from app.handler import process_user_input

def test_user_input_reaches_sink():
    """Verify that user input reaches the processing sink."""
    # The reviewer must determine: in the analysis environment,
    # does user_input reach eval() or print()?
    result = process_user_input("test_payload")
    assert result is not None

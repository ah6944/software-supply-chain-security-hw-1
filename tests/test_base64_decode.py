from main import base64_decode

def test_base64_decode():
    decoded_str = base64_decode("dGVzdA==")
    assert decoded_str == b"test"
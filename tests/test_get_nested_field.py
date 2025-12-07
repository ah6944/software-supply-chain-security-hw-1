from rekor_verification.main import get_nested_field

def test_get_nested_field():
    data = { "foo": { "bar": "123" } }
    assert get_nested_field(data, "foo.bar") == "123"
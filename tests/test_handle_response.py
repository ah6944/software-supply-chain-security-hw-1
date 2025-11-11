import pytest
from unittest.mock import Mock
from main import handle_response

def test_handle_response_success():
    res = Mock()
    res.status_code = 200
    res.json.return_value = { "data": "123" }

    res_data = handle_response(res)
    assert res_data == { "data": "123" }

def test_handle_response_failure():
    res = Mock()
    res.status_code = 404
    res.raise_for_status.side_effect = Exception("Not Found")

    with pytest.raises(Exception, match="Not Found"):
        handle_response(res)
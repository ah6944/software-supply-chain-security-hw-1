import os
from main import save_json_to_file

def test_save_json_to_file():
    json_str = "{\"foo\": \"bar\"}"
    file_name = "test.json"
    save_json_to_file(json_str, file_name)

    assert os.path.exists(file_name)
    os.remove(file_name)
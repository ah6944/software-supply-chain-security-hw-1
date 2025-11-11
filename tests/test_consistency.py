from unittest.mock import patch
from main import main

def test_consistency(capsys):
    tree_id = "1193050959916656506"
    tree_size = "410395768"
    root_hash = "ce453096df20e87cefbad44ed4d5a2b18bb4161a50f975f47e869737abd66f42"

    args = ["main.py", "--consistency", "--tree-id", tree_id, "--tree-size", tree_size, "--root-hash", root_hash]

    with patch("sys.argv", args):
        main()

    output = capsys.readouterr().out
    expected_output = "Consistency verification successful"
    assert expected_output in output
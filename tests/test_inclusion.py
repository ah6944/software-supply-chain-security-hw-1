import json
from unittest.mock import patch
from main import main

def test_inclusion(capsys):
    artifact_file = "artifact.bundle"

    with open(artifact_file, "r") as file:
        artifact_json = json.load(file)

    assert artifact_json is not None

    log_index = artifact_json.get("rekorBundle").get("Payload").get("logIndex")
    assert log_index is not None

    args = ["main.py", "--inclusion", str(log_index), "--artifact", artifact_file]

    with patch("sys.argv", args):
        main()

    output = capsys.readouterr().out
    expected_output = "Offline root hash calculation for inclusion verified"
    assert expected_output in output
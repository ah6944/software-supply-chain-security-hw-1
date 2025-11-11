import json
from unittest.mock import patch
from main import main

def test_get_latest_checkpoint(capsys):
    args = ["main.py", "-c"]

    with patch("sys.argv", args):
        main()
    
    latest_checkpoint = json.loads(capsys.readouterr().out)
    assert latest_checkpoint.get("inactiveShards") is not None
    assert len(latest_checkpoint.get("inactiveShards")) == 2
    assert latest_checkpoint.get("rootHash") is not None
    assert latest_checkpoint.get("signedTreeHead") is not None
    assert latest_checkpoint.get("treeID") is not None
    assert latest_checkpoint.get("treeSize") is not None
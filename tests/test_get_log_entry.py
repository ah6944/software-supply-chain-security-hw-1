from rekor_verification.main import get_log_entry
from jsonschema import validate

log_entry_schema = {
    "type": "object",
    "properties": {
        "body": {"type": "string"},
        "integratedTime": {"type": "integer"},
        "logID": {"type": "string"},
        "logIndex": {"type": "integer"},
        "verification": {
            "type": "object",
            "properties": {
                "inclusionProof": {
                    "type": "object",
                    "properties": {
                        "checkpoint": {"type": "string"},
                        "hashes": {
                            "type": "array",
                            "items": {
                                "type": "string"
                            }
                        },
                        "logIndex": {"type": "integer"},
                        "rootHash": {"type": "string"},
                        "treeSize": {"type": "integer"}
                    },
                    "required": ["checkpoint", "hashes", "logIndex", "rootHash", "treeSize"]
                },
                "signedEntryTimestamp": {"type": "string"}
            },
            "required": ["inclusionProof", "signedEntryTimestamp"]
        }
    },
    "required": ["body", "integratedTime", "logID", "logIndex", "verification"]
}

def test_get_log_entry():
    log_index = "512770004"
    log_entry = get_log_entry(log_index)

    assert log_entry is not None
    uuid = next(iter(log_entry.keys()))
    content = log_entry.get(uuid)
    assert content is not None
    validate(instance=content, schema=log_entry_schema)
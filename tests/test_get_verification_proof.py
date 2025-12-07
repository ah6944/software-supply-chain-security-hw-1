from rekor_verification.main import get_verification_proof, get_log_entry

def test_get_verification_proof():
    log_index = "512770004"

    log_entry = get_log_entry(log_index)
    assert log_entry is not None
    uuid = next(iter(log_entry.keys()))

    leaf_hash, index, root_hash, tree_size, hashes = get_verification_proof(log_entry, uuid)
    assert leaf_hash is not None
    assert index is not None
    assert root_hash is not None
    assert tree_size is not None
    assert hashes is not None
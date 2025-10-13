import argparse
import requests
import base64
import json
from util import extract_public_key, verify_artifact_signature
from merkle_proof import (
    DefaultHasher,
    verify_consistency,
    verify_inclusion,
    compute_leaf_hash,
)


def get_log_entry(log_index, debug=False):
    params = {"logIndex": log_index}
    url = "https://rekor.sigstore.dev/api/v1/log/entries"
    response = requests.get(url, params=params)
    result = handle_response(response)

    if debug:
        save_json_to_file(json.dumps(result, indent=4), "log_entry.json")

    return result


def get_verification_proof(log_entry, uuid, debug=False):
    leaf_hash = compute_leaf_hash(get_nested_field(log_entry, f"{uuid}.body"))
    inclusionProof = get_nested_field(log_entry, f"{uuid}.verification.inclusionProof")
    index, root_hash, tree_size, hashes = [
        inclusionProof.get(key)
        for key in ("logIndex", "rootHash", "treeSize", "hashes")
    ]

    if debug:
        print(
            f"index: {index}\nroot_hash: {root_hash}\ntree_size: {tree_size}\nhashes: {json.dumps(hashes, indent=4)}"
        )

    return leaf_hash, index, root_hash, tree_size, hashes


def inclusion(log_index, artifact_filepath, debug=False):
    log_entry = get_log_entry(log_index, debug)
    uuid = next(iter(log_entry.keys()))
    body = json.loads(base64_decode(get_nested_field(log_entry, f"{uuid}.body")))
    signature = base64_decode(get_nested_field(body, "spec.signature.content"))
    certificate = base64_decode(
        get_nested_field(body, "spec.signature.publicKey.content")
    )
    public_key = extract_public_key(certificate)

    verify_artifact_signature(signature, public_key, artifact_filepath)

    leaf_hash, index, root_hash, tree_size, hashes = get_verification_proof(
        log_entry, uuid, debug
    )

    verify_inclusion(DefaultHasher, index, tree_size, leaf_hash, hashes, root_hash)
    print("Offline root hash calculation for inclusion verified")


def base64_decode(encoded_str):
    return base64.b64decode(encoded_str)


def handle_response(response):
    if response.status_code == 200:
        return response.json()
    else:
        response.raise_for_status()


def get_nested_field(obj, field_path):
    fields = field_path.split(".")

    for field in fields:
        obj = obj.get(field)

        if obj is None:
            print(f"Field {field} returned None")

    return obj


def save_json_to_file(json, file_name):
    with open(file_name, "w") as file:
        file.write(json)


def get_latest_checkpoint(debug=False):
    url = "https://rekor.sigstore.dev/api/v1/log"
    response = requests.get(url)
    result = handle_response(response)

    if debug:
        save_json_to_file(json.dumps(result, indent=4), "checkpoint.json")

    return result


def consistency(prev_checkpoint, debug=False):
    # verify that prev checkpoint is not empty
    latest_checkpoint = get_latest_checkpoint(debug)
    latest_tree_id = latest_checkpoint.get("treeID")
    prev_tree_id = prev_checkpoint.get("treeID")

    if latest_tree_id != prev_tree_id:
        print(
            "The treeIDs of the latest and previous checkpoints do not match:\n"
            f"\tLatest checkpoint treeId: {latest_tree_id}\n"
            f"\tPrevious checkpoint treeId: {prev_tree_id}"
        )
        return

    latest_root_hash = latest_checkpoint.get("rootHash")
    latest_tree_size = latest_checkpoint.get("treeSize")

    prev_tree_size = prev_checkpoint.get("treeSize")
    prev_root = prev_checkpoint.get("rootHash")

    url = "https://rekor.sigstore.dev/api/v1/log/proof"
    params = {
        "firstSize": prev_tree_size,
        "lastSize": latest_tree_size,
        "treeID": prev_tree_id,
    }
    response = requests.get(url, params=params)
    hashes = handle_response(response).get("hashes")
    verify_consistency(
        DefaultHasher,
        prev_tree_size,
        latest_tree_size,
        hashes,
        prev_root,
        latest_root_hash,
    )
    print("Consistency verification successful")


def main():
    debug = False
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument(
        "-d", "--debug", help="Debug mode", required=False, action="store_true"
    )  # Default false
    parser.add_argument(
        "-c",
        "--checkpoint",
        help="Obtain latest checkpoint\
                        from Rekor Server public instance",
        required=False,
        action="store_true",
    )
    parser.add_argument(
        "--inclusion",
        help="Verify inclusion of an\
                        entry in the Rekor Transparency Log using log index\
                        and artifact filename.\
                        Usage: --inclusion 126574567",
        required=False,
        type=int,
    )
    parser.add_argument(
        "--artifact",
        help="Artifact filepath for verifying\
                        signature",
        required=False,
    )
    parser.add_argument(
        "--consistency",
        help="Verify consistency of a given\
                        checkpoint with the latest checkpoint.",
        action="store_true",
    )
    parser.add_argument(
        "--tree-id", help="Tree ID for consistency proof", required=False
    )
    parser.add_argument(
        "--tree-size", help="Tree size for consistency proof", required=False, type=int
    )
    parser.add_argument(
        "--root-hash", help="Root hash for consistency proof", required=False
    )
    args = parser.parse_args()
    if args.debug:
        debug = True
        print("enabled debug mode")
    if args.checkpoint:
        # get and print latest checkpoint from server
        # if debug is enabled, store it in a file checkpoint.json
        checkpoint = get_latest_checkpoint(debug)
        print(json.dumps(checkpoint, indent=4))
    if args.inclusion:
        inclusion(args.inclusion, args.artifact, debug)
    if args.consistency:
        if not args.tree_id:
            print("please specify tree id for prev checkpoint")
            return
        if not args.tree_size:
            print("please specify tree size for prev checkpoint")
            return
        if not args.root_hash:
            print("please specify root hash for prev checkpoint")
            return

        prev_checkpoint = {}
        prev_checkpoint["treeID"] = args.tree_id
        prev_checkpoint["treeSize"] = args.tree_size
        prev_checkpoint["rootHash"] = args.root_hash

        consistency(prev_checkpoint, debug)


if __name__ == "__main__":
    main()

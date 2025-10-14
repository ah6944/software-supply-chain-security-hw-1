"""
Rekor verification script.

This script has the following features:
    - Fetching the latest log entry from the Rekor transparency logs.
    - Verification of the inclusion of an artifact in the transparency logs.
    - Verification of the consistency between the previous and latest
    checkpoints.
"""
import argparse
import base64
import json
import requests
from util import extract_public_key, verify_artifact_signature
from merkle_proof import (
    DefaultHasher,
    verify_consistency,
    verify_inclusion,
    compute_leaf_hash,
)


def get_log_entry(log_index, debug=False):
    """
    Fetch a log entry from Rekor.

    Args:
        log_index (int): Index of the log entry.
        debug (bool, optional): If True, the log entry will be saved to a file. 
        Defaults to False.

    Returns:
        dict: The log entry data.
    """
    params = {"logIndex": log_index}
    url = "https://rekor.sigstore.dev/api/v1/log/entries"
    response = requests.get(url, params=params, timeout=5)
    result = handle_response(response)

    if debug:
        save_json_to_file(json.dumps(result, indent=4), "log_entry.json")

    return result


def get_verification_proof(log_entry, uuid, debug=False):
    """
    Gets the required data in order to verify the log entry.

    Args:
        log_entry (dict): The log entry from Rekor.
        uuid (str): The unique identifier of the log entry.
        debug (bool, optional): If True, the data for the verification proof 
        will be printed. Defaults to False.

    Returns:
        tuple: A tuple that contains the leaf hash of the log entry, the log 
        index, the root hash of the Merkle tree, the size of the Merkle tree, 
        and the log entry's inclusion proof hashes.
    """
    leaf_hash = compute_leaf_hash(get_nested_field(log_entry, f"{uuid}.body"))
    inclusion_proof = get_nested_field(log_entry, f"{uuid}.verification.inclusionProof")
    index, root_hash, tree_size, hashes = [
        inclusion_proof.get(key)
        for key in ("logIndex", "rootHash", "treeSize", "hashes")
    ]

    if debug:
        print(
            f"index: {index}\n"
            f"root_hash: {root_hash}\n"
            f"tree_size: {tree_size}\n"
            f"hashes: {json.dumps(hashes, indent=4)}"
        )

    return leaf_hash, index, root_hash, tree_size, hashes


def inclusion(log_index, artifact_filepath, debug=False):
    """
    Verify the inclusion of an artifact in the transparency logs.

    Args:
        log_index (int): The index in the transparency log of the entry in
        which to verify its inclusion.
        artifact_filepath (str): The filepath to the artifact.
        debug (bool, optional): If True, saves the log entry to a file. Defaults 
        to False.
    """
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

    params = {
        "hasher": DefaultHasher,
        "index": index,
        "size": tree_size,
        "leaf_hash": leaf_hash,
        "proof": hashes,
        "root": root_hash
    }

    verify_inclusion(params)
    print("Offline root hash calculation for inclusion verified")


def base64_decode(encoded_str):
    """
    Gets the base64 decoded plaintext.

    Args:
        encoded_str (str): The base64 encoded text.

    Returns:
        str: The base64 decoded text.
    """
    return base64.b64decode(encoded_str)


def handle_response(response):
    """
    Handles the API response.

    Args:
        response (dict): The data returned from the API.

    Returns:
        dict: The API response data.
    """
    if response.status_code == 200:
        return response.json()

    response.raise_for_status()
    return None


def get_nested_field(obj, field_path):
    """
    Extract the value of the nested dictionary field.

    Args:
        obj (dict): The dictionary containing the field to extract.
        field_path (str): The period-delimited path to the field to extract.

    Returns:
        Any: The field if it exists, otherwise None.
    """
    fields = field_path.split(".")

    for field in fields:
        obj = obj.get(field)

        if obj is None:
            print(f"Field {field} returned None")

    return obj


def save_json_to_file(json_str, file_name):
    """
    Write a JSON string to a file.

    Args:
        json_str (str): The JSON string to write to file.
        file_name (str): The file name to write the JSON string to.
    """
    with open(file_name, "w", encoding='utf-8') as file:
        file.write(json_str)


def get_latest_checkpoint(debug=False):
    """
    Fetch the latest transparency log checkpoint.

    Args:
        debug (bool, optional): If True, save the latest transparency log
        checkpoint to a file. Defaults to False.

    Returns:
        dict: The latest transparency log checkpoint.
    """
    url = "https://rekor.sigstore.dev/api/v1/log"
    response = requests.get(url, timeout=5)
    result = handle_response(response)

    if debug:
        save_json_to_file(json.dumps(result, indent=4), "checkpoint.json")

    return result


def consistency(prev_checkpoint, debug=False):
    """
    Verify a previous checkpoint is consistent with the latest checkpoint
    in the transparency logs.

    Args:
        prev_checkpoint (dict): A dictionary containing the details of a
        previous checkpoint.
        debug (bool, optional): If True, saves the latest checkpoint to a file. 
        Defaults to False.
    """
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
    response = requests.get(url, params=params, timeout=5)
    hashes = handle_response(response).get("hashes")

    params = {
        "hasher": DefaultHasher,
        "size1": prev_tree_size,
        "size2": latest_tree_size,
        "proof": hashes,
        "root1": prev_root,
        "root2": latest_root_hash
    }

    verify_consistency(params)
    print("Consistency verification successful")


def main():
    """
    The entry point for the Rekor verification script.
    """
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

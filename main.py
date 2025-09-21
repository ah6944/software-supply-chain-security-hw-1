import argparse
import requests
import base64
import json
from util import extract_public_key, verify_artifact_signature
from merkle_proof import DefaultHasher, verify_consistency, verify_inclusion, compute_leaf_hash

def get_log_entry(log_index, debug=False):
    params = {'logIndex': log_index}
    url = "https://rekor.sigstore.dev/api/v1/log/entries"
    response = requests.get(url, params=params)
    return handle_response(response)

def get_verification_proof(log_entry, uuid, debug=False):
    leaf_hash = compute_leaf_hash(log_entry.get(uuid).get('body'))
    inclusionProof = log_entry.get(uuid).get('verification').get('inclusionProof')
    index = inclusionProof.get('logIndex')
    root_hash = inclusionProof.get('rootHash')
    tree_size = inclusionProof.get('treeSize')
    hashes = inclusionProof.get('hashes')
    return leaf_hash, index, root_hash, tree_size, hashes

def inclusion(log_index, artifact_filepath, debug=False):
    log_entry = get_log_entry(log_index)
    uuid = next(iter(log_entry.keys()))
    body = json.loads(base64_decode(log_entry.get(uuid).get('body')))
    signature = base64_decode(body.get('spec').get('signature').get('content'))
    certificate = base64_decode(
        body.get('spec').get('signature').get('publicKey').get('content'))
    public_key = extract_public_key(certificate)
    verify_artifact_signature(signature, public_key, artifact_filepath)

    leaf_hash, index, root_hash, tree_size, hashes = get_verification_proof(
        log_entry, uuid)
    verify_inclusion(DefaultHasher, index, tree_size, leaf_hash, hashes, root_hash)

def base64_decode(encoded_str):
    return base64.b64decode(encoded_str)

def handle_response(response):
    if response.status_code == 200:
        return response.json()
    else:
        response.raise_for_status()

def get_latest_checkpoint(debug=False):
    url = 'https://rekor.sigstore.dev/api/v1/log'
    response = requests.get(url)
    return handle_response(response)

def consistency(prev_checkpoint, debug=False):
    # verify that prev checkpoint is not empty
    latest_checkpoint = get_latest_checkpoint()
    latest_root_hash = latest_checkpoint.get('rootHash')
    latest_tree_id = latest_checkpoint.get('treeID')
    latest_tree_size = latest_checkpoint.get('treeSize')
    prev_tree_size = prev_checkpoint.get('treeSize')
    prev_tree_id = prev_checkpoint.get('treeID')
    prev_root = prev_checkpoint.get('rootHash')

    url = 'https://rekor.sigstore.dev/api/v1/log/proof'
    params = {
        'firstSize': prev_tree_size,
        'lastSize': latest_tree_size,
        'treeID': prev_tree_id
    }
    response = requests.get(url, params=params)
    hashes = handle_response(response).get('hashes')
    verify_consistency(DefaultHasher, prev_tree_size, latest_tree_size,
                       hashes, prev_root, latest_root_hash)
    print('Consistency verification successful')

def main():
    debug = False
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument('-d', '--debug', help='Debug mode',
                        required=False, action='store_true') # Default false
    parser.add_argument('-c', '--checkpoint', help='Obtain latest checkpoint\
                        from Rekor Server public instance',
                        required=False, action='store_true')
    parser.add_argument('--inclusion', help='Verify inclusion of an\
                        entry in the Rekor Transparency Log using log index\
                        and artifact filename.\
                        Usage: --inclusion 126574567',
                        required=False, type=int)
    parser.add_argument('--artifact', help='Artifact filepath for verifying\
                        signature',
                        required=False)
    parser.add_argument('--consistency', help='Verify consistency of a given\
                        checkpoint with the latest checkpoint.',
                        action='store_true')
    parser.add_argument('--tree-id', help='Tree ID for consistency proof',
                        required=False)
    parser.add_argument('--tree-size', help='Tree size for consistency proof',
                        required=False, type=int)
    parser.add_argument('--root-hash', help='Root hash for consistency proof',
                        required=False)
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

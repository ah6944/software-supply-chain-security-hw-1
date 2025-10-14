"""
Utility class with Merkle tree operations.
"""
import hashlib
import binascii
import base64

# domain separation prefixes according to the RFC
RFC6962_LEAF_HASH_PREFIX = 0
RFC6962_NODE_HASH_PREFIX = 1


class Hasher:
    """
    A utility class for performing hash operations.
    """
    def __init__(self, hash_func=hashlib.sha256):
        self.hash_func = hash_func

    def new(self):
        """
        Creates a new Hasher instance.

        Returns:
            hashlib._hashlib.HASH: A new hash object.
        """
        return self.hash_func()

    def empty_root(self):
        """
        Computes the hash of an empty tree.

        Returns:
            bytes: The hash of an empty tree.
        """
        return self.new().digest()

    def hash_leaf(self, leaf):
        """Computes the hash of a leaf.

        Args:
            leaf (bytes): The leaf to hash.

        Returns:
            bytes: The hash of the leaf.
        """
        h = self.new()
        h.update(bytes([RFC6962_LEAF_HASH_PREFIX]))
        h.update(leaf)
        return h.digest()

    def hash_children(self, left_child, right_child):
        """
        Given the hashes of the two child leaves, computes the hash of the
        parent.

        Args:
            left_child (bytes): The hash of the left child.
            right_child (bytes): The hash of the right child.

        Returns:
            bytes: The parent hash.
        """
        h = self.new()
        b = bytes([RFC6962_NODE_HASH_PREFIX]) + left_child + right_child
        h.update(b)
        return h.digest()

    def size(self):
        """Gets the size of the hash.

        Returns:
            int: The size of the hash.
        """
        return self.new().digest_size


# DefaultHasher is a SHA256 based LogHasher
DefaultHasher = Hasher(hashlib.sha256)


def verify_consistency(params):
    """
    Verifies the consistency of two roots in the Merkle tree.

    Args:
        params (dict): A dictionary with the following keys:
            - hasher (Hasher): The hasher used for hashing.
            - size1 (int): The size of the previous tree.
            - size2 (int): The size of the latest tree.
            - proof (list): The list of hashes used for verifying consistency.
            - root1 (str): The hex-encoded root hash of the previous tree.
            - root2 (str): The hex-encoded root hash of the latest tree.

    Raises:
        ValueError: If the proof is invalid or the tree sizes are not consistent.
        RootMismatchError: If the calculated and expected roots do not match.
    """
    hasher, size1, size2, proof, root1, root2 = [
        params.get(key)
        for key in ("hasher", "size1", "size2", "proof", "root1", "root2")
    ]

    # change format of args to be bytearray instead of hex strings
    root1 = bytes.fromhex(root1)
    root2 = bytes.fromhex(root2)
    bytearray_proof = []
    for elem in proof:
        bytearray_proof.append(bytes.fromhex(elem))

    if size2 < size1:
        raise ValueError(f"size2 ({size2}) < size1 ({size1})")
    if size1 == size2:
        if bytearray_proof:
            raise ValueError("size1=size2, but bytearray_proof is not empty")
        verify_match(root1, root2)
        return
    if size1 == 0:
        if bytearray_proof:
            raise ValueError(
                f"""
                             expected empty bytearray_proof, but got
                             {len(bytearray_proof)} components"""
            )
        return
    if not bytearray_proof:
        raise ValueError("empty bytearray_proof")

    inner, border = decomp_incl_proof(size1 - 1, size2)
    shift = (size1 & -size1).bit_length() - 1
    inner -= shift

    if size1 == 1 << shift:
        seed, start = root1, 0
    else:
        seed, start = bytearray_proof[0], 1

    if len(bytearray_proof) != start + inner + border:
        raise ValueError(
            f"""
                         wrong bytearray_proof size {len(bytearray_proof)},
                         want {start + inner + border}"""
        )

    bytearray_proof = bytearray_proof[start:]

    mask = (size1 - 1) >> shift
    hash1 = chain_inner_right(hasher, seed, bytearray_proof[:inner], mask)
    hash1 = chain_border_right(hasher, hash1, bytearray_proof[inner:])
    verify_match(hash1, root1)

    hash2 = chain_inner(hasher, seed, bytearray_proof[:inner], mask)
    hash2 = chain_border_right(hasher, hash2, bytearray_proof[inner:])
    verify_match(hash2, root2)


def verify_match(calculated, expected):
    """
    Verifies that the calculated and expected roots are equal.

    Args:
        calculated (bytes): The calculated root hash.
        expected (bytes): The expected root hash.

    Raises:
        RootMismatchError: If there is a mismatch between the calculated and
        expected roots.
    """
    if calculated != expected:
        raise RootMismatchError(expected, calculated)


def decomp_incl_proof(index, size):
    """
    Breaks down the inclusion proof into smaller components.

    Args:
        index (int): The tree leaf index.
        size (int): The size of the tree.

    Returns:
        tuple: A tuple consisting of:
            - inner (int): The size of the inner proof.
            - border (int): The size of the border proof.
    """
    inner = inner_proof_size(index, size)
    border = bin(index >> inner).count("1")
    return inner, border


def inner_proof_size(index, size):
    """
    Gets the size of the inner proof.

    Args:
        index (int): The tree leaf index.
        size (int): The tree size.

    Returns:
        int: The size of the inner proof.
    """
    return (index ^ (size - 1)).bit_length()


def chain_inner(hasher, seed, proof, index):
    """
    Using the proof, computes the hash of the inner chain.

    Args:
        hasher (Hasher): The hasher used for hashing.
        seed (bytes): The initial hash.
        proof (int): The proof hashes.
        index (int): The tree leaf index.

    Returns:
        bytes: The hash of the inner chain.
    """
    for i, h in enumerate(proof):
        if (index >> i) & 1 == 0:
            seed = hasher.hash_children(seed, h)
        else:
            seed = hasher.hash_children(h, seed)
    return seed


def chain_inner_right(hasher, seed, proof, index):
    """
    Computes the hash of the inner right chain.

    Args:
        hasher (Hasher): The hasher used for hashing.
        seed (bytes): The initial hash.
        proof (list): The proof hashes.
        index (int): The tree leaf index.

    Returns:
        bytes: The hash of the inner right chain.
    """
    for i, h in enumerate(proof):
        if (index >> i) & 1 == 1:
            seed = hasher.hash_children(h, seed)
    return seed


def chain_border_right(hasher, seed, proof):
    """
    Computes the hash of the right border chain.

    Args:
        hasher (Hasher): The hasher used for hashing.
        seed (bytes): The initial hash.
        proof (list): The proof hashes.

    Returns:
        bytes: The hash of the right border chain.
    """
    for h in proof:
        seed = hasher.hash_children(h, seed)
    return seed


class RootMismatchError(Exception):
    """
    Exception raised when there is a mismatch between the calculated
    and expected roots.
    """
    def __init__(self, expected_root, calculated_root):
        self.expected_root = binascii.hexlify(bytearray(expected_root))
        self.calculated_root = binascii.hexlify(bytearray(calculated_root))

    def __str__(self):
        return f"""
        calculated root:\n{self.calculated_root}\n does not match expected
        root:\n{self.expected_root}"""


def root_from_inclusion_proof(hasher, index, size, leaf_hash, proof):
    """
    Computes the root hash given the inclusion proof hashes.

    Args:
        hasher (Hasher): The hasher used for hashing.
        index (int): The tree leaf index.
        size (int): The size of the tree.
        leaf_hash (bytes): The leaf hash.
        proof (list): The inclusion proof hashes.

    Raises:
        ValueError: If the size of the leaf hash or proof is invalid.

    Returns:
        bytes: The root hash.
    """
    if index >= size:
        raise ValueError(f"index is beyond size: {index} >= {size}")

    if len(leaf_hash) != hasher.size():
        raise ValueError(
            f"leaf_hash has unexpected size {len(leaf_hash)}, want {hasher.size()}"
        )

    inner, border = decomp_incl_proof(index, size)
    if len(proof) != inner + border:
        raise ValueError(f"wrong proof size {len(proof)}, want {inner + border}")

    res = chain_inner(hasher, leaf_hash, proof[:inner], index)
    res = chain_border_right(hasher, res, proof[inner:])
    return res


def verify_inclusion(params, debug=False):
    """
    Verifies that a leaf is in the tree.

    Args:
        params (dict): A dictionary consisting of the following:
            - hasher (Hasher): The hasher used for hashing.
            - index (int): The tree leaf index.
            - size (int): The tree size.
            - leaf_hash (str): The leaf hash.
            - proof (list): The list of inclusion proof hashes.
            - root (str): The root hash of the tree.
        debug (bool, optional): If True, prints debug information. Defaults to False.
    """
    hasher, index, size, leaf_hash, proof, root = [
        params.get(key)
        for key in ("hasher", "index", "size", "leaf_hash", "proof", "root")
    ]
    bytearray_proof = []
    for elem in proof:
        bytearray_proof.append(bytes.fromhex(elem))

    bytearray_root = bytes.fromhex(root)
    bytearray_leaf = bytes.fromhex(leaf_hash)
    calc_root = root_from_inclusion_proof(
        hasher, index, size, bytearray_leaf, bytearray_proof
    )
    verify_match(calc_root, bytearray_root)
    if debug:
        print("Calculated root hash", calc_root.hex())
        print("Given root hash", bytearray_root.hex())


# requires entry["body"] output for a log entry
# returns the leaf hash according to the rfc 6962 spec
def compute_leaf_hash(body):
    """
    Computes the hash of the leaf.

    Args:
        body (str): The base64-encoded log entry body.

    Returns:
        str: The leaf hash.
    """
    entry_bytes = base64.b64decode(body)

    # create a new sha256 hash object
    h = hashlib.sha256()
    # write the leaf hash prefix
    h.update(bytes([RFC6962_LEAF_HASH_PREFIX]))

    # write the actual leaf data
    h.update(entry_bytes)

    # return the computed hash
    return h.hexdigest()

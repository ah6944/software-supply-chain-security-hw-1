# Python Rekor Signed Artifact Verification Script

## Overview
In software development, artifact signing is a method to help increase the
security of the software by associating an artifact with the person who
uploaded it.

Sigstore is a tool that simplifies the signing of artifacts by signing it and
uploading the signature details to Rekor, an append-only log, so that other
users are able to verify the integrity of the artifact.

This script contains functions for interacting with the Rekor logs, such as
verifying the inclusion of an artifact in the logs.

## Usage
Prior to using this script, an artifact is signed using a tool like cosign. For
example:

```bash
cosign sign-blob <artifact> --bundle artifact.bundle
```

The generated `.bundle` file will contain details about the signing, such as
the log entry that was appended to Rekor as well as the log ID.

Once you have an artifact that has been signed, you can use this script to do
the following:

### Verify the inclusion of the artifact in Rekor
```bash
python main.py --inclusion <logIndex> --artifact <artifact>
```

### Fetch the latest log entry in Rekor
```bash
python main.py -c
```

### Verify the consistency of a log entry with the latest Rekor log entry
In order to perform consistency verification, you'll need the following details
of the log entry that you want to verify its consistency: `treeId`, `treeSize`,
and `rootHash`. You can query the Rekor API for your log entry to obtain these
details. Once obtained, the following command will perform the consistency
verification:

```bash
python main.py --consistency --tree-id <treeId> --treeSize <treeSize> --rootHash <rootHash>
```

## Installation
This script contains a few dependencies that are required to be installed prior
to usage. They can be installed by running:

```bash
pip install -r requirements.txt
```
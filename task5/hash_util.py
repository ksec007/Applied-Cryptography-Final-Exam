import hashlib
import json
import sys
import os

# Compute hashes for given file
def compute_hashes(file_path):
    hashes = {}
    with open(file_path, 'rb') as f:
        file_data = f.read()
        hashes['SHA-256'] = hashlib.sha256(file_data).hexdigest()
        hashes['SHA-1'] = hashlib.sha1(file_data).hexdigest()
        hashes['MD5'] = hashlib.md5(file_data).hexdigest()
    return hashes

# Store hashes in JSON file
def store_hashes(hashes, json_path):
    with open(json_path, 'w') as f:
        json.dump(hashes, f, indent=4)

# Verify integrity by comparing hashes
def verify_hashes(file_path, json_path):
    if not os.path.exists(json_path):
        print(f"Hash file {json_path} does not exist.")
        return

    current_hashes = compute_hashes(file_path)
    with open(json_path, 'r') as f:
        stored_hashes = json.load(f)

    integrity_passed = True
    for algo in current_hashes:
        if current_hashes[algo] != stored_hashes.get(algo):
            print(f"[FAIL] {algo} hash mismatch detected!")
            integrity_passed = False
        else:
            print(f"[PASS] {algo} hash matches.")

    if integrity_passed:
        print("\nIntegrity Check: PASS")
    else:
        print("\nIntegrity Check: FAIL")

# Main execution
if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python hash_util.py <filename> <store|verify>")
        sys.exit(1)

    filename = sys.argv[1]
    mode = sys.argv[2]
    json_file = 'hashes.json'

    if mode == 'store':
        hashes = compute_hashes(filename)
        store_hashes(hashes, json_file)
        print(f"Hashes stored in {json_file}")
    elif mode == 'verify':
        verify_hashes(filename, json_file)
    else:
        print("Invalid mode! Use 'store' or 'verify'.")

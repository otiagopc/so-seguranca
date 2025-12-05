import time
import json
from Crypto.Cipher import AES, PKCS1_OAEP, ChaCha20
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# ============================================================
# SUPORTE
# ============================================================

def load_file(path):
    with open(path, "rb") as f:
        return f.read()

def save_file(path, data):
    with open(path, "wb") as f:
        f.write(data)


# ============================================================
# AES CBC
# ============================================================

def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv

    padding = 16 - len(data) % 16
    padded = data + bytes([padding]) * padding

    encrypted = cipher.encrypt(padded)
    return iv + encrypted


def aes_decrypt(enc_data, key):
    iv = enc_data[:16]
    ciphertext = enc_data[16:]

    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted = cipher.decrypt(ciphertext)

    padding = decrypted[-1]
    return decrypted[:-padding]


# ============================================================
# CHACHA20
# ============================================================

def chacha20_encrypt(data, key):
    cipher = ChaCha20.new(key=key)
    nonce = cipher.nonce
    ciphertext = cipher.encrypt(data)
    return nonce + ciphertext


def chacha20_decrypt(enc_data, key):
    nonce = enc_data[:8]
    ciphertext = enc_data[8:]
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return cipher.decrypt(ciphertext)


# ============================================================
# RSA OAEP
# ============================================================

def rsa_encrypt(data, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    block_size = public_key.size_in_bytes() - 42
    encrypted_blocks = []

    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        encrypted_blocks.append(cipher.encrypt(block))

    return b"".join(encrypted_blocks)


def rsa_decrypt(enc_data, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    block_size = private_key.size_in_bytes()
    decrypted_blocks = []

    for i in range(0, len(enc_data), block_size):
        block = enc_data[i:i + block_size]
        decrypted_blocks.append(cipher.decrypt(block))

    return b"".join(decrypted_blocks)


# ============================================================
# RUN TEST
# ============================================================

def run_test(input_file, rsa_public_path, rsa_private_path):
    original_data = load_file(input_file)
    file_size = len(original_data)

    rsa_pub = RSA.import_key(load_file(rsa_public_path))
    rsa_pri = RSA.import_key(load_file(rsa_private_path))

    results = {}

    # ------------------ AES -------------------
    aes_key = get_random_bytes(16)
    start = time.time()
    aes_output = aes_encrypt(original_data, aes_key)
    results["t_aes"] = time.time() - start
    save_file("output_aes.bin", aes_output)
    assert aes_decrypt(aes_output, aes_key) == original_data

    # ------------------ ChaCha20 -------------------
    chacha_key = get_random_bytes(32)
    start = time.time()
    chacha_output = chacha20_encrypt(original_data, chacha_key)
    results["t_chacha20"] = time.time() - start
    save_file("output_chacha20.bin", chacha_output)
    assert chacha20_decrypt(chacha_output, chacha_key) == original_data

    # ------------------ RSA -------------------
    start = time.time()
    rsa_output = rsa_encrypt(original_data, rsa_pub)
    results["t_rsa"] = time.time() - start
    save_file("output_rsa.bin", rsa_output)
    assert rsa_decrypt(rsa_output, rsa_pri) == original_data

    # ------------------ Final -------------------
    results["file_size"] = file_size
    return results


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()

    parser.add_argument("--file", required=True)
    parser.add_argument("--rsa_pub", required=True)
    parser.add_argument("--rsa_pri", required=True)

    args = parser.parse_args()

    results = run_test(
        args.file,
        args.rsa_pub,
        args.rsa_pri
    )

    print(json.dumps(results, indent=4))

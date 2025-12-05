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

def aes_encrypt(data, key, key_size):
    """Encrypt with AES-CBC using key of specified size"""
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

def run_test(input_file, rsa_public_path, rsa_private_path, aes_key_size=128, chacha_key_size=256):
    """
    Run encryption test with specified key sizes
    aes_key_size: 128 or 256 bits
    chacha_key_size: 256 bits only (fixed for ChaCha20)
    """
    original_data = load_file(input_file)
    file_size = len(original_data)

    rsa_pub = RSA.import_key(load_file(rsa_public_path))
    rsa_pri = RSA.import_key(load_file(rsa_private_path))
    
    # Determine RSA key size from the key itself
    rsa_key_size = rsa_pub.size_in_bits()

    results = {}

    # ------------------ AES -------------------
    aes_key_bytes = aes_key_size // 8
    aes_key = get_random_bytes(aes_key_bytes)
    
    start = time.perf_counter()
    aes_output = aes_encrypt(original_data, aes_key, aes_key_size)
    t_aes = time.perf_counter() - start
    results["t_aes"] = t_aes
    results["aes_key_size"] = aes_key_size
    results["aes_throughput_mbs"] = (file_size / t_aes) / 1_000_000 if t_aes > 0 else 0
    
    save_file("output_aes.bin", aes_output)
    assert aes_decrypt(aes_output, aes_key) == original_data

    # ------------------ ChaCha20 -------------------
    chacha_key_bytes = chacha_key_size // 8
    chacha_key = get_random_bytes(chacha_key_bytes)
    
    start = time.perf_counter()
    chacha_output = chacha20_encrypt(original_data, chacha_key)
    t_chacha = time.perf_counter() - start
    results["t_chacha20"] = t_chacha
    results["chacha_key_size"] = chacha_key_size
    results["chacha_throughput_mbs"] = (file_size / t_chacha) / 1_000_000 if t_chacha > 0 else 0
    
    save_file("output_chacha20.bin", chacha_output)
    assert chacha20_decrypt(chacha_output, chacha_key) == original_data

    # ------------------ RSA -------------------
    start = time.perf_counter()
    rsa_output = rsa_encrypt(original_data, rsa_pub)
    t_rsa = time.perf_counter() - start
    results["t_rsa"] = t_rsa
    results["rsa_key_size"] = rsa_key_size
    results["rsa_throughput_mbs"] = (file_size / t_rsa) / 1_000_000 if t_rsa > 0 else 0
    
    save_file("output_rsa.bin", rsa_output)
    assert rsa_decrypt(rsa_output, rsa_pri) == original_data

    # ------------------ Calcula razões -------------------
    results["ratio_rsa_aes"] = t_rsa / t_aes if t_aes > 0 else float('inf')
    results["ratio_rsa_chacha"] = t_rsa / t_chacha if t_chacha > 0 else float('inf')
    
    # ------------------ Final -------------------
    results["file_size"] = file_size
    results["file_size_mb"] = file_size / (1024 * 1024)
    
    return results

# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Compare encryption algorithms with different key sizes")
    
    parser.add_argument("--file", required=True, help="Input file to encrypt")
    parser.add_argument("--rsa_pub", required=True, help="RSA public key file")
    parser.add_argument("--rsa_pri", required=True, help="RSA private key file")
    parser.add_argument("--aes_bits", type=int, default=128, choices=[128, 256], 
                       help="AES key size in bits (128 or 256)")
    parser.add_argument("--chacha_bits", type=int, default=256, choices=[256], 
                       help="ChaCha20 key size in bits (256 only)")

    args = parser.parse_args()

    results = run_test(
        args.file,
        args.rsa_pub,
        args.rsa_pri,
        aes_key_size=args.aes_bits,
        chacha_key_size=args.chacha_bits
    )

    print(json.dumps(results, indent=4))
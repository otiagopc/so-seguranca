import time
import os
import json
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


# ============================================================
# FUNÇÕES DE SUPORTE
# ============================================================

def load_file(path):
    with open(path, "rb") as f:
        return f.read()


def save_file(path, data):
    with open(path, "wb") as f:
        f.write(data)


# ============================================================
# 1) CRIPTOGRAFIA SIMÉTRICA (AES)
# ============================================================

def aes_encrypt(data, key):
    """
    AES modo CBC.
    O IV deve ser salvo para permitir a descriptografia.
    """
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv

    # PKCS7 Padding
    padding = 16 - len(data) % 16
    padded_data = data + bytes([padding]) * padding

    encrypted = cipher.encrypt(padded_data)
    return iv + encrypted   # concatena IV + ciphertext


def aes_decrypt(enc_data, key):
    iv = enc_data[:16]
    ciphertext = enc_data[16:]

    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted = cipher.decrypt(ciphertext)

    padding = decrypted[-1]
    return decrypted[:-padding]


# ============================================================
# 2) CRIPTOGRAFIA ASSIMÉTRICA (RSA)
# ============================================================

def rsa_encrypt(data, public_key):
    """
    RSA pode apenas cifrar blocos pequenos.  
    Então precisamos quebrar o arquivo em blocos menores.
    """

    cipher = PKCS1_OAEP.new(public_key)

    block_size = public_key.size_in_bytes() - 42  # limite do OAEP

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
# ROTINA PRINCIPAL DO TRABALHO
# ============================================================

def run_test(input_file, aes_key, rsa_public_path, rsa_private_path):
    original_data = load_file(input_file)

    rsa_pub = RSA.import_key(load_file(rsa_public_path))
    rsa_pri = RSA.import_key(load_file(rsa_private_path))

    file_size = len(original_data)

    # --------------------------------------------------------
    # AES
    # --------------------------------------------------------
    start = time.time()
    aes_output = aes_encrypt(original_data, aes_key)
    t_aes = time.time() - start

    save_file("output_aes.bin", aes_output)

    # --------------------------------------------------------
    # RSA
    # --------------------------------------------------------
    start = time.time()
    rsa_output = rsa_encrypt(original_data, rsa_pub)
    t_rsa = time.time() - start

    save_file("output_rsa.bin", rsa_output)

    # --------------------------------------------------------
    # DESCRIPTOGRAFIA (para validar)
    # --------------------------------------------------------
    dec_aes = aes_decrypt(aes_output, aes_key)
    dec_rsa = rsa_decrypt(rsa_output, rsa_pri)

    assert dec_aes == original_data, "ERRO: AES não voltou ao original!"
    assert dec_rsa == original_data, "ERRO: RSA não voltou ao original!"

    # --------------------------------------------------------
    # Retorno com métricas
    # --------------------------------------------------------
    return {
        "file_size": file_size,
        "t_aes": t_aes,
        "t_rsa": t_rsa,
        "ratio": t_rsa / t_aes if t_aes > 0 else None
    }


# ============================================================
# EXECUÇÃO DIRETA
# ============================================================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()

    parser.add_argument("--file", required=True, help="Arquivo a ser cifrado")
    parser.add_argument("--rsa_pub", required=True, help="Chave pública RSA")
    parser.add_argument("--rsa_pri", required=True, help="Chave privada RSA")

    args = parser.parse_args()

    aes_key = get_random_bytes(16)  # AES-128

    results = run_test(
        args.file,
        aes_key,
        args.rsa_pub,
        args.rsa_pri
    )

    print(json.dumps(results, indent=4))

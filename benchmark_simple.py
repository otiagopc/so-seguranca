import sys
import subprocess
import json
import csv
import os
import argparse
import time
from Crypto.PublicKey import RSA

CRYPTO_SCRIPT = "crypto_compare.py"


def ensure_rsa_keypair(bits=2048):
    pub = f"rsa_{bits}_public.pem"
    pri = f"rsa_{bits}_private.pem"

    if os.path.exists(pub) and os.path.exists(pri):
        return pub, pri

    print(f"[+] Gerando chave RSA {bits} bits...")
    key = RSA.generate(bits)

    with open(pri, "wb") as f:
        f.write(key.export_key())

    with open(pub, "wb") as f:
        f.write(key.publickey().export_key())

    return pub, pri


def run_once(input_file, rsa_pub, rsa_pri):
    cmd = [
        sys.executable,
        CRYPTO_SCRIPT,
        "--file", input_file,
        "--rsa_pub", rsa_pub,
        "--rsa_pri", rsa_pri
    ]

    raw = subprocess.check_output(cmd)
    raw_text = raw.decode()
    data = json.loads(raw_text)
    return raw_text, data


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("--file", required=True)
    parser.add_argument("--reps", type=int, default=5)
    parser.add_argument("--rsa_bits", type=int, default=2048)
    parser.add_argument("--outdir", default="results_table")
    args = parser.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    file_size = os.path.getsize(args.file)
    size_label = f"{round(file_size / (1024*1024))} MB"

    rsa_pub, rsa_pri = ensure_rsa_keypair(args.rsa_bits)

    table_rows = []

    for i in range(1, args.reps + 1):
        print(f"[+] Execução {i}/{args.reps}...")

        raw_text, data = run_once(args.file, rsa_pub, rsa_pri)

        # gerar arquivo bruto
        with open(os.path.join(args.outdir, f"exec_{i}.txt"), "w") as f:
            f.write(raw_text)

        t_aes = data["t_aes"]
        t_ch = data["t_chacha20"]
        t_rsa = data["t_rsa"]

        ratio = t_rsa / t_aes

        table_rows.append({
            "Repeticao": i,
            "Tam. Arquivo": size_label,
            "Tempo AES (s)": f"{t_aes:.6f}",
            "Tempo ChaCha20 (s)": f"{t_ch:.6f}",
            "Tempo RSA (s)": f"{t_rsa:.6f}",
            "TempoRSA/TempoAES": f"{ratio:.6f}"
        })

    # salvar CSV
    csv_path = os.path.join(args.outdir, "tabela.csv")

    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(table_rows[0].keys()))
        writer.writeheader()
        for row in table_rows:
            writer.writerow(row)

    print("\n[✓] Tabela gerada:", csv_path)
    print("[✓] Arquivos brutos gerados em:", args.outdir)

    print("\n=== TABELA FINAL ===")
    for row in table_rows:
        print(row)


if __name__ == "__main__":
    main()

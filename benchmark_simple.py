import sys
import subprocess
import json
import csv
import os
import argparse
import time
import statistics
import math
from Crypto.PublicKey import RSA

CRYPTO_SCRIPT = "crypto_compare.py"

def ensure_rsa_keypair(bits=2048):
    """Generate RSA keypair if not exists"""
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

def run_once(input_file, rsa_pub, rsa_pri, aes_bits=128, chacha_bits=256):
    """Run a single encryption test"""
    cmd = [
        sys.executable,
        CRYPTO_SCRIPT,
        "--file", input_file,
        "--rsa_pub", rsa_pub,
        "--rsa_pri", rsa_pri,
        "--aes_bits", str(aes_bits),
        "--chacha_bits", str(chacha_bits)
    ]

    raw = subprocess.check_output(cmd)
    raw_text = raw.decode()
    data = json.loads(raw_text)
    return raw_text, data

def calculate_statistics(data_list, key):
    """Calculate mean, std dev, and confidence interval (95%)"""
    values = [d[key] for d in data_list if key in d]
    if not values:
        return 0, 0, (0, 0)
    
    mean = statistics.mean(values)
    
    # Calcular desvio padrão apenas se tiver 2+ valores
    if len(values) > 1:
        stdev = statistics.stdev(values)
        # 95% confidence interval
        conf = 1.96 * stdev / math.sqrt(len(values))
    else:
        stdev = 0
        conf = 0
    
    return mean, stdev, (mean - conf, mean + conf)

def main():
    parser = argparse.ArgumentParser(description="Benchmark encryption algorithms with statistical analysis")
    
    parser.add_argument("--file", required=True, help="Input file to encrypt")
    parser.add_argument("--reps", type=int, default=5, help="Number of repetitions for statistical significance")
    parser.add_argument("--rsa_bits", type=int, default=2048, choices=[2048, 4096], 
                       help="RSA key size in bits (2048 or 4096)")
    parser.add_argument("--aes_bits", type=int, nargs='+', default=[128, 256], 
                       help="AES key sizes to test (e.g., 128 256)")
    parser.add_argument("--outdir", default="results_table", help="Output directory")
    
    args = parser.parse_args()

    # Verificar número mínimo de repetições
    if args.reps < 2:
        print(f"[!] AVISO: Para análise estatística, recomenda-se pelo menos 2 repetições")
        print(f"[!] Continuando com {args.reps} repetição(ões)...")

    os.makedirs(args.outdir, exist_ok=True)

    file_size = os.path.getsize(args.file)
    size_mb = file_size / (1024 * 1024)
    size_label = f"{size_mb:.1f} MB"

    print(f"[+] Arquivo: {args.file} ({size_label})")
    print(f"[+] Repetições: {args.reps}")
    print(f"[+] Tamanhos de chave RSA: {args.rsa_bits} bits")
    print(f"[+] Tamanhos de chave AES: {args.aes_bits} bits")
    print("=" * 60)

    # Generate RSA keys for each size
    rsa_pub, rsa_pri = ensure_rsa_keypair(args.rsa_bits)
    
    # Dictionary to store all results by AES key size
    all_results = {aes_size: [] for aes_size in args.aes_bits}
    
    for aes_size in args.aes_bits:
        print(f"\n[+] Testando AES-{aes_size}...")
        
        table_rows = []
        
        for i in range(1, args.reps + 1):
            print(f"  Execução {i}/{args.reps}...", end="\r")
            
            raw_text, data = run_once(args.file, rsa_pub, rsa_pri, 
                                      aes_bits=aes_size, chacha_bits=256)
            
            # Save raw output
            raw_filename = f"exec_aes{aes_size}_rsa{args.rsa_bits}_{i}.txt"
            with open(os.path.join(args.outdir, raw_filename), "w") as f:
                f.write(raw_text)
            
            # Calculate throughput
            throughput_aes = (file_size / data["t_aes"]) / 1_000_000 if data["t_aes"] > 0 else 0
            throughput_chacha = (file_size / data["t_chacha20"]) / 1_000_000 if data["t_chacha20"] > 0 else 0
            throughput_rsa = (file_size / data["t_rsa"]) / 1_000_000 if data["t_rsa"] > 0 else 0
            
            ratio_rsa_aes = data["t_rsa"] / data["t_aes"] if data["t_aes"] > 0 else float('inf')
            
            table_rows.append({
                "Repeticao": i,
                "Tam. Arquivo": size_label,
                "AES Key Size": f"{aes_size} bits",
                "RSA Key Size": f"{args.rsa_bits} bits",
                "Tempo AES (s)": f"{data['t_aes']:.6f}",
                "Tempo ChaCha20 (s)": f"{data['t_chacha20']:.6f}",
                "Tempo RSA (s)": f"{data['t_rsa']:.6f}",
                "Throughput AES (MB/s)": f"{throughput_aes:.2f}",
                "Throughput ChaCha20 (MB/s)": f"{throughput_chacha:.2f}",
                "Throughput RSA (MB/s)": f"{throughput_rsa:.4f}",
                "TempoRSA/TempoAES": f"{ratio_rsa_aes:.2f}"
            })
            
            all_results[aes_size].append(data)
        
        # Save CSV for this AES key size
        csv_filename = f"tabela_aes{aes_size}_rsa{args.rsa_bits}.csv"
        csv_path = os.path.join(args.outdir, csv_filename)
        
        with open(csv_path, "w", newline="", encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=list(table_rows[0].keys()))
            writer.writeheader()
            for row in table_rows:
                writer.writerow(row)
        
        print(f"  [✓] Tabela salva: {csv_filename}")
    
    # ==================== ANÁLISE ESTATÍSTICA ====================
    print(f"\n{'='*60}")
    print("📊 ANÁLISE ESTATÍSTICA COMPLETA")
    print("="*60)
    
    stats_file = os.path.join(args.outdir, "estatisticas_detalhadas.txt")
    with open(stats_file, "w", encoding='utf-8') as f:
        f.write("="*60 + "\n")
        f.write("ANÁLISE ESTATÍSTICA DETALHADA\n")
        f.write("="*60 + "\n\n")
        
        for aes_size in args.aes_bits:
            data_list = all_results[aes_size]
            if not data_list:
                continue
                
            f.write(f"\n{'─'*50}\n")
            f.write(f"CONFIGURAÇÃO: AES-{aes_size}, RSA-{args.rsa_bits}\n")
            f.write(f"{'─'*50}\n")
            
            # Statistics for AES
            aes_times = [d["t_aes"] for d in data_list]
            aes_throughputs = [d["aes_throughput_mbs"] for d in data_list]
            
            f.write(f"\nAES-{aes_size}:\n")
            f.write(f"  Tempo médio: {statistics.mean(aes_times):.6f} s\n")
            if len(aes_times) > 1:
                f.write(f"  Desvio padrão: {statistics.stdev(aes_times):.6f} s\n")
            else:
                f.write(f"  Desvio padrão: N/A (apenas 1 medição)\n")
            f.write(f"  Throughput médio: {statistics.mean(aes_throughputs):.2f} MB/s\n")
            if len(aes_throughputs) > 1:
                f.write(f"  Variação throughput: ±{statistics.stdev(aes_throughputs):.2f} MB/s\n")
            
            # Statistics for ChaCha20
            chacha_times = [d["t_chacha20"] for d in data_list]
            chacha_throughputs = [d["chacha_throughput_mbs"] for d in data_list]
            
            f.write(f"\nChaCha20:\n")
            f.write(f"  Tempo médio: {statistics.mean(chacha_times):.6f} s\n")
            if len(chacha_times) > 1:
                f.write(f"  Desvio padrão: {statistics.stdev(chacha_times):.6f} s\n")
            f.write(f"  Throughput médio: {statistics.mean(chacha_throughputs):.2f} MB/s\n")
            if len(chacha_throughputs) > 1:
                f.write(f"  Variação throughput: ±{statistics.stdev(chacha_throughputs):.2f} MB/s\n")
            
            # Statistics for RSA
            rsa_times = [d["t_rsa"] for d in data_list]
            rsa_throughputs = [d["rsa_throughput_mbs"] for d in data_list]
            ratios = [d["ratio_rsa_aes"] for d in data_list]
            
            f.write(f"\nRSA-{args.rsa_bits}:\n")
            f.write(f"  Tempo médio: {statistics.mean(rsa_times):.6f} s\n")
            if len(rsa_times) > 1:
                f.write(f"  Desvio padrão: {statistics.stdev(rsa_times):.6f} s\n")
            f.write(f"  Throughput médio: {statistics.mean(rsa_throughputs):.4f} MB/s\n")
            if len(rsa_throughputs) > 1:
                f.write(f"  Variação throughput: ±{statistics.stdev(rsa_throughputs):.4f} MB/s\n")
            
            # Ratios
            f.write(f"\nRAZÕES (RSA/AES):\n")
            f.write(f"  Média: {statistics.mean(ratios):.2f}x mais lento\n")
            if len(ratios) > 1:
                f.write(f"  Mínimo: {min(ratios):.2f}x\n")
                f.write(f"  Máximo: {max(ratios):.2f}x\n")
                f.write(f"  Desvio padrão: ±{statistics.stdev(ratios):.2f}x\n")
            else:
                f.write(f"  (Apenas 1 medição)\n")
            
            # Confidence intervals
            if len(aes_times) > 1:
                conf_aes = 1.96 * statistics.stdev(aes_times) / math.sqrt(len(aes_times))
                f.write(f"\nINTERVALO DE CONFIANÇA 95% (AES):\n")
                f.write(f"  {statistics.mean(aes_times)-conf_aes:.6f} ≤ μ ≤ {statistics.mean(aes_times)+conf_aes:.6f} s\n")
    
    # ==================== RESUMO GERAL ====================
    print("\n" + "="*60)
    print("📈 RESUMO GERAL DOS RESULTADOS")
    print("="*60)
    
    summary_file = os.path.join(args.outdir, "resumo_estatistico.csv")
    with open(summary_file, "w", newline="", encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["Algoritmo", "Tamanho Chave", "Tempo Médio (s)", 
                        "Throughput Médio (MB/s)", "Razão RSA/Algoritmo"])
        
        for aes_size in args.aes_bits:
            data_list = all_results[aes_size]
            if not data_list:
                continue
                
            # AES summary
            aes_mean_time = statistics.mean([d["t_aes"] for d in data_list])
            aes_mean_throughput = statistics.mean([d["aes_throughput_mbs"] for d in data_list])
            writer.writerow(["AES", f"{aes_size} bits", f"{aes_mean_time:.6f}", 
                           f"{aes_mean_throughput:.2f}", "1.00"])
            
            # ChaCha20 summary
            chacha_mean_time = statistics.mean([d["t_chacha20"] for d in data_list])
            chacha_mean_throughput = statistics.mean([d["chacha_throughput_mbs"] for d in data_list])
            writer.writerow(["ChaCha20", "256 bits", f"{chacha_mean_time:.6f}", 
                           f"{chacha_mean_throughput:.2f}", "N/A"])
            
            # RSA summary
            rsa_mean_time = statistics.mean([d["t_rsa"] for d in data_list])
            rsa_mean_throughput = statistics.mean([d["rsa_throughput_mbs"] for d in data_list])
            mean_ratio = statistics.mean([d["ratio_rsa_aes"] for d in data_list])
            writer.writerow(["RSA", f"{args.rsa_bits} bits", f"{rsa_mean_time:.6f}", 
                           f"{rsa_mean_throughput:.4f}", f"{mean_ratio:.2f}"])
    
    print(f"\n[✓] Todos os testes concluídos!")
    print(f"[✓] Tabelas CSV salvas em: {args.outdir}/")
    print(f"[✓] Análise estatística detalhada: {args.outdir}/estatisticas_detalhadas.txt")
    print(f"[✓] Resumo estatístico: {args.outdir}/resumo_estatistico.csv")
    
    # Mostrar razão média se tiver dados
    for aes_size in args.aes_bits:
        if aes_size in all_results and all_results[aes_size]:
            ratios = [d["ratio_rsa_aes"] for d in all_results[aes_size]]
            if ratios:
                avg_ratio = statistics.mean(ratios)
                print(f"\n[📊] RSA-{args.rsa_bits} é em média {avg_ratio:.0f}x mais lento que AES-{aes_size}")
    
    if args.rsa_bits == 2048:
        print(f"\n[🔄] Para comparar com RSA 4096 bits, execute:")
        print(f"    python benchmark_simple.py --file {args.file} --rsa_bits 4096 --reps {args.reps}")

if __name__ == "__main__":
    main()
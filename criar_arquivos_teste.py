# criar_arquivos_teste.py
import os

print("📁 Criando arquivos de teste...")

# 1. Arquivo de 1 MB (1.048.576 bytes)
with open("teste_1mb.bin", "wb") as f:
    f.write(b"A" * 1024 * 1024)  # 1 MB
print("✅ teste_1mb.bin criado (1 MB)")

# 2. Arquivo de 5 MB
with open("teste_5mb.bin", "wb") as f:
    f.write(b"B" * 1024 * 1024 * 5)  # 5 MB
print("✅ teste_5mb.bin criado (5 MB)")

# 3. Arquivo de 10 MB
with open("teste_10mb.bin", "wb") as f:
    f.write(b"C" * 1024 * 1024 * 10)  # 10 MB
print("✅ teste_10mb.bin criado (10 MB)")

# 4. Arquivo pequeno (100 KB) para teste rápido
with open("teste_100kb.bin", "wb") as f:
    f.write(b"D" * 1024 * 100)  # 100 KB
print("✅ teste_100kb.bin criado (100 KB)")

print("\n📊 Tamanhos dos arquivos:")
for file in ["teste_1mb.bin", "teste_5mb.bin", "teste_10mb.bin", "teste_100kb.bin"]:
    size = os.path.getsize(file)
    print(f"  {file}: {size:,} bytes ({size/(1024*1024):.2f} MB)")
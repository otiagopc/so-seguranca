# 🔐 TRABALHO IV - SEGURANÇA

## 📋 REQUISITOS IMPLEMENTADOS

### ✅ **Requisitos Mínimos:**
- Programa que criptografa/descriptografa arquivos
- Medição de tempo para AES (simétrica) e RSA (assimétrica)
- 5 medições com cada algoritmo
- Tabela comparativa

### ✅ **Requisitos Recomendados ADICIONAIS:**
- **Múltiplos algoritmos:** AES + ChaCha20 + RSA
- **Múltiplos tamanhos de chave:** AES 128/256 bits, RSA 2048/4096 bits
- **Análise estatística robusta:** Média, desvio padrão, intervalo de confiança
- **Throughput calculado:** Taxa em MB/s para cada algoritmo

## 🚀 COMO EXECUTAR

### 1. **Preparação inicial:**
```bash
# Instalar dependências
pip install -r requirements.txt

# Criar arquivos de teste
python criar_arquivos_teste.py
2. Teste automático (RECOMENDADO):
bash
python teste_automatico.py
3. Testes manuais:
Teste básico (5 repetições):
bash
python benchmark_simple.py --file teste_1mb.bin --reps 5
Teste com múltiplos tamanhos de AES:
bash
python benchmark_simple.py --file teste_1mb.bin --reps 5 --aes_bits 128 256
Teste com RSA 4096 bits:
bash
python benchmark_simple.py --file teste_1mb.bin --reps 3 --rsa_bits 4096
Teste rápido (100 KB):
bash
python benchmark_simple.py --file teste_100kb.bin --reps 3
📊 SAÍDAS GERADAS
O programa gera na pasta RESULTADOS_FINAIS/:

1. Tabelas CSV:
tabela_aes128_rsa2048.csv - Resultados para AES-128

tabela_aes256_rsa2048.csv - Resultados para AES-256

2. Arquivos brutos:
exec_aes128_rsa2048_1.txt até _5.txt - Saídas JSON de cada execução

3. Análise estatística:
estatisticas_detalhadas.txt - Análise completa com médias, desvios, etc.

resumo_estatistico.csv - Resumo em formato de tabela

📈 INTERPRETAÇÃO DOS RESULTADOS
Colunas da tabela:
Tempo AES (s) - Tempo para cifrar com AES

Tempo RSA (s) - Tempo para cifrar com RSA

Throughput AES (MB/s) - Velocidade do AES

Throughput RSA (MB/s) - Velocidade do RSA

TempoRSA/TempoAES - Quantas vezes o RSA é mais lento

Resultados esperados:
AES: 200-500 MB/s

ChaCha20: 250-500 MB/s

RSA: 0.3-0.8 MB/s

Razão RSA/AES: 300-900x mais lento

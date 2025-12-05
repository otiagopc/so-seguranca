🔐 Projeto de Comparação de Algoritmos Criptográficos

Este projeto executa testes de desempenho dos seguintes algoritmos:

AES (modo CBC)

ChaCha20

RSA (OAEP)

Ele mede o tempo gasto por cada algoritmo ao cifrar um mesmo arquivo, repetindo o processo várias vezes para produzir uma tabela estatisticamente representativa.

📁 Estrutura do Projeto
|
|-- crypto_compare.py
|-- benchmark_simple.py
|-- rsa_2048_public.pem   (gerado automaticamente, se não existir)
|-- rsa_2048_private.pem  (gerado automaticamente, se não existir)
|-- teste.bin (arquivo que você fornece)
|-- results_table/
|     |-- exec_1.txt
|     |-- exec_2.txt
|     |-- exec_3.txt
|     |-- tabela.csv
|
|-- README.md

⚙️ Arquivos Principais
📌 crypto_compare.py

Executa a criptografia com AES, ChaCha20 e RSA e retorna um JSON contendo:

{
    "t_aes": 0.0031,
    "t_chacha20": 0.0024,
    "t_rsa": 0.1651,
    "file_size": 1048576
}


⚠️ Não altere o formato da saída, pois benchmark_simple.py depende dele.

📌 benchmark_simple.py

Script responsável por:

✔ Executar o crypto_compare.py várias vezes
✔ Gerar uma tabela em .csv
✔ Criar arquivos .txt com a saída bruta de cada execução
✔ Calcular o ratio RSA/AES

🧪 Como Executar os Testes
1️⃣ Crie um arquivo de entrada para testar

Exemplo de arquivo de 1 MB:

Em Python:
with open("teste.bin","wb") as f:
    f.write(b"A" * 1024 * 1024)

2️⃣ Execute o benchmark
python benchmark_simple.py --file teste.bin --reps 5

Parâmetros:
Parâmetro	Descrição	Padrão
--file	Arquivo a ser criptografado	(obrigatório)
--reps	Número de execuções (linhas da tabela)	5
--rsa_bits	Tamanho da chave RSA	2048
--outdir	Pasta onde salvar resultados	results_table

Exemplo com 10 repetições:

python benchmark_simple.py --file teste.bin --reps 10

📤 Saídas Geradas

Após rodar o script, será criada a pasta:

results_table/


Dentro dela:

📄 tabela.csv

Tabela no formato solicitado:

Repetição,Tam. Arquivo,Tempo AES (s),Tempo ChaCha20 (s),Tempo RSA (s),TempoRSA/TempoAES
1,1 MB,0.003100,0.002400,0.162000,52.258065
2,1 MB,0.003000,0.002300,0.159000,53.000000
...

📝 exec_X.txt

Cada execução tem um arquivo contendo a saída bruta do crypto_compare.py.

Exemplo de conteúdo de exec_1.txt:

{"t_aes": 0.0031, "t_chacha20": 0.0024, "t_rsa": 0.162, "file_size": 1048576}


Esses arquivos devem ser enviados junto com a tabela, conforme requerido.

📊 Como Interpretar a Tabela

Cada linha representa uma repetição completa do processo de criptografia.

Tempo AES (s) → velocidade do AES-CBC

Tempo ChaCha20 (s) → velocidade do ChaCha20

Tempo RSA (s) → tempo para cifrar usando RSA

TempoRSA/TempoAES → se RSA for 100x mais lento que AES, aparece algo como 100.0

Este valor é importante para mostrar o impacto da criptografia assimétrica em comparação com a simétrica.

🔒 Geração de Chaves RSA

Você NÃO precisa gerar manualmente.

Ao rodar o script:

python benchmark_simple.py --file teste.bin


Se as chaves rsa_2048_public.pem e rsa_2048_private.pem não existirem, elas são criadas automaticamente.

🧩 Dependências

Instale o PyCryptodome:

pip install pycryptodome
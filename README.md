# 🗺️ BillsMap - Port Scanner em Python

```text
+=============================================================================+
|                                                                             |
|   ██████╗ ██╗██╗     ██╗     ███████╗███╗   ███╗ █████╗ ██████╗             |
|   ██╔══██╗██║██║     ██║     ██╔════╝████╗ ████║██╔══██╗██╔══██╗            |
|   ██████╔╝██║██║     ██║     ███████╗██╔████╔██║███████║██████╔╝            |
|   ██╔══██╗██║██║     ██║     ╚════██║██║╚██╔╝██║██╔══██║██╔═══╝             |
|   ██████╔╝██║███████╗███████╗███████║██║ ╚═╝ ██║██║  ██║██║                 |
|   ╚═════╝ ╚═╝╚══════╝╚══════╝╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝                 |
|                                                                             |
|   :: Automated Reconnaissance & Port Mapping Toolkit ::                     |
+=============================================================================+
```

![Python Version](https://img.shields.io/badge/Python-3.11%2B-blue?style=for-the-badge&logo=python)
![Asyncio](https://img.shields.io/badge/asyncio-Fast-success?style=for-the-badge)
![Security](https://img.shields.io/badge/Security-Recon-red?style=for-the-badge)

Bem-vindo ao **BillsMap**. Este projeto nasceu de uma **curiosidade para entender como o [Nmap](https://nmap.org/) funciona por baixo dos panos**.
A ideia foi construir um scanner de portas do zero em Python, utilizando concorrência e I/O assíncrono para fins de aprendizado.

O resultado é um script funcional que mapeia portas e exibe os resultados organizados no terminal.

> **Nota de Desenvolvimento:** Este código foi inicialmente desenhado e escrito à mão com o intuito de estudar e aplicar na prática os conceitos de rede. Ao longo do processo de evolução, refatoração e polimento de algumas funcionalidades e padrões do código, o projeto contou com o auxílio de IA.

---

## 🚀 Como o código funciona (Passo a Passo)

Abaixo está o detalhamento técnico do que acontece na execução:

### 1. 🚦 O Motor Assíncrono (`ScannerEngine` e `_check_port`)

O projeto utiliza a biblioteca nativa `asyncio` com **Sockets Não-Bloqueantes** (`asyncio.open_connection`), em vez de threads normais.

- O método `_check_port` tenta abrir uma conexão TCP com o IP e a porta alvo.
- Se a conexão é estabelecida, a porta é classificada como `OPEN`.
- Se o alvo recusa a conexão (`ConnectionRefusedError`), ela é marcada como `CLOSED`.
- Se a conexão dá timeout (`asyncio.TimeoutError`), consideramos `FILTERED` (indica que um firewall possivelmente bloqueou o pacote).
- Existe um limite de tempo (`timeout`) para evitar que o código fique esperando indefinidamente pela resposta.

### 2. 🎛️ Controle de Fluxo: `TokenBucket` e `asyncio.Semaphore`

Para evitar sobrecarga de rede, foram adicionados dois mecanismos:

- **Semaphore (`asyncio.Semaphore`)**: Controla o número máximo de validações de porta ativas simultaneamente (configurável pelo parâmetro `--concurrency`).
- **Token Bucket**: Um limitador de taxa (Rate Limit) que controla a quantidade de requisições por segundo.

### 3. 🛡️ Limites do Sistema Operacional (`check_and_apply_fd_limit`)

No Linux e sistemas baseados em Unix, as conexões de rede ativas ocupam "File Descriptors". O sistema operacional tem um limite global padrão de arquivos/conexões que podem ficar abertos de uma vez (geralmente 1024).
Se o scanner tentar abrir mais conexões que o limite, o programa quebra com um erro de sistema (`Too many open files`).
O script utiliza a biblioteca `resource` do Python para checar o ulimit. Se a flag `--unsafe-adjust-limits` for fornecida, ele tenta elevar dinamicamente esse teto no SO durante o tempo de execução do script.

### 4. 🎨 Console e UI (`RichConsolePresenter`)

A visualização no terminal usa a biblioteca externa `rich`.
Como o teste de portas assíncrono é executado fora de ordem (uma porta alta pode responder antes de uma porta baixa), a impressão de logs diretos iria se sobrescrever na barra de loading. Para resolver isso, foi implementada uma fila (`asyncio.Queue`) e uma corrotina consumidora dedicada (`_consume_results`). O worker de verificação apenas deposita o resultado nessa fila e a task interface atualiza o console ordenadamente.

### 5. 🏗️ Estrutura

- **Dataclasses**: O estado e os relatórios usam objetos `ScanResult`, `ScanReport` e `ScanConfig` para garantir que as informações se mantenham unificadas e explícitas.
- **Protocolos (`Protocol`)**: `ScanPresenter` foi desenhado como interface (duck typing), caso em um outro momento exista a necessidade de tirar a saída do terminal e jogar para outra saída sem quebrar o engine de scan.
- **Exportação (`ReportExporter`)**: Um roteador de formatos simples que permite gravar em disco `TXT`, `JSON` ou `CSV`.

### 6. 🎯 Resolução DNS e CLI

- O endereço alvo é convertido em IP via `asyncio.get_running_loop().getaddrinfo` logo no início, evitando bloqueio do loop e reduzindo a latência nas tarefas individuais.
- Argumentos são roteados pelo `argparse` em linha de comando, interpretando intervalos no formato numeral e gerando as listas corretas no `parse_ports`.

---

## 🛠️ Como Usar

O único pacote externo exigido é o da renderização de console:

```bash
pip install rich
```

### Exemplo Básico

Escanear o top 1000 portas no IP local:

```bash
python billsMap.py -t 127.0.0.1
```

### Exemplo com Argumentos Adicionais

Escanear as 10.000 portas em um alvo, subindo o limite de concorrência e exportando para um relatório:

```bash
python billsMap.py -t scanme.nmap.org --top-10k --concurrency 2000 --unsafe-adjust-limits -o relatorio_{host}.json --format json
```

### Menus de Ajuda

Para ver todas as marcações e controles:

```bash
python billsMap.py --help
```

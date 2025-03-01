# monitor_ddos
playing with XDP and eBPF to mitigate a DDoS attack

Esse script Bash implementa uma abordagem híbrida para detectar um ataque DDoS e opera em conjunto com o [xdp-drop-ddos]()

- Monitorando o número de conexões em /proc/net/nf_conntrack.
- E existindo um pico suspeito, analisa os logs do nftables para identificar IPs com alta frequência.
- Para então atualizar o mapa eBPF (fixado em um caminho configurável) para bloquear os IPs surpeitos.


1. **Interface de Configuração via Linha de Comando:**
    
    - O script utiliza o `getopts` para permitir a configuração de parâmetros essenciais:
        - **-m:** Caminho do mapa eBPF pinado (ex.: `/sys/fs/bpf/blocked_ips`).
        - **-c:** Limite de conexões para acionar a análise (usando `/proc/net/nf_conntrack`).
        - **-l:** Número mínimo de ocorrências de um IP nos logs para considerá-lo suspeito.
        - **-i:** Intervalo de tempo (em segundos) para cada verificação.
        - **-f:** Caminho para o arquivo de log do nftables.
        - **-h:** Exibe a mensagem de ajuda.
    - Essa abordagem torna o script flexível e adaptável a diferentes ambientes.

2. **Pinagem Automática do Mapa:**

- A função `auto_pin_map()` verifica se o arquivo especificado em `MAP_PIN` existe. Se não existir, ela usa o `bpftool map show` para procurar uma linha contendo "blocked_ips" e extrai o ID do mapa.
- Em seguida, utiliza o comando `bpftool map pin id` para fixar o mapa no caminho desejado.
- Essa automação elimina a necessidade de pinagem manual e garante que o script e o programa XDP trabalhem com o mesmo mapa.

1. **Conversão de IP para Hexadecimal:**
    
    - A função `ip_to_hex` divide o endereço IP em seus quatro octetos e formata cada um com dois dígitos em hexadecimal, gerando uma chave compatível com o formato esperado pelo mapa eBPF.

4. **Monitoramento de Conexões:**
    
    - O script lê `/proc/net/nf_conntrack` para determinar o número de conexões ativas.
    - Se o número de conexões ultrapassar o valor definido em `THRESHOLD_CONN`, ele aciona a análise dos logs do nftables.

5. **Análise dos Logs do nftables:**
    
    - Utiliza `tail` com `timeout` para ler uma janela de logs por um período determinado.
    - A filtragem com `grep` e `sed` extrai os IPs a partir de linhas que contêm `SRC=`.
    - O `awk` conta as ocorrências e filtra somente os IPs que ultrapassam o limite definido em `LOG_THRESHOLD`.

6. **Atualização do Mapa eBPF:**
    
    - Para cada IP suspeito identificado, o script utiliza o comando `bpftool` para inserir o IP no mapa eBPF, fazendo com que o programa XDP bloqueie os pacotes oriundos desse IP.

7. **Considerações Gerais:**
    
    - Verifique se os caminhos configurados (para o mapa e o log) estão corretos e se os módulos necessários (como nf_conntrack) estão carregados.
    - Teste a porra toda né! Sou péssimo programador!
    - O script deve ser executado com privilégios para acessar `/proc`, os logs e atualizar o mapa eBPF.


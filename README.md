# monitor-dos
Esse script implementa uma abordagem híbrida para detectar um ataque DDoS e opera em conjunto com o [xdp-block-dos](https://github.com/0xttfx/xdp-block-ddos/)

- Monitorando o número de conexões em /proc/net/nf_conntrack.
- E existindo um pico suspeito, analisa os logs do nftables para identificar IPs com alta frequência.
- Para então atualizar o mapa eBPF (fixado em um caminho configurável) para bloquear os IPs surpeitos.

---

- Go Horse
  - garanta a pemissão de execução
  ```bash
  sudo chmod +x monitor-dos.sh
  ```
  - execute com os valores padrões
  ```bash
  sudo ./monitor-dos.sh
  ```


**Opções ajutáveis:**
    
   - **-m:** Caminho do mapa eBPF pinado
   - **-c:** Limite de conexões para acionar a análise (usando `/proc/net/nf_conntrack`).
   - **-l:** Número mínimo de ocorrências de um IP nos logs para considerá-lo suspeito.
   - **-i:** Intervalo de tempo (em segundos) para cada verificação.
   - **-f:** Caminho para o arquivo de log do nftables.
   - **-h:** Exibe a mensagem de ajuda.


## Detalhes técnicos


### 1. Inicialização de Variáveis e Processamento de Opções

- **Definição de Valores Padrão:**  
  O script já define valores padrões para as variáveis:

  - `MAP_PIN_DEFAULT`           → `/sys/fs/bpf/blocked_ips`
  - `THRESHOLD_CONN_DEFAULT`    → 2000 (número de conexões para acionar a análise)
  - `LOG_THRESHOLD_DEFAULT`     → 5 (ocorrências para considerar um IP suspeito)
  - `INTERVAL_DEFAULT`          → 10 segundos (intervalo de verificação)
  - `LOG_FILE_DEFAULT`          → `/var/log/nftables.log`

- **Processamento com `getopts`:**  
  Utilizando `getopts`, o script permite sobrescrever os valores padrões:

  - `-m` para o caminho do mapa eBPF;
  - `-c` para o limite de conexões;
  - `-l` para o limite de ocorrências de um IP nos logs;
  - `-i` para o intervalo de tempo;
  - `-f` para o caminho do log do nftables;
  - `-h` exibi ajuda e sai ...o/

*Após processar os argumentos, os valores configurados são informados*

---

## 2. Função `auto_pin_map`
  
  Essa função garante que o mapa eBPF esteja “pinado” no caminho especificado.
  
- **Funcionamento:**  
  1. **Verificação da Existência:**  
     - Se o arquivo definido por `MAP_PIN` não existir, o script tenta localizar o mapa “blocked_ips” usando o comando:
       ```bash
       bpftool map show 2>/dev/null | grep -m1 "blocked_ips" | awk '{print $1}' | tr -d ':'
       ```
     - Esse comando busca na saída do `bpftool map show` a linha que contenha “blocked_ips” e extrai o ID do mapa.
  2. **Pinagem do Mapa:**  
     - Se o ID for encontrado, o script utiliza:
       ```bash
       bpftool map pin id "$map_id" "$MAP_PIN"
       ```
       para fixar o mapa no caminho desejado.
  3. **Verificação de Erro:**  
     - Caso a pinagem falhe ou o mapa não seja encontrado, o script exibe uma mensagem de erro e encerra a execução.

---

## 3. Função `ip_to_hex`
 
  Converte o IP no formato decimal (ex.: `192.168.0.1`) para uma representação hexadecimal em big-endian, que é o formato esperado pela chave no mapa eBPF.
  
- **Como Funciona:**  
  - O comando `IFS='.' read -r a b c d <<< "$ip"` divide o IP nos seus quatro octetos.
  - O `printf "0x%02X%02X%02X%02X"` formata cada octeto em dois dígitos hexadecimais e os concatena.

---

## 4. Função `block_ip`

  Inserir no mapa eBPF (pinado em `MAP_PIN`) a chave correspondente a um IP suspeito.

- **Como Funciona:**  
  1. Converte o IP para hexadecimal utilizando `ip_to_hex`.
  2. Exibe uma mensagem indicando que o IP está sendo bloqueado, junto com sua chave hexadecimal.
  3. Utiliza o comando:
     ```bash
     bpftool map update pinned "$MAP_PIN" key "$key_hex" value 0x1 2>/dev/null
     ```
     para atualizar o mapa eBPF, inserindo a chave e definindo o valor (neste caso, `0x1` indica o bloqueio).

---

## 5. Função `get_conn_count`
  
  Conta o número de linhas em `/proc/net/nf_conntrack`, que corresponde ao número de conexões rastreadas pelo sistema.

- **Como Funciona:**  
  - Se o arquivo existe, o comando `wc -l` é utilizado para contar as linhas.
  - Caso o arquivo não exista, a função retorna “0”.

---

## 6.  Função `main`

- **Fluxo do Loop:**
  1. **Leitura do Número de Conexões:**  
     - A função `get_conn_count` é chamada para obter o número atual de conexões.
     - É exibida uma mensagem com o número de conexões.
  
  2. **Verificação de Pico de Conexões:**  
     - Se o número de conexões ultrapassa o limite definido por `THRESHOLD_CONN`, o script:
       - Exibe um alerta indicando que houve um pico.
       - Inicia a análise dos logs do nftables para identificar IPs suspeitos.
  
  3. **Análise dos Logs do nftables:**  
     - Utiliza uma cadeia de comandos para extrair os IPs:
       ```bash
       suspicious_ips=$(timeout "$INTERVAL" tail -n 1000 "$LOG_FILE" 2>/dev/null | \
           grep "SRC=" | sed -n 's/.*SRC=\([0-9.]\+\).*/\1/p' | sort | uniq -c | \
           awk -v thresh="$LOG_THRESHOLD" '$1 >= thresh {print $2}')
       ```
       - **Passo a passo da cadeia:**
         - `tail -n 1000 "$LOG_FILE"`: Obtém as últimas 1000 linhas do log.
         - `timeout "$INTERVAL"`: Garante que a leitura não ultrapasse o intervalo definido.
         - `grep "SRC="`: Filtra as linhas que contêm a string “SRC=”, que indica a presença de um endereço IP de origem.
         - `sed -n 's/.*SRC=\([0-9.]\+\).*/\1/p'`: Extrai o endereço IP dessas linhas.
         - `sort | uniq -c`: Ordena os IPs e conta as ocorrências de cada um.
         - `awk -v thresh="$LOG_THRESHOLD" '$1 >= thresh {print $2}'`: Filtra apenas os IPs cuja contagem seja maior ou igual ao valor definido em `LOG_THRESHOLD`.
  
  4. **Bloqueio dos IPs Suspeitos:**  
     - Para cada IP identificado como suspeito na etapa anterior, a função `block_ip` é chamada para inserir o IP no mapa eBPF.
  
  5. **Intervalo de Espera:**  
     - Ao final de cada iteração, o script aguarda o número de segundos definido por `INTERVAL` antes de iniciar a próxima verificação.

- **Loop Infinito:**  
  O `while true; do ... done` mantém o monitoramento contínuo, permitindo uma resposta dinâmica a picos de tráfego.

---

## 8. Execução Condicional

- **Execução Direta:**  
  O trecho final:
  ```bash
  if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
      main
  fi
  ```
  Garante que o loop principal só seja iniciado se o script for executado diretamente (e não quando ele for "sourced" por outro script!para os teses do script...).


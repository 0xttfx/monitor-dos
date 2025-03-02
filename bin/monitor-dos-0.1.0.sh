#!/bin/bash
# monitor_ddos_hybrid.sh
# Abordagem híbrida para detectar ataques DDoS:
# 1. Monitora /proc/net/nf_conntrack para identificar picos no número de conexões.
# 2. Se houver pico, analisa os logs do nftables para extrair IPs com alta frequência.
# 3. Atualiza o mapa eBPF (pinado em MAP_PIN) para bloquear os IPs suspeitos.
#
# OBSERVAÇÕES TÉCNICAS:
# - Certifique-se de que o módulo nf_conntrack esteja carregado e que o arquivo /proc/net/nf_conntrack exista.
# - O log do nftables deve estar configurado corretamente; muitas vezes o kernel envia esses logs para syslog,
#   então pode ser necessário ajustar o caminho.
# - O script deve ser executado com privilégios de root para acesso aos arquivos e atualização do mapa eBPF via bpftool.
# - O programa XDP e o mapa eBPF devem estar previamente carregados na interface de rede.
#

# Valores padrões
MAP_PIN_DEFAULT="/sys/fs/bpf/blocked_ips"
THRESHOLD_CONN_DEFAULT=2000
LOG_THRESHOLD_DEFAULT=5
INTERVAL_DEFAULT=10
LOG_FILE_DEFAULT="/var/log/nftables.log"

# Inicializa variáveis com os valores padrão
MAP_PIN="$MAP_PIN_DEFAULT"
THRESHOLD_CONN="$THRESHOLD_CONN_DEFAULT"
LOG_THRESHOLD="$LOG_THRESHOLD_DEFAULT"
INTERVAL="$INTERVAL_DEFAULT"
LOG_FILE="$LOG_FILE_DEFAULT"

# Função para exibir a mensagem de ajuda
usage() {
    cat << EOF
Uso: $(basename "$0") [opções]

Opções:
  -m MAP_PIN         Caminho do mapa eBPF pinado (padrão: $MAP_PIN_DEFAULT)
  -c THRESHOLD_CONN  Número de conexões para acionar análise (padrão: $THRESHOLD_CONN_DEFAULT)
  -l LOG_THRESHOLD   Número mínimo de ocorrências de um IP nos logs para bloqueá-lo (padrão: $LOG_THRESHOLD_DEFAULT)
  -i INTERVAL        Intervalo de tempo para verificação em segundos (padrão: $INTERVAL_DEFAULT)
  -f LOG_FILE        Caminho para o arquivo de log do nftables (padrão: $LOG_FILE_DEFAULT)
  -h                 Exibe esta mensagem de ajuda e sai

Exemplo:
  sudo $(basename "$0") -m /sys/fs/bpf/blocked_ips -c 1500 -l 10 -i 15 -f /var/log/nftables.log

EOF
}

# Processa as opções de linha de comando
while getopts "m:c:l:i:f:h" opt; do
    case "$opt" in
        m) MAP_PIN="$OPTARG" ;;
        c) THRESHOLD_CONN="$OPTARG" ;;
        l) LOG_THRESHOLD="$OPTARG" ;;
        i) INTERVAL="$OPTARG" ;;
        f) LOG_FILE="$OPTARG" ;;
        h)
            usage
            exit 0
            ;;
        ?)
            usage
            exit 1
            ;;
    esac
done

echo "Configurações utilizadas:"
echo "  MAP_PIN:         $MAP_PIN"
echo "  THRESHOLD_CONN:  $THRESHOLD_CONN"
echo "  LOG_THRESHOLD:   $LOG_THRESHOLD"
echo "  INTERVAL:        $INTERVAL"
echo "  LOG_FILE:        $LOG_FILE"
echo

# Função: Converte um IP (formato x.x.x.x) para valor hexadecimal (big-endian)
ip_to_hex() {
    local ip="$1"
    IFS='.' read -r a b c d <<< "$ip"
    printf "0x%02X%02X%02X%02X" "$a" "$b" "$c" "$d"
}

# Função: Atualiza o mapa eBPF para bloquear um IP específico
block_ip() {
    local ip="$1"
    local key_hex
    key_hex=$(ip_to_hex "$ip")
    echo "Bloqueando IP suspeito: $ip (chave: $key_hex)"
    bpftool map update pinned "$MAP_PIN" key "$key_hex" value 0x1 2>/dev/null
}

# Função: Retorna a contagem de conexões em /proc/net/nf_conntrack
get_conn_count() {
    if [ -f /proc/net/nf_conntrack ]; then
        wc -l < /proc/net/nf_conntrack
    else
        echo "0"
    fi
}

# Loop principal de monitoramento
while true; do
    conn_count=$(get_conn_count)
    echo "Conexões atuais: $conn_count"

    if [ "$conn_count" -gt "$THRESHOLD_CONN" ]; then
        echo "Alerta: Pico de conexões detectado ($conn_count > $THRESHOLD_CONN)."
        echo "Analisando os logs do nftables para identificar IPs suspeitos..."

        # Captura uma janela de logs do nftables durante o intervalo definido.
        # 'timeout' limita a execução do tail, 'grep' filtra linhas com "SRC=",
        # 'sed' extrai o IP, e 'awk' seleciona IPs com ocorrências acima do limite.
        suspicious_ips=$(timeout "$INTERVAL" tail -n 1000 "$LOG_FILE" 2>/dev/null | \
            grep "SRC=" | sed -n 's/.*SRC=\([0-9.]\+\).*/\1/p' | sort | uniq -c | \
            awk -v thresh="$LOG_THRESHOLD" '$1 >= thresh {print $2}')

        for ip in $suspicious_ips; do
            block_ip "$ip"
        done
    else
        echo "Número de conexões dentro do esperado."
    fi

    sleep "$INTERVAL"
done


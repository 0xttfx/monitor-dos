#!/usr/bin/env bats

setup() {
  # Define variáveis necessárias para os testes (pode ser necessário ajustar conforme o seu ambiente)
  export MAP_PIN_DEFAULT="/tmp/test_blocked_ips"
  export THRESHOLD_CONN_DEFAULT=2000
  export LOG_THRESHOLD_DEFAULT=5
  export INTERVAL_DEFAULT=10
  export LOG_FILE_DEFAULT="/tmp/test_nftables.log"

  # Cria arquivos temporários para simular recursos utilizados pelo script
  touch "$MAP_PIN_DEFAULT"
  touch "$LOG_FILE_DEFAULT"
}

teardown() {
  rm -f "$MAP_PIN_DEFAULT" "$LOG_FILE_DEFAULT"
}

@test "ip_to_hex converte 192.168.1.1 para 0xC0A80101" {
  run bash -c 'source ../scripts/monitor_ddos_hybrid.sh; ip_to_hex "192.168.1.1"'
  [ "$status" -eq 0 ]
  [ "$output" = "0xC0A80101" ]
}

@test "usage exibe mensagem de ajuda" {
  run bash -c 'source ../scripts/monitor_ddos_hybrid.sh; usage'
  [ "$status" -eq 0 ]
  [[ "$output" =~ "Uso:" ]]
}


## Explicação dos testes

- setup/teardown:
Essas funções preparam o ambiente para os testes, criando arquivos temporários e definindo variáveis necessárias. Após os testes, os recursos são limpos.

- Teste da função ip_to_hex:
É feito o source do script e chamada a função ip_to_hex passando o IP "192.168.1.1". O teste compara a saída com o valor hexadecimal esperado (0xC0A80101).

- Teste da função usage:
É verificado se a função de ajuda (usage) exibe uma mensagem que contenha a palavra “Uso:”, indicando que a mensagem de uso foi impressa corretamente.

## Considerações adicionais

- Isolamento das funções:
Se o script original não estiver preparado para testes (por exemplo, se o loop principal rodar imediatamente), você deve refatorá-lo conforme o exemplo acima para separar a execução das funções da definição delas.

- Mocking de comandos externos:
Para funções que interagem com recursos do sistema (como bpftool, leitura de /proc/net/nf_conntrack, etc.), pode ser necessário usar técnicas de mocking ou ajustar variáveis de ambiente para simular os cenários desejados sem afetar o sistema real.

- Execução dos testes:
Após instalar o `Bats`, execute os testes com o comando `bats tests/` dentro do diretório raiz do projeto.

- Dependências:
  - [Bats](https://github.com/bats-core/bats-core)

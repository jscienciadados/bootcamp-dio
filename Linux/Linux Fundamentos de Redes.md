##Linux Fundamentos de Redes
Rede de computadores é um conjunto de equipamentos interligados de maneira a trocarem informações e compartilharem recursos de dados.

Rede Wan (Wide Area Network ou World Area Network) é uma rede geograficamente distribuida.
Rede Man (Metrpolitan Area Network) é uma rede metropolitana que interligam vários locais.
Rede Lan (Local Area Network) é uma rede local de forma geral em um único prédio ou campus.

Protocolos é a "linguagem" usada pelos dispositivos de uma rede de modo que eles consigam se entender.
IP - Protocolo de Internet - Endereço IP - Numeros que identificam seu computador em uma rede.
ICMP - (Internet Control Message Protocol) - tem por objetivo prover mensagens de controle na comunicação entre os nós.
DNS - (Domain Name Server) - Esse protocolo de aplicação tem por função identificar endereços ip´s e manter uma tabela com os endereços dos caminhos de algumas redes.

Interface de Rede é um software e/ou hardware que faz a comunicação em uma rede de computadores
As Interfaces de Rede no Linux estão localizadas no diretório /dev e a maioria é criada dinamicamente pelos softwares quando requisitadas.
exemplo: eth0 - Placa de rede ethert - cabeada
A Interface loopback é um tipo especial de interface que permite fazer conexões com voce mesmo, com ela, voce pode testar varios programas de rede sem interferir em sua rede. Padrão, o endereço IP 127.0.0.1 foi escolhido para loopback.

Comandos Avançados de Sistema
ifconfig -> exibe o endereço de ip
hosname -> exibe informações sobre o host
hostname -I -> exibe o endereço IP
hostname -i -> exibe o Loopback
w -> exibe informações do usuario logado na rede
who -> mostra como estou logado 
whoami -> exibe o usuario logado
ping -> testa a conexão da rede
dig -> exibe informações sobre o DNS
traceroute -> traça o caminho da rede
dig www.google.com +short -> tras apenas o endereço dns do site
whois -> exibe informações sobre determinado site
whois www.pudim.com.br
finger -> exibe informações do usuario logado no host

history -c -> limpa o historico
alias hh="history" -> cria um nickname para determinado comando
nl -> mostra o numero de linhas de um arquivo 
wc -l -> mostra o numero de linhas ou palavras
cmp -> faz comparação entre dois arquivos
last reboot -> exibe informações de reinicialização do sistema
route -m -> mostra a tabela de roteamente de interface de rede
time -> tempo que cada comando leva para ser processado
uptime -> mostra o tempo que o sistema esta em execução
init 0 -> desliga a maquina no instante
halt -> desliga com autenticacao
seq -> gera uma sequencia de valores aleatorio

linux online
https://bellard.org/jslinux

Questionario
1 - O que é uma interface de rede?
Interface de Rede é um software e/ou hardware que faz a comunicação em uma rede de computadores
2 - Qual sequencia de comandos exibe o numero de IP do siete www.google.com.br?
dig www.google.com.br
3 - Qual comando apaga o historico de comandos?
history -c
4 - Quais 3 tipos de protocolos de rede?
IP, ICMP e DNS
5 - O que é Rede?
É um conjunto de equipamentos interligados de maneira a trocarem informações e compartilharem recursos
6 - Quais opçoes de comandos para desligar a maquina rapidamente?
shutdown -h now, init 0, telint 0 e halt
7 - Qual a sequencia de comandos exibe a rota do seu compuatador até o host www.google.com.br
traceroute www.google.com.br
8 - Qual comando exibe a contagem do numero de palavras de um arquivo de nome vazio.txt?
wc -w vazio.txt

Gerenciadores de Pacotes
.deb -> sudo dpkg -i [nome_pacote]
.rpm -> 
rpm -ivh [nome_pacote]
sudo rpm -ivh --nodeps [pacote]

Atualização
rpm -U [pacote]

yum install [pacote]






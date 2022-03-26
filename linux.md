## Treinamento em Linux
man [comando] -> exibe a documentação do comando especificado

su -> trocar de usuario

## Gerenciamento de Usuarios
passwd -> troca senha de usuario
sudo passwd root -> troca a senha do usuario root
sudo adduser -> cria um novo usuario
sudo groupadd -> cria um novo grupo
sudo groupadd ti
sudo usermod -> adcionar usuarios em grupos
sudo usermod -aG ti linux -> adciona o usuario ao grupo
sudo usermod -L ti linux -> bloqueia o usuario ao grupo
sudo usermod -U ti linux -> desbloqueia usuario do grupo

## Navegador via linha de comando
sudo apt install links 

## Gerenciamento de Redes
## Comandos
sudo ifconfig -> exibe a configuração da interface de rede
sudo ifconfig enp0s3 down -> derruba a interface de rede
up -> levanta a rede
sudo ifconfig enp0s3 [ip] [netmask] -> troca o ip da rede

sudo route -> serve para visualizar rotas exixtentes ou mesmo criação de novas rotas

para adcionar uma rota 
sudo route add -net [ip] [netmask] dev [interface de rede]

para adicionar um gateway-padrao
sudo route add gw default  [gateway]

## Escaneamento de Portas (scan ports)
sudo apt install nmap

NMAP -> escaneamento de portas
sudo nmap 127.0.0.1 -> escaneamento na propria maquina
sudo nmap 127.0.0.1 --allports -sV

## Serviços Web - apache
sudo apt install apache2

## Subindo o serviço
sudo /etc/init.d/apache2 start

## Administração de Sistema
ps -> lista os processos em exceução
sudo ps -au
top -> exibe informações dos processos em andamento
kill e killall -> mata processos
kill -sigstop [PID] -> pausa o processo
kill -sigcont [PID] -> continua o processo de onde parou
sigkill -> significa a destruição do processo
killall -> mata todos os processos pelo nome e não pelo PID

## Rodando Processos em Background
--> utiliza & no final do comando para por em segundo plano
gnome-chess &

## Criando Terminais Virtuais
sudo apt install screen
screen -S [nome do terminal] -> cria um terminal virtual
[ctrl + A] + D -> finaliza o termianal

## Acesso a máquinas Remotas com SSH
sudo apt install SSH
sudo /etc/init.d/ssh start
-- senhas seguras
-- configurar o serviço shh 
/etc/ssh/sshd_config 


## SCP - Realizando transferencias de arquivos seguras
scp [origem][destino]

## Editor de Textos - vi
i, a, A, o -> modo de inserção de textos
esc :wq -> salva o arquivo
esc :x -> salva e sai do vi
esc :set nu -> insere linhas no arquivo
[y][y] -> copia uma linha inteira
[G]p -> cola a linha copiada
[yw] -> copia uma palavra
[dd] -> apaga uma linha inteira
[dw] -> apaga a palavra
[d->] -> apaga um caractere
[u] -> desfaz o comando anterior
[d]p -> cola a palavra

** videos 8

## Gerenciamento de Arquivos
sudo fdisk /dev/sda "p" -> mostra a tabela de alocação dos discos
cat /etc/mtab | grep sda1 -> exibe qual sistema de arquivo o linux esta usando

## Visualizando os volumes 
sudo cat /var/log/syslog | grep sda

## Verificando partições
sudo fdisk /dev/sda

## Criando Partições
sudo fdisk /dev/sdb -> opção p (partição)

## Particionando o disco
sudo fdisk /dev/sdb
-> new (p) primaria
-> p
-> w
-> t -> troca de partição (pode ser escolhida varias com a letra L)

## Criando Sistema de Arquivos
mkfs -> cria um sistema de arquivo
sudo ls /dev/sd*
sudo mkfs -t ext4 /dev/sdb1
sudo mkfs.ext4 /dev/sdb2


## Montagem de Volumes
mount -> faz a montagem de volumes
sudo df -h -> permite visualizar o tamanhos dos volumes
sudo mount /dev/sdb1 /
sudo umount /dev/sdb1 / -> desmonta um volume

## Montagem automatica de volumes
/etc/fstab -> basta informa-la 
cat /etc/fstab
sudo vi /etc/fstab
/dev/sdb1	/dev/novaParticao	ext4	defaults	0	0
esta é aforma de montagem automatica, quando der o boot no sistema ele o montaria o sistema


## Desmontagem de volumes
umount -> permite desmontar um volume da raiz de diretórios.

## Verificar um sistema de Araquivos - FSCK
fsck -> permite uma verificação na suade do sistema de arquivo presente na partição.
sudo fsck /dev/sdb1

## Agendamento de Tarefas
cron -> agendador de tarefas
sudo crontab -u root -e


## Politica de Firewall
iptables -> firewall padrao do linux montagem de tabelas de ip's
--> criar um script.sh para rodar todas as regras.

## Filtragem de Pacotes IPTables

## Port-Knocking
knockd
-> fazer a configuração do arquivo knockd.conf
subir o serviço
sudo /etc/init.d/knockd start



## Cyber Defense

## Defesa em profundidade
defesa de varias camadas

Segurança da informação -> conjunto de todas as medidas e ações tomadas por uma empresa para proteger as informações.
é a proteção da confidenciabilidade, integridade e disponibilidade da informação.

## Segurança da Informação ou Cibersegurança?
## Segurança da Informação
	. Definição de mecanismos para proteção da informação independentemente da sua forma de 	estado
	. A segurança da informação tem alcance amplo

## cibersegurança
	. Consiste na proteção dos ativos atraves do tratamento de ameaças à informação em formato
	digital, sejam elas armazenadas, em processamento ou em transporte.

## Triade CID
	* Confidencialidade => garantia de que apenas as pessoas certas podem acessar determinados 		dados

	Exemplos: -> seistema de controle de acesso, criptografia, entre outros mecanismos.

	* Integridade -> garantia de que os dados naoa foram adulterados da origem ate o destino
	ou em armazenamento.

	Exemplos -> Hashes

	* Disponibilidade -> garantia de que nossos serviços e os dados que eles precisam consumir 		estejam disponiveis a maior parte do tempo.

	Exemplos -> firewalls, load balance. cdns.

## Vetores de Ataques
. Colaboradores sem treinamento/conscientização sobre a segurança da informação
. Ataques de Phisshing -> vishing, smishing, whaling, pharming.
. Não utilização de uma boa de politicas de senhas
. Ausencia de um bom antivirus

. Malware -> código malicioso criado cm o objetivo de comprometer ao menos um dos pilares Sg
. Eavesdropping -> pratica de interceptar conversas não autorizadas, podem ser escritas, gravadas ou videos.
. Shoulder Surfing -> Coleta de informações atraves da observação.exemplos, nomes de usuarios, senhas, pins.
. Dumpster Diving -> revirar lixo, incluindo eletronico.
. Repackaging Legitimate APPS -> submeter um app malicioso nas lojas oficiais para extrair informações.
. Man-in-the-middle -> tecnica computacional para interceptar dados.
. Social Engineering -> convener alguem atraves de recursos pscologicos a compartilhar informações relevantes ao atacante.
. Politicas permissivas de acesso e controle
. Utilização de protocolos inseguros
. Ausencia de um mecanismo para correlação de eventos
. Ausencia de hardening -> fortalecimento do sistema operacional (enrigesser)
. Ausencia de uma politica para aplicação de patches de segurança
. Ausencia de um processo padrão de desenvolvimento seguro
-> filme Takedown - caçada virtual

## Tipos de hackers
Black-hat - nao segue codigo de etica
White-hat - utiliza a etica
Gray-hat - esta em cima do muro
Suicide hackers - invade sistema e sabe que vai ser preso, nao apaga seus rastros
Script kiddies - utiliza ferramentas - sem conhecimento
Cyber terrorist - terrorista cibernetico
Stat-sponsored hackers apts - conhecimentos avançados
hacktivist - pixadores

## Principais motivadores
- Dinheiro
- Politicos
- Espionagem industrial
- Hacktivismo
- Venda de informações
- Desafio e autoafirmação

## Redes TCP/IP e principais ataques
## Ataques
- Arp poisioning -> normalmente utilizado para realizar ataques MitTM
# echo 1 > /proc/sys/net/ipv4/ip_forward -> permite que a maquina atue como um roteador

# ettercap - Tq -i eth0 -M arp /// /// -> faz o sniffers de qualquer trafego que chegar na placa de rede.

- Mac flooding -> atque muito utilizado por atacante para que o switch funcione como um hub
# macof -i eth0 -n 10 -> pacotes sao enviados para todos os clientes inclive o atacante

- DNS Poisoning -> consiste em redirecionar o trafego da vitma para sites falsos

- Mac Spoofing -> consiste em duplicar logicamente o endereço Mac de um usuario legitimo
# macchanger eth0 -m [tempo] -> clonar logicamente
# ifconfig

## Aplicações Web e principais ataques
- HTTP: Cabeçalhos de requiição
. Accept -> tipos de conteudo aceitos na resposta
. Cookie -> serve para fazer o controle da sessão
. content-Length -> tamanho da requisição
. Host -> hostname da url requisitada
. Referer -> de onde a requisição foi feita
. User-Agent -> tipo de cliente utilizado

- HTTP: Cabeçalhos de resposta.
- Content-Encoding -> tipo de codificação utilizada
- Location -> utilizado para redirecionamentos
- Pragma -> define configurações de cache
- Server -> apresenta dados do servidor em questao
- Set-Cookie -> definir um novo cookie no cliente
- Status -> o status da resposta

## Sistemas Operacionais e principais ataques
. Malware -> ransomware, worm, vírus...
. Execução remota de código
. Elevação de privilégios

## Técnicas e ferramentas para coleta de informações
- OSINT -> Open-source intelligence e o OSINT Framework
- OSINT -> Coleta de informações a partir de fontes publicas
- OSINT ! = Codigo Aberto
- Subcategoria de cyber intelligence
- Coleta em redes sociais, sites de noticias, relatorios publicos entre outros.

## OSINT Framework
--> site https://osintframework.com
- possui uma listagem muito util de ferramentas.

## Fontes
. Redes Sociais, como facebook, twitter, instagran, linkedin
. Sites Governamentais (portal de transparencia)
. tv, radio
. blogs
. pastebin
. serviços de armazenamento (google drive, dropbox, oneDrive entre outros)
. listas de discussões abertas
. buscadores e varias outras

## Operation Security (opsec)
- Termo criado por militares norte-americanos durante a guerra do vietnã
- Consiste na proteção de informações críticas consideradas como essenciais durante operações militares.

## opsec e OSINT:
- dependendo da nossa operação em OSINT, teremos níveis de proteção diferentes.
Exemplo: Ao obter dados em redes sociais, nao precisamos nos preocupar necessariamente em ocultar nossa localização. Entretanto, ao fazer requisições a um IoC, queremos que o atacante não nos identifique.
- Rede Tor -> navegação anonima 

## Alguns Mecanismos
. Utilização de VPNs
. Rede Tor
. Criação de um avatar para as operações (perfil falso na rede social)

## Coleta Ativa vs Coleta Passiva
- Ativa:
	. Scan de porta via nmap
	. Brute-force em diretorios de aplicações web
	. Scraping em sites
	
- Passiva:
	. Na coleta passiva, não geramos logs diretamente nos servidores do alvo.
	- Monitoramento de trafego via wireshark ou tcdump
	- Coleta de dados em redes sociais
	- Acesso a arquivos do site via cache dos buscadores
	- Google hacking
	- Pesquisa via Shodan
	- Archive.org
	
## Google Hacking
--> Utilização do principal buscador no mercado para obtenção de informações sensíveis.
inurl:php?id= site:com.br 
--> busca informações a respeito dos sites que tem este padrão
(php) -> faz referencia direta a um objeto

intext:"senha" filetype:xlsx
--> busca arquivos que contenha a palavra senha e possivelmente as senha contida nela

intext:"senha" site:trello.com 
--> busca senhas no site do trello.com

filetype:old intext:"password"
--> busca senhas (password) em arquivos de backup

site:docs.google.com intext:"senha"
--> busca senha no google docs

inurl:/intranet/login.php
-> busca por senha em intranet

intitle:index of settings.py
-> arquivos de configurações bd e usuarios conexões

intitle:"index of" "*.php"
-> listagem php de todos os sites

inurl:admin filetype:txt
-> arquivo de texto simples que contem palavras admin e pode conter acesso ao admin

https://exploit-db.com/google-hacking-database

## Shodan - pesquisa
--> Serviço que permite a pesquisa de diversos servidores conectados à internet
port:445 country:br
proftpd 1.3.5 country:br
port:2375 product:"Docker"
port:9200 json (elast search com indice)

## Censys
--> similar ao Shodan, tambem permite a pesquisa por dispositivos conectados a internet
services.port: {22, 23, 24, 25}
service.software.product: "raspberry Pi"

## Maltego
--> Um dos principais softwares utilizados para inteligencia e analise forense
- automatiza muito o OSINT atraves de pesquisas em diferentes bases
- intuitiva e facil de usar

## Recon-ng
--> framework para reconhecimento
- prove um ambiente poderoso para OSINT
- interface CLI parecida a do Metasploit Framework
- ferramenta gratuita e por padrao instalada no kali

su
passwd

- marketplace info all
- marketplace install all

## Coletando Informações
modules load recon/domains-hosts/google_site_web
option list
options set SOURCE [site](daryus.com.br)
db query select * from hosts

## Exportando para csv
modules load reporting/csv

## Setando o nome
options set FILENAME /home/kali/Desktop/teste.csv
run

## Pulsedive
- plataforma gratuita para theat intelligence
- permite a pesquisa e scan de IPs, URLs e IOCs
IOCs -> indicador de comprometimento

## Extraindo Informações de Imagens
--> Imagens podem conter informações úteis para um atacante.
- Exemplos:
	. dispositivo utilizado
	. fabricante
	. geolocalização
	. software de edição utilizado
	
- a principal ferramenta utilizada para extração manual é o ExifTool
- permite a visualização, edição e exclusao de metadados
- pode ser utilizada para forjar dados

exiftool [nome da imagem.extensao]
-> extrai toda informações da imagem
exiftool -all= [nome da imagem] -> apaga os metadados da imagem

forjando
exiftool -autor=[nome do autor]
xxd [nome da imagem] -> localiza os metadados

## Whois
--> Protocolo da pilha TCP/IP especifico para consulta de informações de contato e DNS para entidades na internet

- Essas entidades podem ser:
	. nome do dominio
	. endereço IP
	. um AS
	
whois [site] ou [ip]

## crt.sh 
-> transparencia de certificados
- permite o monitoramento e auditoria de certificados digitais
- o site https://crt.sh -> permite consultar o historico dos certificados digitais emitidos a um dominio

## Nmap
--> principais ferramentas de qualquer hacker
- permite a enumeração de portas e possui diversos filtros
- possui scripts para analise de vulnerabilidades

## Tipos de Scan
-- TCP/SYN / Half open
	. opção padrao do nmap (parametro -sS)
	. não completa o three-way handshake
	. mais stealth
	
-- TCP Connect
	- completa o three-way handshake
	- utiliza a system call connect()
	- parametro -sT
	- menos stealth
	
-- UDP Scan
	- parametro -sU
	
-- Ping Scan
	. parametro -sn
	. muito util para descoberta de hosts ativos
	. nao verifica por portas abertas
	
## Entendendo e utilizando o Nmap
-- Principais Opções
	. -p -> especifica as portas que serao testadas
	. -sV -> opção para descorberta de versões
	. -F -> fast scan
	. --top-ports 10 -> testa as 10 portas mais comuns
	. -O -> descoberta de sistema operacional
	
## Moulos de reconhecimento do Metasploit
--> o Metasploit framework possui varios modulos auxiliares que podem nos ajudar no levantamento de informações.

## Entendendo Técnicas de Invasão como um cibercriminoso

## Conhecendo o OWASP Top 10
- Documento publicado pela OWASP Foundation a cada ~3 anos
- Contém uma lista das principais ameaças a aplicaçoes webdurante o periodo analisado
- visa melhorar a segurança de software em geral

## Top 10 de Ameaças
A1 -> Broken Acess Control
-> Controle de acesso quebrado
A2 -> Criptographic Failures
-> Falhas de criptografias (uso de protocolos e senhas inseguras) - vazamento de dados
A3 -> Injection
-> Falhas de falta de input do usuario para o banco de dados
A4 -> Insecure Design
-> Falhas relacionada ao design da aplicação
A5 -> Security Misconfiguration
-> Falhas de configurações - instalações defaults
A6 -> Vulnerable and Outdated Components
-> Componentes desatualizados
A7 -> Identification and Authentication Failures
-> Falhas na identificação do usuario
A8 -> Software and Data Integrity Failures
-> Falhas que causa integridade dos dados
A9 -> Security Logging and Monitoring Failures
-> Falhas em sistema que não sao bem monitorados
A10 -> Server-Side Request Forgey (SSRF)
-> falhas de servidores para obter informaçoes 

## Atacando Aplicações Web

## Usando o Sqlmap para explorar site inseguro
sqlmap -u http:testphp.vulweb.com/product.php?pic=1 --dbs (encontra as base de dados no site)

## Obtendo informações do banco de dados encontrados
-- Listar todas as tabelas
sqlmap -u http:testphp.vulweb.com/product.php?pic=1 --dbs -D [name of bank] --tables

## Obtendo informações de uma tabela especifica (users)
sqlmap -u http:testphp.vulweb.com/product.php?pic=1 --dbs -D [name of bank] -T [name of tables] --columns

## Realizando um Dump da tabela explorada
sqlmap -u http:testphp.vulweb.com/product.php?pic=1 --dbs -D [name of bank] -T [name of table] -C [name of field of table] --dump >> arquivo.csv

## Cross-site Scripting (XSS)
beef-xss -> gera um codigo malicioso quando injetado no browser da vitma e faz a exploração

## Conhecendo o Metasploit Framework
- uma das ferramentas mais utilizadas por hacker durante invasoes
- possui diversos modulos de scan e exploração
- automatiza muito o trabalho do atacante e do pentester
- pode armazenar informações em um banco de dados

msfconsole -> acessar
show option -> mostra o que o msf precisa
set Domain -> setar um dominio
run -> roda o metasploit
back -> volta para a raiz do msf

## Explorando as portas abertas no alvo
db_nmap sS -sV [host]

search vsftpd -> encontrando uma vulnerabilidade

## Atacando o host alvo
set RHOSTS [ip alvo]
exploit -> atacando o alvo


## Matendo Acesso

## Cobrindo os Rastros

## Engenharia Social

## Conhecendo e utilizando o iptables
- Firewall no qual podemos configurar regras de acesso ao servidor
- utiliza tabelas que contém uma série de regras
- As regras configuradas irão filtar trafego de entrada e saída.

## Principais Politicas
* ACCEPT -> Aceita Pacotes
* DROP -> Descarta Pacotes
* REJECT -> Rejeita Pacotes

## Principais Filtros
* INPUT -> Pacotes destinados ao servidor
* OUTPUT -> Pacotes enviados pelo servidor
* FORWARD -> Pacotes que serao encaminhados

## Comandos
iptables -L -v -> faz a listagem das regras
iptables -F -> apaga todas as regras
iptables -p INPUT -p tcp --dport 80 -j DROP -> Politica de negar tudo por padrão
iptables -A INPUT -p tcp --dport 80 -j ACCEPT -> aceita conexao na porta 80 (http)
iptables -A INPUT -p tcp --dport 22 -j ACCEPT -> libera acesso via ssh
iptables -A INPUT -p tcp --dport 80 -s [ip] -j ACCEPT -> aceitando conexão da origem
iptables -A INPUT -p tcp -s [IP] -j DROP -> Dropa da origem
iptables -A INPUT -s [IP] -j DROP -> Dropa da origem

nmap -sn -> scaneia a rede toda

## ModSecurity (Modsec)
- Firewall de camada 7
- Originalmente um módulo do apache
- Pode ser integrado com regras da OWASP

-- startando apache
systemctl start apache2

## Instalando o modsecurity
apt install libapache2-mod-security2

## Startando o modsecurity
a2enmod security2
systemctl restart apache2

## Fazendo backup do arquivo modsecurity.conf-recommended
cp /etc/modesecurity/modsecurity.conf-recommendended /etc/modsecurity/modsecurity.conf

## Macete do Bash
vi !$ ->ele completa com o nome do arquivo

## Habilitar
SecRuleEngine DetectionOnly -> apenas para [On]

## Baixar projeto da OWASP
git clone https://github.com/coreruleset/coreruleset.git

## Mover o arquivo crs-setup.conf.example
mv crs-setup.conf.example /etc/modsecurity/crs-setup.conf

## Mover a pasta com as regras 
mv rules /etc/modsecurity

## Configurar o modulo apache2
vi /etc/apache2/mods-enabled/security2.conf
# comentar a ultima linha

# Incluir a seguinte linha
Include /etc/modsecurity/rules/*.conf

restart apache2

## OWASP Top 10 controles proativos
- Contém técnicas que devem ser incluidas em projetos de desenvolvimento
- Fornece uma orientação e recomendações sobre o desenvolvimento de software seguro
* https://owasp.org/www-project-proactive-controls/

C1 - Defina requisitos de segurança
C2 - Utilize framework e bibliotecas seguras
C3 - Acesso seguro ao banco de dados
C4 - Codifique e sanitize os dados
C5 - Valide todas as entradas
C6 - Implemente identidade digital
C7 - Aplique controles de acesso
C8 - Proteja dados em todo lugar
C9 - Implemente logs e monitoramento
C10 - Trate todos os erros e exceções

## Boas Práticas de Codificação
* Validação dos dados de entrada
* Codificação dos dados de saida
* Autenticação e gerenciamento de credenciais
* Gerenciamento de sessões
* Controle de acesso
* Praticas de criptografia
* Tratamento de erros e logging
* Proteção de dados
* Segurança nas comunicações
* Hardening do sistema
* Segurança no banco de dados
* Gerenciamento de arquivos

## SAST DAST SCA

## SAST -> consiste em analisar o código fonte da aplicação em busca de vulnerabilidades

## DAST -> Busca por vulnerabilidades com o software em execução

## SCA -> Identificação de bibliotecas contendo vulnerabilidades conhecidas

-- a ferramenta mais conhecida para realização de SAST é o Sonarqube
-- tem suporte para mais de 20 linguagens de programação
-- diversos plugins disponiveis, inclusive para SCA

sonarqube -> roda na porta 9000
 SonarLint -> extensao para vs code
 
## Hardening de sistemas
* Mapear ameaças, mitigar riscos e adotar ações corretivas

Guia disponibilizado pelo Nic.br
https://bcp.nic.br/i+seg/acoes/hardening/

## Hardening de Sistemas: Requisitos
- autenticação
- autorização
- auditoria
- acesso
- logs
- sistema
- configurações

## Conhecendo e utilizando o PortSentry
* Aplicação capaz de barrar scans e tentativas de burlar sua segurança
* simples de ser utilizada
* simula portas abertas no seu servidor
* quando as portas recebem alguma requisição, a origem é bloqueada

## Instalação
apt-get install portsentry

systemctl stop portsentry

## Habilite o:
vi /etc/portsentry/portsentry.conf
BLOCK_TCP="1" 
BLOCK_UDP="1"

## Habilite KILL_ROUTE via iptables;
vi /etc/portsentry/portsentry.conf
KILL_ROUTE="/sbin/iptables -I INPUT -s $TARGET$ -j DROP"

Startando o portsentry
portsentry -stcp -> barra scanners

pkill portsentry -> para a execução

## DevOps e DevSecOps
DevOps -> Desenvolvimento + Operações
DevSecOps -> Desenvolvimento + Segurança + Operações

A segurança de fazer parte de todo processo de desenvolvimento de software.
A abordagem SSL (Shifing Security Left) nos permite lidar com problemas de segurança com antencendencia e com frequencia.
Encontrar problemas de segurança com antecedencia leva menos erros e menos comprometimentos.

## Segurança e Privacidade por design
Segurança por design --> Visa incluir segurança no software desde a sua fundação
https://wiki.owasp.org/index.php/security by Design Principles

Privacidade por design --> Visa incluir proteção à privacidade do usuario desde a idealização do software
https://www.ipc.on.ca/wp-content/uploads/2018/01/pbd-1.pdf

## Ferramentas
https://osintframework.com/
Hacker Tools -> Ferramentas para hacking











 
























































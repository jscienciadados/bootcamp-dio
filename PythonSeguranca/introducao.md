##Introdução à Segurança da Informação em Python
_____________________________________________________________________________________________________

Dados -> pode ser uma representação simbólica, numerica ou textual qualquer.
Informação -> é o conjunto ou a junção de dados que fazem umcontexto ou sentido.

Segurança da Informação -> Area que tem com objetivo assegurar que todos os dados ou mais informações esteja sempre confidenciais,
integros e disponiveis em qualquer meio de comunicação.

Por que Segurança?
-> o ser humano tem necessidade de segurança
Piramide de Maslow
sentido de baixo para cima
Auto Realização
Estima
Sociais
Segurança
Fisiologicas

##Pilares da Segurança da Informação
Integridade -> Principio que visa a proteger a informação de alterações indevidas.
Confidencialidade -> Principio que visa manter uma informação confidencial
Disponibilidade -> Principio que visa garantir que um recurso e/ou informação esteja disponivel
Identificação -> Visa identificar uma entidade
Autenticação -> Visa verificar a entidade e suas credenciais
Autorização -> Visa autorizar a entidade dentro de um sistema
Nao Repúdio -> Visa evitar que uma entidade negue suas ações em um sistema

O que é ICMP -> (internet Control Message protocol), é um protocolo integrante do protocolo IP utilizado para fornecer relatorios
de erros a fonte original.

O que é o Ping -> é uma ferramenta que usa o protocolo ICMP para testar a conectividade entre nós. É um comando disponivel pra
ticamente em todos os sistemas operacionais que consiste no envio de pacotes para o equipamento de destino e na "escuta" das 
respostas.

Host A------------------------------------------Server
-->echo request
echo reply <---

ping -n 6 www.google.com.br

##Biblioteca Socket
-> fornece acesso de baixo nível à interface de rede.
-> O S.O fornece a API socket que relaciona o programa com a rede

TCP -> (transmission Control Protocol) ou protocolo de controle de transmissão é um protocolo de comunicação, que dão suporte a rede global 
internet, verificando se os dados são enviados na sequencia correta e sem erros.

UDP -> (User Datagram Protocol) ou protocolo de datagrama de usuário é um protocolo simples da camada de transporte que permite que a aplicação
envie um datagrama dentro num pacote ipv4 ou ipv6 a um destino, porem sem qualquer tipo de garantia que o pacote chegue corretamente.

Biblioteca Random
Esta biblioteca implementa geradores de números pseudoaleatorios para varias distribuições.
Esta biblioteca será utilizada no gerador de senhas para randomizar letras e numeros e a cada execução do programa gerar uma nova senha aleatoria.

O que é um hash
É como se fosse um identificador único gerado atraves de um algoritmo que vai analisar byte a byte de determinado código que só aquele arquivo terá. se neste mesmo arquivo um unico bit for alterado
o hash gerada sera diferente.

haslib -> esta biblioteca implementa uma interface comum para muitos algoritmos de hash seguro com SHA1, SHA256, MD5 entre outros

Multithreading -> é o processo e no ambiente multithread, cada processo pode responder a várias solicitações concorrentemente ou mesmo simultaneamente.

Biblioteca Multithreading -> constroi interfaces de alto nivel para processamento usando o módulo thread, de mais baixo nível, ou seja relação direta com o processador.

Biblioteca ipaddress -> tem a capacidade de criar, manipular endereços IP do tipo IPv4, IPv6 e até redes inteiras.

Wordlist -> são arquivos contendo uma palavra por linha. São utilizadas em ataques de força bruta como quebra de autenticação, pode ser usada para testar a autenticação e confidencialidade de um sistema.

Itertools -> esta biblioteca fornece condições para iteraçoes como permutação e combinação.

Web Scraping -> é uma ferramenta de coleta de dados da web, uma forma de mineração que permite a extração de dados de sites da web convertendo-os em informação estruturada para posterior análise.

Bibliotecas:
BeautifulSoup -> é usada para extração de dados de arquivos Html e XML.
Request -> permite que envie solicitações HTTP em Python.

Web Crawler -> é uma ferramenta usada para encontrar, ler e indexar páginas de um site. É como um robô que captura informaçoes de cada um dos links que encontra pela frente, cadastra e compreende o que é mais relevante. (palavras chaves)
Muito utilizado em levantamento de informações em um processo de Pentest.

Bibliotecas:
BeautifulSoup
Operator -> exporta um conjunto de funções eficientes correspondentes aos operadores intrinsecos do python como: +-*/not and
Collections -> nos ajuda a preencher e manipular eficientemente as estruturas de dados como tuplas, dicionarios e listas.

Verificador de Telefone
Biblioteca phonenumbers -> fornece varios recursos,como informações basicas de um numero de telefone, validação de um numero de telefone, etc.

Ocultador de arquivos
ctypes -> fornece tipos de dados compatíveis com C e permite funções de chamada em DLLs ou bibliotecas compartilhadas.

Verificador de IP externo
Bibliotecas:
re -> permite operações com expressoes regulares
json -> fornece operações de codificação e decodificação JSON
urllib.request import urlopen -> funções e classes que ajudam a abrir urls.
http://ipinfo.io

Ferramenta Grafica para abrir navegador
Biblioteca:
webbrowser -> fornece uma interface de alto nivel para permitir a exibição de documentos web aos usuarios.
tkinter -> fornece interface padrao do python para o kit de ferramentas graficas Tk.




./pycharm.sh






=====================================================================================================






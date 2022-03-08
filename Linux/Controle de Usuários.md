Controle de Usuários
##Adcionando um Usuario
sudo adduser dio

##Trocar de usuario 
sudo su [usuario] -> root
su - -> root
su -> troca de usuario

##Alterar a senha do usuario
passwd [usuario]
D#i45@2022

##Macecete para Senha
ZENIT
POLAR

dio
DENAT@0234

LASTLOG -> EXIBE INFORMAÇOES DE TODOS OS USUARIOS
last -> exibe informaçoes dos usuario logado no sistema
logname -> exibe o nome do usuario logado no sistema
id -> exibe identificadores dos usuarios
cat /etc/paswwd -> exibe todos os usuarios do sistema

##Remover o usuario
sudo userdel -r [nome usuario]

##Grupos
Grupos permitem organizar os usuarios e definir as permissões de acesso a arquivos e diretorios de forma facil.

cat /etc/group | more -> exibe todos os grupos
groups -> exibe todos os grupos do usuarios

##Cria um grupo
sudo addgroup [nome grupo]

##Adicionar um usuario a um grupo
sudo adduser [usuario] [grupo]
gpasswd -a [usuario] [grupo]

##Removendo um usuario de um grupo
gpasswd -d [usuario] [grupo]

##Remover um grupo
sudo groupdel [grupo]
cat /etc/group/group | grep aula

##Permissões
Permissões em arquivos e diretórios servem para restringir acessos como:
leitura, escrita e execução, onde
r - read (leitura)
w - write (escrita)
x - eXecution (execução)

##Tabela de Permissões
==========================================
User (Owner)	Group 		Other
==========================================
r 	w 	x = 	r 	w 	x = r 	w 	x
==========================================
4 	2 	1 = 	4 	2 	1 = 4 	2 	1
==========================================

ls -lh -> exibe as permissões dos usuarios
chmod [numeros] [nome]-> muda a permissão de diretorio ou de arquivo










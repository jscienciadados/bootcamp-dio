import os
# Import os -> importa o módulo ou biblioteca os (integra os programas e recursos do S.O).
print("#" * 60)

ip_ou_host = input("Digite o Ip pu host a ser verificado: ")
# Criamos uma variavel que vai receber do usuario um endereço de Ip ou Host
print("-" * 60)
os.system('ping {}'.format(ip_ou_host))
# Chama o metodo system da biblioteca os - comando ping que verifica a conexão o ip informado
# e formatando a saida do comando.
print("#" * 60)

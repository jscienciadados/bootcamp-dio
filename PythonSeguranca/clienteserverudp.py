import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

print("Cliente Socket Criado com sucesso!!!")

host = 'localhost'
port = 5433
mensagem = 'Mensagem de Comunicação'
try:
    print('cliente: ' + mensagem)
    s.sendto(mensagem.encode(), (host, 5432))

    dados, servvidor = s.recvfrom(4096)
    dados = dados.decode()
    print("cliente: " + dados)
finally:
    print('cliente: Fechando a conexão')
    s.close()    
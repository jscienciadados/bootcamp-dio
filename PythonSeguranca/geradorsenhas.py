import random
import string

# Implementando um Gerador de Senhas

tamanho = int(input('Digite o tamanho de senha que voce deseja: '))
chars = string.ascii_letters + string.digits + '!@#~%&*()-=+?./'
rnd = random.SystemRandom()

print(''.join(rnd.choice(chars) for i in range(tamanho)))
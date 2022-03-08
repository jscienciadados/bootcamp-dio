import os
import time

print("Programa que Verifica varios endereços ip's")
print("#" * 60)
with open('hosts.txt') as file:
	dump = file.read()
	dump = dump.splitlines()
	for ip in dump:
		print('Verificando conexão com o Ip: ', ip)
		print('-' * 60)
		os.system('ping  {} '.format(ip))
		print('#' * 60)
		time.sleep(5)	
	

import ipaddress

# Implementando um verificador de ip's

ip = '192.168.0.1'
endereco = ipaddress.ip_address(ip)
print(endereco + 10)
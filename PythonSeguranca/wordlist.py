import itertools

# Implementando um Gerador de Wordlist

string = input("String a ser permutada: ")
resultado = itertools.permutations(string, len(string))

for i in resultado:
    print(''.join(i))
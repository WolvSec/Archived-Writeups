import base64
import codecs
import random
from pwn import *
import json
import re

from Crypto.Util.number import bytes_to_long, long_to_bytes

IP, PORT = 'socket.cryptohack.org', 13377

p = remote(IP, PORT)

def hex_decode(cipher):
	PLAINTEXT = ""
	array = re.findall('..?', cipher)
	for i in array:
		i = int(i, 16)
		PLAINTEXT = PLAINTEXT + chr(i)
	return PLAINTEXT

def utf8(cipher):
	PLAINTEXT = ""
	for i in cipher:
		PLAINTEXT = PLAINTEXT + chr(i)
	return PLAINTEXT
	
def rot13(cipher):
	return codecs.decode(cipher, 'rot_13')

def bigint(cipher):
	return long_to_bytes(int(cipher, 16)).decode()

def base_64(cipher):
	return base64.b64decode(cipher).decode()

for i in range(0,101):
	print(i)
	if i == 100:
		print(p.recvline())
	result = p.recvline()
	j = json.loads(result)
	type_ = j["type"]
	encoded = j["encoded"]
	result = ""
	if type_ == 'hex':
		result = hex_decode(encoded)
	elif type_ == 'base64':
		result = base_64(encoded)
	elif type_ == 'rot13':
		result = rot13(encoded)
	elif type_ == 'bigint':
		result = bigint(encoded)
	elif type_ == 'utf-8':
		result = utf8(encoded)
	your_input = "{\"decoded\" : " + "\"" + result + "\" }"
	print(your_input)
	p.sendline(your_input)
	if i == 100:
		print(p.recvline())
		


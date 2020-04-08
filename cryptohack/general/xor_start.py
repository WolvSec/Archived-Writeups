import re
import codecs

flag = "label"
binary = codecs.encode(flag, 'hex')

bin_array = re.findall('..?', binary)
xor_key = 13

temp = ""
for i in bin_array:
	integer = int(i, 16)
	xored = integer ^ xor_key
	temp = temp + chr(xored)

print(temp)




PLAINTEXT = ""


#for i in result:
#	i = int(i, 16)
#	PLAINTEXT = PLAINTEXT + chr(i)

print(PLAINTEXT)

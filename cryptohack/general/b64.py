import re

flag = "72bca9b68fc16ac7beeb8f849dca1d8a783e8acf9679bf9269f7bf"

PLAINTEXT = ""
binary = f"{0:4b}".format(int(flag,16))

print(binary)

result = re.findall('..?', flag)
print(result)

list_test = []
binary_string = ""
for i in result:
	i = int(i, 16)
	binary_string = binary_string + format(i, '08b')
#	PLAINTEXT = PLAINTEXT + chr(i)

divide = re.findall('......?', binary_string)

encode = []
for i in divide:
	i = int(i,2)
	encode.append(i)

b64_chart = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6' ,'7', '8', '9', '+', '/']

flag = ""
for i in encode:
	flag = flag + b64_chart[i]

print(flag)

import re
import codecs

flag = "0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104"


bin_array = re.findall('..?', flag)

#myXORkey
key = [109, 121, 88, 79, 82, 107, 101, 121]

temp = ""
print(bin_array)
for i in range(len(bin_array)):
	integer = int(bin_array[i], 16)
	xored = integer ^ key[i % 8]
	temp = temp + chr(xored)

print(temp)

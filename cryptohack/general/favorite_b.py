import re
import codecs

flag = "73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d" 


bin_array = re.findall('..?', flag)

print(bin_array[0])

for i in range(0xff):
	temp = ""
	print(hex(i))
	for j in range(len(bin_array)):
		integer = int(bin_array[j], 16)
		xored = integer ^ i 
		temp = temp + chr(xored)
	#for j in bin_array:
	#	integer = int(j, 16)
	#	xored = integer ^ i
	#	temp = temp + chr(xored)
	print(temp)

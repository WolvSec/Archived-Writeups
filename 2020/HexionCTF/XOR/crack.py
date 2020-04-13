from itertools import cycle

flagTemplate = 'hexCTF{suaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}'
with open("flag.enc", "r") as file:
    flagenc = file.read()

print(len(flagenc))

key = []
for i in range(0, len(flagenc)):
    key.append(ord(flagTemplate[i]) ^ ord(flagenc[i]))

print(key)
#     [74, 116, 109, 90, 122, 67, 74, 121, 83, 91, 112, 126, 88, 122, 78, 66, 107, 84, 74, 114, 101, 87, 114, 81, 95, 99, 69, 78, 109, 124, 82, 122, 78, 66, 110, 73, 72, 124, 99, 78, 104, 67]

key = [74, 116, 109, 90, 122, 67, 74, 107, 71]
print(''.join([chr(n) for n in key]))

key_gen = cycle(key)
flag = ''
for i in range(len(flagenc)):
    flag = flag + chr(ord(flagenc[i]) ^ next(key_gen))

print(flag)

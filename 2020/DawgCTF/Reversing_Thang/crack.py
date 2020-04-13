userdata = [0x41, 0xf5, 0x51, 0xd1, 0x4d, 0x61, 0xd5, 0xe9, 0x69, 0x89, 0x19, 0xdd, 0x09, 0x11, 0x89, 0xcb, 0x9d, 0xc9, 0x69, 0xf1, 0x6d, 0xd1, 0x7d, 0x89, 0xd9, 0xb5, 0x59, 0x91, 0x59, 0xb1, 0x31, 0x59, 0x6d, 0xd1, 0x8b, 0x21, 0x9d, 0xd5, 0x3d, 0x19, 0x11, 0x79, 0xdd]

# Massaged C code from ghidra
# k = 0;
#   while (k < 0x15) {
#     temp = userdata[k];
#     userdata[k] = userdata[0x2a - k];
#     userdata[0x2a - k] = temp;
#     k = k + 1;
#   }
def reverseBytesInList():
    for k in range(0, 0x15):
        temp = userdata[k]
        userdata[k] = userdata[0x2a - k]
        userdata[0x2a -k] = temp


# Massaged C code from ghidra
# j = 0;
# while (byteValue = 0, j < 0x2b) {
#   i = 0;
#   while (i < 8) {
#     if ((1 << i & userdata[j]) != 0) {
#       byteValue = byteValue | (1 << (7 - i));
#     }
#     i = i + 1;
#   }
#   userdata[j] = byteValue;
#   j = j + 1;
# }
def reverseBitsInByte():
    for j in range(0, 0x2b):
        byteValue = 0
        for i in range(0, 8):
            if (userdata[j] & (1 << i)) != 0:
                byteValue = byteValue | (1 << (7 - i))
        userdata[j] = byteValue


def flipBitsInByte():
    for j in range(0, 0x2b):
        userdata[j] = userdata[j] ^ 0xff

reverseBytesInList()
reverseBitsInByte()
flipBitsInByte()

print(''.join([chr(n) for n in userdata]))





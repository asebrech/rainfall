#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void run(void)
{
	fwrite("Good... Wait what?\n", 1, 19, stdout);
	system("/bin/sh");
	return;
}

/*
 * Assembly analysis:
 *
 * 08048480  PUSH EBP                 ; Save old base pointer
 * 08048481  MOV EBP, ESP             ; Set up new stack frame
 * 08048483  AND ESP, 0xfffffff0      ; Align stack to 16-byte boundary
 * 08048486  SUB ESP, 0x50            ; Allocate 80 bytes (0x50)
 * 08048489  LEA EAX, [ESP + 0x10]    ; Buffer starts at ESP + 16
 * 0804848d  MOV [ESP], EAX           ; Pass buffer address to gets()
 * 08048490  CALL gets
 * 08048495  LEAVE
 * 08048496  RET
 *
 * Stack layout after SUB ESP, 0x50:
 * - Buffer starts at ESP + 0x10 (16 bytes from ESP)
 * - Buffer size = 0x50 - 0x10 = 64 bytes
 * - Overflow requires 76 bytes to reach return address:
 *   64 (buffer) + ~8 (alignment padding) + 4 (saved EBP) = 76
 */
int main(void)
{
	char buffer[64];

	gets(buffer);
	return 0;
}

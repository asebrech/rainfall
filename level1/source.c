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
 * Stack layout:
 * 
 * High Memory
 * ┌──────────────────────────────────┐
 * │ Return Address     [EBP + 4]     │ ← 4 bytes
 * ├──────────────────────────────────┤
 * │ Saved EBP          [EBP]         │ ← 4 bytes
 * ├──────────────────────────────────┤
 * │ Alignment padding  (~8 bytes)    │ ← From AND ESP, 0xfffffff0
 * ├──────────────────────────────────┤
 * │ buffer[64]         [ESP + 0x10]  │ ← 64 bytes
 * ├──────────────────────────────────┤
 * │ Padding            [ESP]         │ ← 16 bytes
 * └──────────────────────────────────┘
 * Low Memory
 * 
 * Overflow: 64 (buffer) + 8 (align) + 4 (saved EBP) = 76 bytes to return address
 */
int main(void)
{
	char buffer[64];

	gets(buffer);
	return 0;
}

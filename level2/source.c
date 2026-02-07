#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * Stack layout:
 * 
 * High Memory
 * ┌──────────────────────────────────┐
 * │ Return Address     [EBP + 4]     │ ← 4 bytes (target)
 * ├──────────────────────────────────┤
 * │ Saved EBP          [EBP]         │ ← 4 bytes
 * ├──────────────────────────────────┤
 * │ (unused)           [EBP - 4]     │ ← 4 bytes
 * ├──────────────────────────────────┤
 * │ (unused)           [EBP - 8]     │ ← 4 bytes
 * ├──────────────────────────────────┤
 * │ ret_addr           [EBP - 12]    │ ← 4 bytes (overwritten during overflow)
 * ├──────────────────────────────────┤
 * │ buffer[63]         [EBP - 13]    │
 * │ ...                              │
 * │ buffer[0]          [EBP - 76]    │ ← 64 bytes
 * └──────────────────────────────────┘
 * Low Memory
 * 
 * Overflow: 64 (buffer) + 4 (ret_addr) + 8 (unused) + 4 (saved EBP) = 80 bytes to return address
 */
void p(void)
{
	char buffer[64];        // At EBP - 76 (64 bytes to EBP - 13)
	unsigned int ret_addr;  // At EBP - 12 (4 bytes)

	fflush(stdout);
	gets(buffer);

	ret_addr = __builtin_return_address(0);
	if ((ret_addr & 0xb0000000) == 0xb0000000) {
		printf("(%p)\n", ret_addr);
		_exit(1);
	}

	puts(buffer);
	strdup(buffer);
	return;
}

int main(void)
{
	p();
	return 0;
}

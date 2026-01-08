#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void p(void)
{
	char buffer[76];
	unsigned int ret_addr;

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

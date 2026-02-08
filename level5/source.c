#include <stdio.h>
#include <stdlib.h>

void o(void)
{
	system("/bin/sh");
	_exit(1);
}

void n(void)
{
	char buffer[512];
	
	fgets(buffer, 512, stdin);  // 0x200 = 512
	printf(buffer);             // Format string vulnerability!
	exit(1);
}

int main(void)
{
	n();
	return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void n(void)
{
	system("/bin/cat /home/user/level7/.pass");
}

void m(void)
{
	puts("Nope");
}

int main(int argc, char **argv)
{
	char *buffer;
	void (**function_pointer)(void);
	
	// Allocate 64 bytes for buffer on the heap
	buffer = (char *)malloc(64);
	
	// Allocate 4 bytes for function pointer on the heap
	function_pointer = (void (**)(void))malloc(4);
	
	// Set function pointer to point to m() by default
	*function_pointer = m;
	
	// Vulnerable: No bounds checking! Can overflow buffer into function_pointer
	strcpy(buffer, argv[1]);
	
	// Call whatever function the pointer points to
	(*function_pointer)();
	
	return 0;
}

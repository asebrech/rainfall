#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

char c[68];  // Global buffer where flag gets stored

void m(void)
{
	time_t current_time;
	
	current_time = time(NULL);
	printf("%s - %d\n", c, current_time);
}

int main(int argc, char **argv)
{
	int *chunk1;   // Points to first heap chunk (8 bytes: int + pointer)
	int *chunk2;   // Points to second heap chunk (8 bytes: int + pointer)
	FILE *file;
	
	// First allocation: 8 bytes storing [int, pointer]
	chunk1 = (int *)malloc(8);
	chunk1[0] = 1;                    // Store integer 1 at offset 0
	chunk1[1] = (int)malloc(8);       // Store pointer at offset 4 (treating as int)
	
	// Second allocation: 8 bytes storing [int, pointer]
	chunk2 = (int *)malloc(8);
	chunk2[0] = 2;                    // Store integer 2 at offset 0
	chunk2[1] = (int)malloc(8);       // Store pointer at offset 4 (treating as int)
	
	// Vulnerable: No bounds checking!
	// chunk1[1] is a pointer stored as an int - cast it back to char* for strcpy
	strcpy((char *)chunk1[1], argv[1]);  // Overflow can corrupt chunk2[1]
	strcpy((char *)chunk2[1], argv[2]);  // Uses potentially corrupted pointer!
	
	// Read flag into global buffer
	file = fopen("/home/user/level8/.pass", "r");
	fgets(c, 68, file);               // 0x44 = 68 in decimal
	
	puts("~~");
	return 0;
}

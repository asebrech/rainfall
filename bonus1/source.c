#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	char buffer[40];    // Stack buffer at ESP+0x14
	int num;            // Signed integer at ESP+0x3c
	
	// Convert first argument to signed integer
	num = atoi(argv[1]);
	
	// ⚠️ VULNERABLE: Signed integer comparison
	// Negative numbers pass this check!
	if (num <= 9)
	{
		// ⚠️ CRITICAL: Integer overflow vulnerability!
		// - num is SIGNED (can be negative)
		// - num * 4 can overflow/wrap around
		// - memcpy expects size_t (UNSIGNED)
		// - Negative num * 4 → huge positive size!
		memcpy(buffer, argv[2], num * 4);
		
		// Check if num equals magic value 0x574f4c46 ("FLOW" in little-endian)
		// If memcpy overflowed the buffer, it overwrote num!
		if (num == 0x574f4c46)
		{
			execl("/bin/sh", "sh", 0);    // 🚩 Spawn shell!
		}
		return 0;
	}
	else
	{
		return 1;
	}
}

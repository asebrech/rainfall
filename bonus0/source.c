#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void p(char *dest, char *prompt);
void pp(char *buffer);

int main(void)
{
	char buffer[54];
	
	pp(buffer);
	puts(buffer);
	return 0;
}

void pp(char *param_1)
{
	char cVar1;
	uint uVar2;
	char *pcVar3;
	byte bVar4;
	char local_34[20];  // First 20-byte buffer
	char local_20[20];  // Second 20-byte buffer
	
	bVar4 = 0;
	
	// Read first input (20 bytes max)
	p(local_34, " - ");
	
	// Read second input (20 bytes max)
	p(local_20, " - ");
	
	// ⚠️ VULNERABLE: strcpy expects null-terminated string
	// If local_34 has no null terminator, it keeps reading into local_20!
	strcpy(param_1, local_34);
	
	// Calculate string length (will read past local_34 if no null!)
	uVar2 = 0xffffffff;
	pcVar3 = param_1;
	do {
		if (uVar2 == 0) break;
		uVar2 = uVar2 - 1;
		cVar1 = *pcVar3;
		pcVar3 = pcVar3 + (uint)bVar4 * -2 + 1;
	} while (cVar1 != '\0');
	
	// Add space separator after the string
	(param_1 + (~uVar2 - 1))[0] = ' ';
	(param_1 + (~uVar2 - 1))[1] = '\0';
	
	// ⚠️ Concatenate second buffer (more overflow!)
	strcat(param_1, local_20);
	return;
}

void p(char *dest, char *prompt)
{
	char *pcVar1;
	char buffer[4104];  // Large read buffer
	
	puts(prompt);
	read(0, buffer, 4096);
	
	// Find newline and replace with null terminator
	pcVar1 = strchr(buffer, 10);
	*pcVar1 = '\0';
	
	// ⚠️ CRITICAL: strncpy does NOT null-terminate if source >= 20 bytes!
	// If user inputs 20+ characters, dest will have NO null terminator
	strncpy(dest, buffer, 20);
	return;
}

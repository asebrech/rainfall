#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Read input and copy to dest (max 20 bytes, may not null-terminate!)
void p(char *dest, char *prompt);

// Read two inputs and concatenate them with space separator
void pp(char *buffer);

int main(void)
{
	char buffer[54];
	
	pp(buffer);      // Read and process two inputs
	puts(buffer);    // Print concatenated result
	return 0;
}

void pp(char *output_buffer)
{
	char first_input[20];   // First 20-byte buffer
	char second_input[20];  // Second 20-byte buffer
	
	// Read first input (up to 20 bytes, may not be null-terminated!)
	p(first_input, " - ");
	
	// Read second input (up to 20 bytes, may not be null-terminated!)
	p(second_input, " - ");
	
	// ⚠️ VULNERABILITY 1: strcpy expects null-terminated string
	// If first_input has no null terminator, strcpy will read past it into second_input!
	strcpy(output_buffer, first_input);
	
	// Calculate length of what was copied
	// (This is just strlen reimplemented)
	size_t len = 0;
	while (output_buffer[len] != '\0') {
		len++;
	}
	
	// Add space separator at the end of the copied string
	output_buffer[len] = ' ';
	output_buffer[len + 1] = '\0';
	
	// ⚠️ VULNERABILITY 2: strcat concatenates without bounds checking
	// Can overflow output_buffer if combined length > 54 bytes
	strcat(output_buffer, second_input);
}

void p(char *dest, char *prompt)
{
	char buffer[4096];
	
	puts(prompt);
	read(0, buffer, 4096);
	
	// Find newline and replace with null terminator
	char *newline = strchr(buffer, '\n');
	*newline = '\0';
	
	// ⚠️ CRITICAL VULNERABILITY: strncpy does NOT null-terminate if source >= n!
	// If user inputs 20+ characters, dest will have NO null terminator
	// This leads to out-of-bounds reads in strcpy() later
	strncpy(dest, buffer, 20);
}

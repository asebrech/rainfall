#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
	char buffer[66];
	char message[66];
	FILE *file;
	int index;

	file = fopen("/home/user/end/.pass", "r");
	memset(buffer, 0, 66);

	if (file == NULL || argc != 2)
		return (-1);

	fread(buffer, 1, 66, file);
	buffer[atoi(argv[1])] = '\0';
	
	fread(message, 1, 65, file);
	fclose(file);

	if (strcmp(buffer, argv[1]) == 0)
		execl("/bin/sh", "sh", NULL);
	else
		puts(message);

	return (0);
}

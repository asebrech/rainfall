#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int language = 0;

void greetuser(char *username)
{
	char greeting[64];

	if (language == 1)
		strcpy(greeting, "Hyvää päivää ");
	else if (language == 2)
		strcpy(greeting, "Goedemiddag! ");
	else if (language == 0)
		strcpy(greeting, "Hello ");
	
	strcat(greeting, username);
	puts(greeting);
}

int main(int argc, char **argv)
{
	char buffer[72];
	char *lang_env;

	if (argc != 3)
		return (1);
	
	memset(buffer, 0, 72);
	strncpy(buffer, argv[1], 40);
	strncpy(buffer + 40, argv[2], 32);
	
	lang_env = getenv("LANG");
	if (lang_env != NULL)
	{
		if (memcmp(lang_env, "fi", 2) == 0)
			language = 1;
		else if (memcmp(lang_env, "nl", 2) == 0)
			language = 2;
	}
	
	greetuser(buffer);
	return (0);
}

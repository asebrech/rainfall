#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

char c[80];  // Global buffer for the flag

// Heap structure (8 bytes each)
struct data_struct {
	int id;        // 4 bytes
	char *data;    // 4 bytes pointer
};

void m(void)
{
	time_t current_time;
	
	current_time = time(NULL);
	printf("%s - %d\n", c, current_time);
}

int main(int argc, char **argv)
{
	struct data_struct *ptr1;
	struct data_struct *ptr2;
	FILE *file;
	
	// Allocate two structures and their data buffers
	ptr1 = malloc(sizeof(struct data_struct));
	ptr1->id = 1;
	ptr1->data = malloc(8);
	
	ptr2 = malloc(sizeof(struct data_struct));
	ptr2->id = 2;
	ptr2->data = malloc(8);
	
	// Vulnerable strcpy calls
	strcpy(ptr1->data, argv[1]);
	strcpy(ptr2->data, argv[2]);
	
	// Read flag (would work on actual challenge server)
	file = fopen("/home/user/level8/.pass", "r");
	fgets(c, 68, file);
	
	puts("~~");
	return 0;
}

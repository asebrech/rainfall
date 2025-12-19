#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

int main(int argc, char **argv)
{
	int input;
	char *args[2];
	gid_t gid;
	uid_t uid;

	input = atoi(argv[1]);
	if (input == 423) {
		args[0] = strdup("/bin/sh");
		args[1] = NULL;
		gid = getegid();
		uid = geteuid();
		setresgid(gid, gid, gid);
		setresuid(uid, uid, uid);
		execv("/bin/sh", args);
	}
	else {
		fwrite("No !\n", 1, 5, stderr);
	}
	return 0;
}

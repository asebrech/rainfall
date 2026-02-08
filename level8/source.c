#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *auth = NULL;
char *service = NULL;

int main(void)
{
    char buffer[128];
    
    while (1) {
        printf("%p, %p \n", auth, service);
        
        if (fgets(buffer, 128, stdin) == NULL) {
            return 0;
        }
        
        // Command: "auth <username>"
        if (strncmp(buffer, "auth ", 5) == 0) {
            auth = (char *)malloc(4);
            auth[0] = '\0';
            auth[1] = '\0';
            auth[2] = '\0';
            auth[3] = '\0';
            
            char *username = &buffer[5];
            size_t username_len = strlen(username);
            
            if (username_len < 31) {
                strcpy(auth, username);  // ⚠️ Overflow: 4-byte buffer, up to 30-byte copy
            }
        }
        
        // Command: "reset"
        if (strncmp(buffer, "reset", 5) == 0) {
            free(auth);  // ⚠️ Dangling pointer: auth not set to NULL
        }
        
        // Command: "service<string>"
        if (strncmp(buffer, "service", 7) == 0) {
            service = strdup(&buffer[7]);
        }
        
        // Command: "login"
        if (strncmp(buffer, "login", 5) == 0) {
            if (auth[32] == 0) {  // ⚠️ Out-of-bounds: checks 32 bytes beyond 4-byte allocation
                fwrite("Password:\n", 1, 10, stdout);
            }
            else {
                system("/bin/sh");
            }
        }
    }
    
    return 0;
}

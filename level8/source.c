#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *auth = NULL;
char *service = NULL;

int main(void)
{
    char cVar1;
    char *pcVar2;
    char *pcVar3;
    char *pcVar4;
    int iVar5;
    uint uVar6;
    byte *pbVar7;
    byte *pbVar8;
    bool bVar9;
    bool bVar12;
    byte bVar14;
    byte local_90[5];
    char local_8b[2];
    char acStack_89[125];
    
    bVar14 = 0;
    
    do {
        printf("%p, %p \n", auth, service);
        pcVar4 = fgets((char *)local_90, 0x80, stdin);
        bVar9 = false;
        bVar12 = pcVar4 == (char *)0x0;
        
        if (bVar12) {
            return 0;
        }
        
        // Command: "auth "
        iVar5 = 5;
        pbVar7 = local_90;
        pbVar8 = (byte *)"auth ";
        do {
            if (iVar5 == 0) break;
            iVar5 = iVar5 + -1;
            bVar9 = *pbVar7 < *pbVar8;
            bVar12 = *pbVar7 == *pbVar8;
            pbVar7 = pbVar7 + (uint)bVar14 * -2 + 1;
            pbVar8 = pbVar8 + (uint)bVar14 * -2 + 1;
        } while (bVar12);
        
        if ((!bVar9 && !bVar12) == bVar9) {
            auth = (char *)malloc(4);
            pcVar4 = auth + 1;
            pcVar2 = auth + 2;
            pcVar3 = auth + 3;
            auth[0] = '\0';
            *pcVar4 = '\0';
            *pcVar2 = '\0';
            *pcVar3 = '\0';
            
            uVar6 = 0xffffffff;
            pcVar4 = local_8b;
            do {
                if (uVar6 == 0) break;
                uVar6 = uVar6 - 1;
                cVar1 = *pcVar4;
                pcVar4 = pcVar4 + (uint)bVar14 * -2 + 1;
            } while (cVar1 != '\0');
            
            uVar6 = ~uVar6 - 1;
            if (uVar6 < 0x1f) {
                strcpy(auth, local_8b);
            }
        }
        
        // Command: "reset"
        iVar5 = 5;
        pbVar7 = local_90;
        pbVar8 = (byte *)"reset";
        do {
            if (iVar5 == 0) break;
            iVar5 = iVar5 + -1;
            bVar9 = *pbVar7 < *pbVar8;
            bVar12 = *pbVar7 == *pbVar8;
            pbVar7 = pbVar7 + (uint)bVar14 * -2 + 1;
            pbVar8 = pbVar8 + (uint)bVar14 * -2 + 1;
        } while (bVar12);
        
        if ((!bVar9 && !bVar12) == bVar9) {
            free(auth);
        }
        
        // Command: "service"
        iVar5 = 6;
        pbVar7 = local_90;
        pbVar8 = (byte *)"service";
        do {
            if (iVar5 == 0) break;
            iVar5 = iVar5 + -1;
            bVar9 = *pbVar7 < *pbVar8;
            bVar12 = *pbVar7 == *pbVar8;
            pbVar7 = pbVar7 + (uint)bVar14 * -2 + 1;
            pbVar8 = pbVar8 + (uint)bVar14 * -2 + 1;
        } while (bVar12);
        
        if ((!bVar9 && !bVar12) == bVar9) {
            service = strdup(acStack_89);
        }
        
        // Command: "login"
        iVar5 = 5;
        pbVar7 = local_90;
        pbVar8 = (byte *)"login";
        do {
            if (iVar5 == 0) break;
            iVar5 = iVar5 + -1;
            bVar9 = *pbVar7 < *pbVar8;
            bVar12 = *pbVar7 == *pbVar8;
            pbVar7 = pbVar7 + (uint)bVar14 * -2 + 1;
            pbVar8 = pbVar8 + (uint)bVar14 * -2 + 1;
        } while (bVar12);
        
        if ((!bVar9 && !bVar12) == bVar9) {
            if (*(int *)(auth + 0x20) == 0) {
                fwrite("Password:\n", 1, 10, stdout);
            }
            else {
                system("/bin/sh");
            }
        }
        
    } while (true);
}

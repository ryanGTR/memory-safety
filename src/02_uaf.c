/* 02_uaf.c — use-after-free: free 之後還拿舊指標去讀
 * build: gcc -g -fsanitize=address 02_uaf.c -o 02_uaf
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct user {
	char name[16];
	int  is_admin;		/* 0 = 一般, 1 = 管理員 */
};

int main(void)
{
	struct user *u = malloc(sizeof(*u));	/* 1) 配一塊 */
	strcpy(u->name, "ryan");
	u->is_admin = 0;

	free(u);				/* 2) 還回去，但 u 沒變 NULL（dangling） */

	/* 3) 還拿舊指標去讀 —— 這就是 use-after-free */
	printf("name=%s is_admin=%d\n", u->name, u->is_admin);

	return 0;
}

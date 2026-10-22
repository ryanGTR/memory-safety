/* uaf_detect_demo.c — 示範「用 strace 從 shell 看出 hijack」
 * 跟 uaf_hijack_demo 一樣，但 attacker 函式改成 exec /bin/echo（無害），
 * 目的是讓劫持後的「行為」在 syscall 層現形。純教學。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>

struct victim { char name[8]; void (*action)(void); };

static void normal_action(void) { printf("[正常] normal_action\n"); }
static void attacker_action(void)
{
	/* 劫持後執行：去 exec 一個外部程式。strace 會抓到這個 execve。 */
	execl("/bin/echo", "echo", "[HIJACK] 我被劫持，去執行 /bin/echo 了", (char *)NULL);
}

int main(void)
{
	struct victim *v = malloc(sizeof(*v));
	v->action = normal_action;
	v->action();

	free(v);
	char *a = malloc(sizeof(struct victim));
	void (*t)(void) = attacker_action;
	memcpy(a + offsetof(struct victim, action), &t, sizeof(t));

	v->action();   /* 被劫持 → exec /bin/echo */
	return 0;
}

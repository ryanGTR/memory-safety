/* uaf_hijack_demo.c — 用玩具程式演示 UAF 如何劫持控制流
 * 純教學：payload 只是 printf，不是真的 system()。無目標、無 shellcode。
 * build (silent UAF, 看劫持成功): gcc -g uaf_hijack_demo.c -o uaf_hijack_demo
 * build (ASan 會攔住):            gcc -g -fsanitize=address ... 
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

/* 受害物件：裡面有「決定接下來呼叫誰」的函式指標 ← 有料欄位 */
struct victim {
	char name[8];
	void (*action)(void);
};

static void normal_action(void)
{
	printf("   [正常] normal_action() 執行\n");
}

static void attacker_action(void)
{
	printf("   [!!!] 控制流被劫持 → attacker_action() 執行（這裡本可是 system(\"/bin/sh\")）\n");
}

int main(void)
{
	/* ① 配置受害物件，函式指標指向正常函式 */
	struct victim *v = malloc(sizeof(*v));
	strcpy(v->name, "ryan");
	v->action = normal_action;

	printf("1) free 前，v->action() 指向正常函式：\n");
	v->action();

	/* 釋放，但 v 沒被設 NULL → dangling pointer */
	free(v);
	printf("2) free(v) 完成。v 仍握著舊地址（dangling）。\n");

	/* ② 攻擊者馬上配一塊「同樣大小、內容他控制」的記憶體。
	 *    glibc tcache 是 LIFO，會把剛 free 的那塊原封不動發回來。 */
	char *attacker = malloc(sizeof(struct victim));
	printf("3) 攻擊者 malloc 同樣大小 → 拿回同一塊？ %s\n",
	       (void *)attacker == (void *)v ? "是（洞被重用了）" : "否");

	/* ③ 在「函式指標那個 offset」寫入攻擊者要跳的地址 */
	void (*target)(void) = attacker_action;
	memcpy(attacker + offsetof(struct victim, action), &target, sizeof(target));
	printf("4) 攻擊者在 offset %zu 寫入 attacker_action 的地址。\n",
	       offsetof(struct victim, action));

	/* ④ 程式還用舊的 dangling v，以為 action 還是 normal_action */
	printf("5) 程式再呼叫 v->action()（它以為還是正常物件）：\n");
	v->action();   /* ← 實際跳到 attacker_action = 控制流被劫持 */

	return 0;
}

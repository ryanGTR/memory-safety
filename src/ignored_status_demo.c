/* ignored_status_demo.c — 回傳狀態被丟掉：失敗被當成功，繼續寫 → heap 越界寫
 * 仿 brotli CVE-2026-111497 的「形狀」（不是它的真實路徑）：
 *   一個 bool 回傳值代表「格式壞了」，但「快速模式」巨集直接把它丟掉。
 * build: gcc -g -fsanitize=address ignored_status_demo.c -o ignored_status_demo
 */
#include <stdio.h>
#include <stdlib.h>

#define OUT_CAP 16

struct dec {
	unsigned char *out;	/* 輸出 buffer，OUT_CAP byte */
	unsigned int pos;
	unsigned int left;	/* 目前這段還要寫幾 byte */
};

/* 讀下一段長度。
 * 契約：回 1 = 成功；回 0 = 格式壞（長度 0 或超出剩餘空間），呼叫端必須停。
 * [[nodiscard]]：呼叫端丟掉回傳值，編譯器就警告（第 1 層防線）
 */
[[nodiscard]] static int read_len(struct dec *d, unsigned int n)
{
	if (n == 0 || n > OUT_CAP - d->pos)
		return 0;		/* 格式壞：直接走，d->left 沒被設定 */
	d->left = n;
	return 1;
}

/* 「快速模式」：作者假設輸入一定合法，回傳值直接丟掉
 * （brotli 的 BROTLI_SAFE 巨集 else 分支就是 `METHOD;`，同一個形狀）
 */
#define FAST(call)	call

int main(void)
{
	/* 壞輸入：第 2 段長度 0 是非法的 */
	const unsigned int lens[] = { 10, 0 };
	struct dec d = { .out = malloc(OUT_CAP) };

	if (!d.out)
		return 1;

	for (int b = 0; b < 2; b++) {
		FAST(read_len(&d, lens[b]));	/* 回 0 了，卻沒人看 */
		do {
			/* 第 2 段：left 還是 0 → --left 變 4294967295 → 一路寫出界 */
			d.out[d.pos++] = 'A';
		} while (--d.left);
	}

	printf("wrote %u bytes\n", d.pos);
	free(d.out);
	d.out = NULL;
	return 0;
}

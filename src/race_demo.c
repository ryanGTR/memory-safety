/* race_demo.c — 資料競爭（data race）最小示範，CVE-2026-98432 的本質（純教學）
 *
 * CVE-2026-98432 的根因是：一塊共享狀態（ireq_opt）被多顆 CPU 同時存取，
 * 其中一邊沒有適當同步就動它 → kernel 用「過一個 RCU grace period 才 free」來修。
 * 這裡抽掉 kernel 和 UAF，只留最乾淨的核心：兩條 thread 無鎖碰同一塊記憶體。
 *
 * 教學點（配 make verify-matrix 看）：
 *   - 靜態層（-fanalyzer / cppcheck）：看不到，它們不模擬跨 thread 的交錯
 *   - ASan：也看不到，因為這裡沒有記憶體錯誤、只是「結果不確定」的競爭
 *   - TSan：穩定報 data race —— 不用等壞事發生，先報「你沒上鎖就共享可變狀態」
 *
 * 延伸（不在這支裡跑）：真實 CVE 的 race 進一步導致 use-after-free；
 * 那種情況 ASan 只在「交錯剛好踩成 UAF」那一次才碰得到 → 非決定性，不可靠。
 * 所以這類 bug 的穩定裁判是 race 偵測器（userspace=TSan / kernel=KCSAN），不是 ASan。
 */
#include <pthread.h>
#include <stdio.h>

#define ITERS 200000

static long shared;   /* 跨 thread 共享的可變狀態，故意不上鎖 */

static void *worker(void *arg)
{
	(void)arg;
	for (int i = 0; i < ITERS; i++)
		shared++;     /* 讀-改-寫，和另一條 thread 競爭 */
	return NULL;
}

int main(void)
{
	pthread_t a, b;

	pthread_create(&a, NULL, worker, NULL);
	pthread_create(&b, NULL, worker, NULL);
	pthread_join(a, NULL);
	pthread_join(b, NULL);

	/* 期望 400000，但無鎖競爭下幾乎不會是這個數 —— 結果本身就不可信 */
	printf("shared = %ld（期望 %d）\n", shared, 2 * ITERS);
	return 0;
}

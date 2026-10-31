/* race_demo.c — 資料競爭（data race）最小示範（純教學）
 *
 * 2026-10-31 更正：本檔原本寫「這是 CVE-2026-98432 的本質」，不對。
 * 這支示範的是 lost update（兩條 thread 同時 ++，更新被蓋掉）。
 * CVE-2026-98432 是「物件生命週期」問題：讀端在 rcu_read_lock() 下讀 ireq_opt，
 * free 端卻用 plain kfree() 當場釋放 → UAF；兩邊都有同步，錯在 free 的時間點。
 * 那個案例見 wiki/use-after-free.md「跨 thread 的生命週期 UAF」。
 * 這裡只留最乾淨的競爭核心：兩條 thread 無鎖碰同一塊記憶體。
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

---
title: Use-After-Free（UAF，釋放後使用）
type: concept
created: 2026-10-22
updated: 2026-10-31
tags: [memory-safety, c, uaf, dangling-pointer, asan, cwe-416, rcu]
sources:
  - src/02_uaf.c
  - "AddressSanitizer 實跑輸出（本機 gcc 16.2, 2026-10-22）"
  - "CWE-416: Use After Free"
  - "CVE-2026-98432 修補 commit e3f33b0a1d89（Eric Dumazet, 2026-10-01）"
---

# Use-After-Free（UAF，釋放後使用）

> 本頁用三段回答：**怎麼寫出事 → 為什麼出事 → 出事長什麼樣子**。
> 對應 CWE-416。這是 2026-10 PHP `php2shell`（[[php-cve-2026-109618-109619]]）其中一個洞的類別。

## 1. 怎麼寫出事

一段**看起來完全正常**的 C：

```c
struct user *u = malloc(sizeof(*u));   // 1) 配一塊
strcpy(u->name, "ryan");
u->is_admin = 0;

free(u);                               // 2) 還回去——但 u 這個指標「值」沒變

printf("%s %d\n", u->name, u->is_admin); // 3) 還拿舊 u 去讀 → UAF
```

關鍵誤解：`free(u)` **不會**把 `u` 設成 `NULL`。它只是告訴 allocator「這塊地我不要了」。
`u` 裡仍然存著那個位址，變成 **dangling pointer（懸空指標）**。

完整可編譯範例見 `src/02_uaf.c:19`（free）與 `src/02_uaf.c:22`（釋放後讀取）。

## 2. 為什麼出事

- `free` 之後那塊記憶體可能：(a) 被 allocator 的 metadata 覆寫、(b) 被下一次 `malloc`
  配給別的物件。無論哪種，你用舊指標讀到的都**不再是你以為的東西**。
- 這是 **undefined behavior（未定義行為）**：編譯器與執行期不保證任何結果——
  可能剛好印出舊值（最危險，因為看起來「沒事」）、可能印出垃圾、可能直接 crash。
- 危險升級點：若被釋放的結構裡有「決定後續行為」的欄位（如本例的 `is_admin`，
  或真實世界的函式指標 / vtable），攻擊者只要能讓 `malloc` 把那塊地重配成他能控制的
  內容，就能改寫那個欄位 → 這就是 UAF 通往 RCE 的橋（列入 [[待進行]]，本系列先不碰）。

### Java 類比

```
Java 沒有 UAF。
  - 沒有手動 free()，物件由 GC 回收。
  - 只要還有任何參照指著物件，GC 就不會回收它 → 不可能「釋放後還拿得到」。
C 把「誰還持有這塊地」的追蹤責任整個丟給你，GC 幫你做的事變成你的義務。
```

最接近的 Java 心像：你把物件 `pool.release(obj)` 還回物件池，卻留著 `obj` 參照繼續用，
而池子已把那塊記憶體發給別人——只是 Java 層級通常不會讓你真的踩到別人的記憶體，C 會。

## 3. 出事長什麼樣子

```
$ gcc -g -fsanitize=address src/02_uaf.c -o 02_uaf
$ ./02_uaf
==ERROR: AddressSanitizer: heap-use-after-free on address 0x... 
READ of size 4 at 0x... thread T0
    #0 ... in main .../02_uaf.c:22        ← 在哪裡「用」了已釋放的記憶體

0x... is located 16 bytes inside of 20-byte region [...]   ← 讀到結構內 offset 16（is_admin）
freed by thread T0 here:
    #1 ... in main .../02_uaf.c:19         ← 在哪裡 free 的
previously allocated by thread T0 here:
    #1 ... in main .../02_uaf.c:15         ← 在哪裡 malloc 的

SUMMARY: AddressSanitizer: heap-use-after-free .../02_uaf.c:22 in main
```

**怎麼讀這份報告**（這是本課真正要帶走的技能）：

| 區塊 | 告訴你 |
|---|---|
| `heap-use-after-free` + 第一個堆疊 | 出事的**動作與位置**（哪行在用釋放後的記憶體） |
| `READ of size 4` | 讀了 4 bytes → 剛好是 `int is_admin` |
| `located 16 bytes inside of 20-byte region` | 踩在那塊 20-byte 結構的 offset 16（name[16] 之後就是 is_admin） |
| `freed by thread T0 here` | **誰 free 的**（第 19 行） |
| `previously allocated` | **誰 malloc 的**（第 15 行） |

ASan 把「配置 → 釋放 → 誤用」三個現場的 backtrace 一次給你，debug UAF 幾乎是看圖說故事。

## 修法

```c
free(u);
u = NULL;        // free 後立刻 NULL：之後誤用會變成明確的 NULL 解參考（易抓），而非 UAF
```

⚠️ **這招只在單執行緒有效。** 設成 NULL 的只有「你自己這份」指標；別的 thread 早就把位址抄進
自己的區域變數，你碰不到。跨 thread 的情況見下一節。

更根本的做法屬於設計層（所有權單一化、ownership 清楚），這也是 Rust 的 borrow checker
在編譯期就擋掉 UAF 的核心思路——列入 [[待進行]] 的 Rust 對照。

## 跨 thread 的生命週期 UAF（真實案例：CVE-2026-98432）

上面的範例都是「同一個 thread 先 free 再讀」。kernel 裡更常見的是**兩顆 CPU 交錯**：

```c
/* CPU0：建立子 socket */
newinet->inet_opt = ireq->ireq_opt;	/* 直接共用指標，沒複製 */

				/* CPU1：收到重送的 SYN */
				rcu_read_lock();
				opt = ireq->ireq_opt;	/* 拿到同一塊 */

/* CPU0：子 socket 被釋放 */
kfree(inet_opt);			/* 當場還回去 */

				len = opt->optlen;	/* UAF */
				rcu_read_unlock();
```

兩個錯：

1. **所有權沒切乾淨**：一塊記憶體兩個擁有者，沒複製、也沒 refcount（IPv6 版本有複製，所以沒中第一個洞）。
2. **讀端守 RCU 規矩，free 端沒守**：讀的一方在 `rcu_read_lock()` 底下，但 destructor 用 plain `kfree()`。

這不是「沒同步」——兩邊都有同步機制，是 **free 的時間點**錯了。所以它跟計數器 `++` 那種
lost update 是不同類別（見 `src/race_demo.c` 檔頭）。

修法（2 行）：`net/ipv4/af_inet.c` 的 `inet_sock_destruct()` 與 `net/ipv4/tcp_ipv4.c` 的
`tcp_v4_reqsk_destructor()` 把 `kfree()` 換成 `kfree_rcu()`。本機 v7.0 樹對應
`net/ipv4/af_inet.c:165`、`net/ipv4/tcp_ipv4.c:1232` (v7.0)。為什麼這樣就夠——見 [[rcu]]。

偵測：ASan 只有在交錯剛好踩中那一次才抓得到；kernel 端靠 KASAN＋壓力測試、或 KCSAN 抓競爭。

## See Also

- [[dangling-pointer]] — UAF 的前置概念（指標為何會懸空）
- [[double-free]] — free 兩次，allocator metadata 被玩壞
- [[error-path-corruption]] — OOM/錯誤路徑的記憶體毀損（PHP 另一個 CVE 的類別）
- [[rcu]] — kernel 的「延後 free」機制（`~/Documents/linux_kernel/wiki/concepts/rcu.md`）
- [[index]] — 本系列目錄

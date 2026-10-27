---
title: 回傳狀態被丟掉（Unchecked Return Value → 越界寫）
type: concept
created: 2026-10-27
updated: 2026-10-27
tags: [memory-safety, c, cwe-252, cwe-787, brotli, nodiscard, codeql, variant-analysis]
sources:
  - src/ignored_status_demo.c
  - codeql/ignored-status.ql
  - "google/brotli v1.2.0 vs v1.2.1，修補 commit 0ed4268（c/dec/decode.c），2026-10-21"
  - "CVE-2026-111497（Node2Shell）公開報導：patchtheplanet.org/brotli、aikido.dev"
  - "本機實測（2026-10-27）：semgrep / cppcheck / gcc -fanalyzer / libFuzzer+ASan / CodeQL"
---

# 回傳狀態被丟掉（Unchecked Return Value → 越界寫）

> 本頁用三段回答：**怎麼寫出事 → 為什麼出事 → 出事長什麼樣子**，再加一段「工具抓不抓得到」（本機實測）。
> 對應 CWE-252（沒檢查回傳值）→ CWE-787（越界寫）。真實案例：brotli CVE-2026-111497。

## 目錄

1. 怎麼寫出事
2. 為什麼出事
3. 出事長什麼樣子
4. 真實案例：brotli CVE-2026-111497
5. 工具抓不抓得到（本機實測）
6. 寫法教訓
7. Java 對照

## 1. 怎麼寫出事

一個函式用回傳值表示「格式壞了，請停」，但呼叫端把回傳值丟掉（`src/ignored_status_demo.c`）：

```c
/* 契約：回 1 = 成功；回 0 = 格式壞，呼叫端必須停 */
static int read_len(struct dec *d, unsigned int n)
{
	if (n == 0 || n > OUT_CAP - d->pos)
		return 0;		/* 格式壞：直接走，d->left 沒被設定 */
	d->left = n;
	return 1;
}

#define FAST(call)	call		/* 「快速模式」：回傳值直接丟掉 */

FAST(read_len(&d, lens[b]));		/* 回 0 了，卻沒人看 */
do {
	d.out[d.pos++] = 'A';		/* left 是 0 → --left 變 4294967295 */
} while (--d.left);
```

## 2. 為什麼出事

- **契約只寫在腦中**：「回 0 要停」沒有任何東西強制呼叫端遵守。
- **失敗路徑沒把狀態設好**：`read_len` 失敗時 `d->left` 保持舊值 0。
- **unsigned 下溢**：`--d->left` 從 0 變成 `UINT_MAX`，迴圈變成「幾乎無限」。
- **C 不做邊界檢查**：寫超過 `out` 的 16 byte 不會被語言擋下 → heap 越界寫。

## 3. 出事長什麼樣子

`make test` 實跑（本機 gcc 16.2，2026-10-27）：

```
==71369==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7bd992be0020
WRITE of size 1 at 0x7bd992be0020 thread T0
    #0 0x55de4a8b1559 in main src/ignored_status_demo.c:47
0x7bd992be0020 is located 0 bytes after 16-byte region [0x7bd992be0010,0x7bd992be0020)
```

「0 bytes after 16-byte region」＝剛好寫到第 17 個 byte 被攔。

## 4. 真實案例：brotli CVE-2026-111497

| 項目 | 內容 |
|---|---|
| 受影響 | google/brotli 1.0.3 – 1.2.0 decoder |
| 修補 | 1.0.10 / 1.1.1 / 1.2.1（2026-10-21），commit `0ed4268` |
| 下游 | Node.js（編進 runtime）、.NET、Python、Envoy/Istio、PHP、Ruby… |
| 類別 | 越界寫 → RCE |

**修補前的形狀**（`c/dec/decode.c (v1.2.0)`）：

```c
/* DecodeBlockTypeAndLength：兩種失敗都回 BROTLI_FALSE */
if (max_block_type <= 1) {
	return BROTLI_FALSE;		/* 意思：格式壞了 */
}
...
if (!SafeReadSymbol(type_tree, br, &block_type)) return BROTLI_FALSE; /* 意思：輸入不夠 */

/* 呼叫端：回傳值被丟掉 */
static void BROTLI_NOINLINE DecodeLiteralBlockSwitch(BrotliDecoderState* s) {
	DecodeLiteralBlockSwitchInternal(0, s);
}

/* BROTLI_SAFE 巨集：unsafe 分支直接 `METHOD;` */
#define BROTLI_SAFE(METHOD)  { if (safe) { if (!Safe##METHOD) {...goto saveStateAndReturn;} } else { METHOD; } }
```

**根因**：一個 `BROTLI_BOOL` 塞了兩種意思。契約是「FALSE＝輸入不夠」，unsafe 模式保證輸入夠，所以作者放心丟掉回傳值；但「格式壞」也回 FALSE → 壞資料被當成「沒事」繼續解碼。

**修補**：bool 換成 3 態錯誤碼（`SUCCESS / NEEDS_MORE_INPUT / ERROR_FORMAT_BLOCK_SWITCH`），新巨集 `BROTLI_SAFE_WITH_STATUS` 不管 safe 與否都檢查；另加 `BROTLI_DCHECK(meta_block_remaining_len <= BROTLI_BLOCK_SIZE_CAP)`。

> ⚠️ 未證實：「壞狀態具體是哪個欄位、怎麼一路變成越界寫」本頁沒有追到 brotli 原始碼證實。§1 的 demo 是**仿形狀**，不是 brotli 的真實路徑。

## 5. 工具抓不抓得到（本機實測，v1.2.0 的 `c/dec/decode.c`）

| 工具 | 結果 | 為什麼 |
|---|---|---|
| semgrep（自訂 2 條＋社群 16 條） | ❌ | 沒有這類規則；自寫規則也看不穿 `static BROTLI_INLINE BROTLI_BOOL` 巨集 |
| cppcheck | ❌ | 沒標 nodiscard 就不知道「該檢查」 |
| gcc `-Wall -Wextra` | ❌ 0 警告 | 同上 |
| gcc `-fanalyzer` | ❌ | 只報一個不相干的 shift 警告 |
| libFuzzer＋ASan/UBSan（8 核 10 分鐘，約 100 萬次） | ❌ 0 crash | 要剛好產生「只有 1 種 block type 卻觸發切換」的輸入；brotli 本來就在 OSS-Fuzz 長期跑也沒抓到 |
| CodeQL `security-and-quality` 整包 | ❌ | 只有 3 個風格警告（long switch case、goto） |
| CodeQL `cpp/return-value-ignored` | ❌ | 門檻是「≥90% 呼叫端有用回傳值」；這裡每個函式 2 個呼叫點、1 個丟掉＝50% |
| **`warn_unused_result` 屬性**（sed 加到所有狀態函式） | ✅ 5 處 | v1.2.0：被修的 3 處＋2 處故意忽略；v1.2.1 只剩那 2 處 |
| **自訂 CodeQL `codeql/ignored-status.ql`** | ✅ 5 處 | 同上，且不用改原始碼 |

結論：**通用規則包抓不到契約型 bug**；要嘛讓編譯器知道契約（nodiscard），要嘛自己寫規則。

### 這條規則是「一類一條」

查詢裡沒有任何 brotli 的名字，條件只有「static、回傳整數、有 `return 0`、結果被丟掉」，所以同一條在 brotli 和 `src/ignored_status_demo.c` 都命中。這就是 **variant analysis（變種分析）**：看到一個 CVE，寫抓「這一類形狀」的查詢，拿去掃找兄弟。

邊界（誠實標註）：

- 只看 `static` 函式，跨檔 API 不管。
- 只認「`return 0`＝失敗」慣例；用 `-1` 或 enum 表示失敗的會漏。

## 6. 寫法教訓

1. **狀態回傳一律 `[[nodiscard]]`**（C23；舊版 gcc 用 `__attribute__((warn_unused_result))`）。注意：C23 的 `(void)` 強轉可以消掉警告，等於留了一個明確的「我故意的」記號。
2. **一個回傳值只表達一種意思**：「輸入不夠」和「格式壞」要分開 → 用 enum，不用 bool。
3. **巨集裡別寫 `METHOD;`** 把結果丟掉；快路徑也要檢查錯誤，只能省「效能檢查」，不能省「正確性檢查」。
4. **失敗路徑也要把狀態設成安全值**（例如把計數器歸零並標記錯誤），別留半更新的狀態。
5. **在 fuzz build 打開 assert**：讓「壞狀態」當場 crash，而不是默默寫壞。（推論，未實測）

## 7. Java 對照

| C | Java |
|---|---|
| 回傳 `bool` / `int` 表示失敗，呼叫端可以不理 | `boolean tryXxx()`，呼叫端一樣可以不理 |
| `[[nodiscard]]` | ErrorProne 的 `@CheckReturnValue` |
| 3 態 enum 錯誤碼 | 丟具體的 checked exception：不處理就編不過 |
| 不理之後繼續寫 → 越界寫（記憶體毀損） | 不理之後繼續跑 → 頂多邏輯錯；越界時 JVM 丟 `ArrayIndexOutOfBoundsException` |

所以同樣「忽略錯誤」，在 Java 是 bug，在 C 是 RCE。

## See Also

- [[use-after-free]] — 另一種「契約沒守住」（free 之後還用）
- [[php-hashtable-rce-2004-vs-2026]] — 同期另一個 C runtime 的真實 RCE
- [[error-path-corruption]] — 錯誤路徑沒把狀態收好（本頁 §2 第 2 點）
- [[index]] — 本系列目錄

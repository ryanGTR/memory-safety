---
title: Bug 類型課綱對照（攻擊視角 × 本專案進度）
type: index
created: 2026-10-31
updated: 2026-10-31
tags: [memory-safety, c, syllabus, bug-classes, exploit-dev, cwe]
sources:
  - "SnailSploit/claude-red, Skills/exploit-dev/offensive-exploit-development/SKILL.md「Bug Types」節（2026-10-12 commit a8de813，MIT）"
  - "本專案 src/ 與 wiki/ 現況（2026-10-31）"
---

# Bug 類型課綱對照（攻擊視角 × 本專案進度）

> 本頁把一份攻擊方教材（exploit-dev）列的 8 種 bug 類型，對照本專案「怎麼寫出事→為什麼→長什麼樣」已經練到哪。
> 目的是**排課綱的優先序**，不是武器化。攻擊視角在這裡只用來回答一件事：同一個 bug，為什麼它不只是 crash，而是能被拿去控制程式。
> ✅＝已有最小 .c ＋ wiki；⬜＝尚未。

## 對照表

| # | Bug 類型 | 本專案 | 連結／備註 |
|---|---------|:---:|-----------|
| 1 | Use-After-Free | ✅ | [[use-after-free]]、[[control-flow-hijack]]（free 後空位被塞假 vtable → 任意讀寫；這正是「為什麼危險」的下一步） |
| 2 | 併發／Race | ✅ | `src/race_demo.c`＋TSan。攻擊書補一種還沒碰的：**double-fetch**（kernel 讀使用者記憶體兩次）＝ [[use-after-free]] 提到的 CVE-2026-98432 家族 |
| 3 | 回傳值沒檢查（契約型） | ✅ | [[ignored-return-status]]（brotli）。不在傳統「記憶體錯誤」清單內，但攻擊書也當 bug 源頭之一——契約型直覺成立 |
| 4 | 整數溢位／截斷 | ⬜ | **最值得補的下一個**。常見成因＝64 位 `size_t` 塞進 32 位 → 算出負數或超大的 malloc 大小 → 接著 heap overflow。接得上 lab0-c 算長度／算 buffer |
| 5 | Stack Overflow | ⬜ | 經典 `strcpy` 沒邊界檢查蓋掉返回位址。本專案 `.semgrep.yml` 的 `unbounded-strcpy` 規則已經在擋這個 bug 的入口 |
| 6 | Heap Overflow | ⬜ | 寫超過 malloc 範圍、壞掉配置器 metadata。要先懂 glibc tcache，較進階 |
| 7 | 沒檢查的指標 | ⬜ | 10/22 靜態層抓到的「malloc 沒檢查就用」（CWE-690）是這類的一種 |
| 8 | Format String | ⬜ | C 專屬、很經典（`%n` 寫入原語），可排進課綱 |
| — | Type Confusion | ⬜（跳過） | 主要在 C++／JS 引擎（vtable／JIT 型別混淆），離目前 C 線遠，先不排 |

## 建議優先序

課綱往下時，純 C、且接得上現有 semgrep／ASan 管線的三個先做：

1. **整數溢位／截斷**（CWE-190/197）— 一支 .c 示範「size 算錯 → 配置過小 → 越界」，`make check` 看 `-fanalyzer` 抓不抓得到
2. **Stack Overflow**（CWE-121）— 對照 `unbounded-strcpy` 規則，驗證「存檔即攔」真的攔得住
3. **Format String**（CWE-134）— 加 `-Wformat-security`，看編譯器與各工具誰抓得到

其餘（heap overflow 進階、type confusion 離線）留著。每補一課照既有慣例：最小 `.c` ＋ wiki 一頁 ＋ 若有新寫法就加一條 `.semgrep.yml` 規則 ＋ 跑一遍 `make check`／`make test`。

## See Also

- [[use-after-free]] — 已完成的第一支脊椎課
- [[control-flow-hijack]] — UAF 的「怎麼被拿去打」延伸
- [[ignored-return-status]] — 契約型 bug（對照表第 3 項）

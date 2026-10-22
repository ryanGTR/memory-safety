---
title: 從 UAF 到控制流劫持（機制，不含武器化）
type: concept
created: 2026-10-22
updated: 2026-10-22
tags: [memory-safety, uaf, exploitation-concept, control-flow, cwe-416]
sources:
  - src/uaf_hijack_demo.c（本機玩具示範，payload=printf）
  - "php2shell 公開報導 CVE-2026-109618/109619；[[php-hashtable-rce-2004-vs-2026]]"
---

# 從 UAF 到控制流劫持（機制，不含武器化）

> **範圍：理解「為什麼一個 UAF 能變成 RCE」。純機制＋自足玩具示範。**
> **不含**：針對真實目標的 exploit、offset、heap grooming 細節、shellcode、可跑 PoC。那些列 [[待進行]]。
> 這頁是 [[use-after-free]] §2「UAF → 函式指標/vtable → 控制流」那座橋的完整版。

## 核心問題

[[use-after-free]] 教的是「free 後還用」。但你做的 int UAF **打不了**——讀到一個整數沒意義。
**可被利用的關鍵不是 UAF 本身，是 freed 物件裡有沒有「控制接下來行為」的欄位**：
函式指標、C++ vtable、長度、型別標籤、權限旗標。

## 通用 5 步

1. **找「有料」的 UAF**——freed 物件裡有函式指標/vtable 這類「決定下一步跳去哪」的欄位。
2. **搶填那個洞（heap grooming）**——物件一 free，攻擊者馬上送一個「同大小、內容他能控制」的配置；
   allocator（如 glibc tcache，LIFO）把剛空出的那塊原封不動發回來 → 他的 bytes 落在舊物件位置。
3. **型別混淆（type confusion）**——程式還握 dangling 指標，以為是舊物件、照舊格式讀；
   但那格現在是攻擊者寫的值。
4. **劫持控制流**——程式執行 `obj->func()` 或走 vtable → CPU 跳到攻擊者填的地址。
5. **跳去哪＝RCE**——指向 shellcode，或（有 NX 時）串既有程式碼片段（ROP）。

## 玩具示範（`src/uaf_hijack_demo.c`）

受害物件 `struct victim { char name[8]; void (*action)(void); }`——重點是那個函式指標。

| 步 | 程式做的 | 對應上面 |
|---|---|---|
| free 前 | `v->action()` → normal_action | — |
| `free(v)` | v 沒清 → dangling | — |
| `attacker = malloc(同大小)` | 拿回**同一塊**（洞被重用） | ② |
| `memcpy(attacker+offsetof(action), &target)` | 在 offset 8 寫 attacker_action 地址 | ③ |
| `v->action()` | 跳到 attacker_action | ④ |

**兩次執行的對照（本課精華）：**

- **無 ASan（＝ production）**：攻擊者 malloc 拿回同一塊 → 改函式指標 → `v->action()`
  **安靜地**跳到 attacker_action。**全程不 crash、不警告。**
- **ASan（＝ 測試）**：在 `v->action()` 當場攔住 `heap-use-after-free, READ of size 8`
  （size 8＝讀一個指標，對照 [[use-after-free]] 的 size 4＝int）。ASan 把 freed 記憶體隔離不給重用，劫持來不及發生。

> payload 只是 `printf`（標註「這裡本可是 system()」）。無目標、無 shellcode。

## 為什麼現代不是複製貼上（重要）

- **NX/DEP**：資料區不能當程式碼跑 → 要改用 ROP（串既有程式碼片段）。
- **ASLR**：地址隨機 → 要**先有一個 info leak** 洩漏地址，才知道要跳去哪。
- **heap 加固**（safe-linking、指標 mangling、quarantine）、**CFI**（檢查呼叫目標合不合法）。

所以真實 exploit 通常要 **UAF ＋ info leak ＋ 堆疊控制 ＋ 一條 chain**。
**一個 UAF ≠ 自動 RCE**——這也是它們難、值錢的原因。

## 對回 PHP CVE

| 5 步 | php2shell / 2004 |
|---|---|
| 有料欄位 | Zend 的函式指標結構（2004 destructor；2026 zend_fcall_info） |
| 填洞 | 控制 freed HashTable bucket 的內容 |
| 劫持 | `zend_call_function` → `system()` |

詳見 [[php-hashtable-rce-2004-vs-2026]]。

## 防守面（這才是你的終點）

- `free(p); p = NULL;`——把「安靜可利用的 UAF」換成「吵鬧不可利用的 NULL 崩」，整條利用鏈斷在第 5 步。
- 編譯期：ASan（測試）、CFI、`-fstack-protector`。
- 設計：所有權單一化（Rust 的 borrow checker 在編譯期擋掉，列 [[待進行]] 的 Rust 對照）。

## 偵測：怎麼從 shell 看出 hijack（`src/uaf_detect_demo.c`）

**先講殘酷事實：成功的 _silent_ hijack（只改資料、不「做事」）從 shell 幾乎看不到**——
exit code = 0、不 crash、不報錯。這正是記憶體漏洞可怕的地方。能看出來的分三種：

| 方法 | 看什麼 | 什麼時候有效 |
|---|---|---|
| **build 插樁** | ASan（印 heap-use-after-free、exit≠0）、CFI（`-fsanitize=cfi` 跳錯當場擋） | 測試階段，最可靠 |
| **看 side-effect** | strace 的 syscall、`ps`、`ss` | 攻擊者一旦要「做事」（exec／連網／讀檔）就露餡 |
| **它剛好失敗** | 跳到爛地址 → SIGSEGV → `echo $?` = 139 | 攻擊者不精準時 |

**strace 實證**（demo 的 attacker 改成 `execl("/bin/echo", …)`）：

```
$ strace -f -e trace=execve ./uaf_detect_demo
execve("./uaf_detect_demo", …) = 0            ← 正常啟動
execve("/bin/echo", ["echo","[HIJACK]…"]) = 0  ← 💥 鐵證
```

第二個 `execve` 就是證據：**main() 從頭到尾沒寫過任何 exec，它出現只因為被劫持的函式跑了。**
程式再怎麼「以為自己正常」，只要對 kernel 發了不該發的 syscall，strace 就看得到。

> 這正是真實世界防守的原理：**EDR / seccomp / auditd 都在 syscall 這層盯「程式有沒有做它不該做的事」**。
> 接 [[ai-security-learning-hardening]]：auditd 開起來就是在做這件事。

## See Also

- [[use-after-free]] — bug 本體（CWE-416）
- [[php-hashtable-rce-2004-vs-2026]] — 兩個真實 CVE 的機制對照
- [[error-path-corruption]] — 另一條載體（OOM/清理路徑）
- [[index]] — 本系列目錄

# memory-safety — C 記憶體安全漏洞學習系列

用最小可編譯的 C 範例，搭配真實 AddressSanitizer 輸出，學會 C 的記憶體錯誤：
**怎麼寫出事 → 為什麼出事 → 出事長什麼樣子**。

> 範圍：純學習 C 的記憶體行為與除錯。**不做 exploit / 不做武器化**。
> 控制流劫持、CTF pwn、Rust 對照等列入「待進行」。

## 環境需求

- gcc 或 clang（本機：gcc 16.2 / clang 22）
- AddressSanitizer（隨編譯器內附）
- 編譯慣例：`-g -fsanitize=address -Wall -Wextra`

## 使用方式

一鍵管線（根目錄跑，自動掃 `src/*.c`）：

```sh
make check      # 靜態：不執行就抓（gcc -fanalyzer + cppcheck）
make test       # 動態：ASan 編起來跑，看它當場攔截
make valgrind   # 動態：valgrind 版（leak 更細）
make            # = check + test
```

單一範例手動跑（原始作法）：

```sh
cd src
gcc -g -fsanitize=address 02_uaf.c -o 02_uaf
./02_uaf          # ASan 會攔住並印出報告
```

### 為什麼要兩層（靜態 + 動態）

同一支 `02_uaf.c`，兩層抓到的東西不一樣：

| | 靜態 `make check` | 動態 `make test` |
|---|---|---|
| 要不要執行 | 否，編譯期/掃源碼 | 要，實際跑 |
| 抓到 use-after-free | ✅（CWE-416，附 alloc→free→use 事件軌跡） | ✅（ASan 執行時攔截） |
| 抓到「malloc 沒檢查就用」 | ✅（CWE-690） | ❌ runtime malloc 幾乎不會失敗，**ASan 永遠踩不到** |
| 沒被測試踩到的路徑 | ✅ 看得到 | ❌ 看不到（absence of evidence） |

重點：**動態只證明「跑到的路徑乾淨」，不是「乾淨」**。靜態補的就是這個盲區。
兩層都要——這也是 Google（Tricorder + sanitizers）的做法：靜態 shift-left、動態跑測試、各補對方的盲點。

> 下一層（待裝）：[Semgrep](https://semgrep.dev) 寫自己的規則，把 wiki 裡每個 bug 模式變成「會即時攔你」的 linter。
> 安裝：`pipx install semgrep` 或 `pacman -S semgrep`（AUR）。

## 結構

```
memory-safety/
├── README.md        # 本檔
├── src/             # 一個 bug 一個最小 .c
│   └── 02_uaf.c
└── wiki/            # 一課一頁，Karpathy 模式
    └── use-after-free.md
```

## 課綱（pilot 先做 UAF，其餘待逐課展開）

| # | 主題 | 狀態 |
|---|---|---|
| 01 | dangling pointer / use-after-return | 待 |
| 02 | **use-after-free** | ✅ pilot |
| 03 | double free | 待 |
| 04 | heap buffer overflow | 待 |
| 05 | stack buffer overflow | 待 |
| 06 | 讀未初始化記憶體 | 待 |
| 07 | error-path / OOM corruption | 待 |
| 08 | type confusion | 待 |
| 09 | UAF → 控制流（純概念，待進行） | 待 |
| 10 | memory leak（對照組） | 待 |

## 參考資源

- Robert Seacord,《Secure Coding in C and C++》
- SEI CERT C Coding Standard（線上）
- [shellphish/how2heap](https://github.com/shellphish/how2heap)（heap 攻擊範例，進階）
- [NIST Juliet C/C++ Test Suite](https://samate.nist.gov/SARD/test-suites/25)（CWE 標註的 bad/good 配對）

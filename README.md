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

```sh
cd src
gcc -g -fsanitize=address 02_uaf.c -o 02_uaf
./02_uaf          # ASan 會攔住並印出報告
```

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

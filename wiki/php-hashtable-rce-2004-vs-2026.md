---
title: PHP Zend HashTable RCE — 2004 vs 2026（機制對照）
type: reference
created: 2026-10-22
updated: 2026-10-22
tags: [memory-safety, uaf, php, zend-hashtable, cwe-416, history]
sources:
  - "Stefan Esser, Advisory 11/2004: PHP memory_limit remote vulnerability (CAN-2004-0594), bugtraq 2004-07-14, marc.info/?l=bugtraq&m=108981780109154"
  - "php2shell 公開報導：CVE-2026-109618 / CVE-2026-109619（2026-10-21 修補）"
---

# PHP Zend HashTable RCE — 2004 vs 2026（機制對照）

> **範圍：純機制對照，理解「為什麼成立」。不含 exploit、offset、heap grooming——那些列 [[待進行]]。**
> 這頁是 [[use-after-free]] 系列的歷史錨點：同一個要害，隔 22 年出現兩次。

## 一句話

**兩次 RCE 的要害相同：Zend HashTable 內「可被控制的函式指標」＋一個記憶體安全 bug 當載體。**
記憶體 bug 只是把攻擊者的資料送進那個函式指標欄位的手段；真正值錢的目標始終是那個欄位。

## 對照表

| | 2004（CAN-2004-0594） | 2026 php2shell（CVE-2026-109618/9） |
|---|---|---|
| 發現者 | Stefan Esser（e-matters） | （公開報導，多人重現中） |
| 載體 bug | 在 **HashTable 配置/初始化到一半**時，用 `memory_limit` 強制中止 → 清理路徑在半初始化狀態上動作 | **use-after-free**：指標還指著已被 free 的 HashTable bucket，跨請求殘留 |
| 被控制的欄位 | HashTable 的 **destructor 指標** | 偽造的 **`zend_fcall_info` / `zend_internal_function`** |
| 終點 | 任意程式碼執行 | `zend_call_function` → `system()` |
| 觸發面 | 檔案上傳、session 擴充、register_globals | `session.upload_progress` 處理器 |
| 研究者是否公開 PoC | **否**（Esser 刻意不放） | 官方/多數研究者克制；10/20 編號提早外洩 |

## 兩個共通的結構性教訓

1. **error / cleanup 路徑是最肥的攻擊面。**
   - 2004 打的是「中止時的清理」；2026 其中一個 CVE（109618）打的是「OOM 時的 corruption」。
   - 對照 [[error-path-corruption]]：bug 不在正常流程，在「東西壞掉時怎麼收拾」。

2. **把「控制流決策」放進可被記憶體 bug 觸及的資料裡，遲早被改寫。**
   - Zend HashTable 把 destructor / 函式指標放在 heap 上可達的記憶體 → 任何能寫到那塊的 bug 都能轉成 RCE。
   - 這就是 [[use-after-free]] §2 講的「UAF → 函式指標/vtable → 控制流」那座橋（本體列 [[待進行]]，只讀公開 writeup）。

## Java 對照

JVM 的 method table / 物件標頭也有等價的「下一步呼叫誰」資訊，但：
- 沒有手動 `free` → 沒有 UAF 把它暴露（接 [[use-after-free]] 的 Java 類比）。
- 中止一個 thread 不會讓你在「半初始化的內部結構」上控制清理路徑（JVM 的物件要嘛建好要嘛沒有）。
所以這類「中斷/釋放 → 控制函式指標」的 RCE 幾乎是 C 寫的 runtime 專屬——PHP 核心是 C。

## See Also

- [[use-after-free]] — 2026 那條的 bug 類別（CWE-416）
- [[error-path-corruption]] — 2004 與 2026-109618 的共通面（錯誤路徑毀損）
- [[index]] — 本系列目錄

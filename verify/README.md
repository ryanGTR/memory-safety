# 偵測能力矩陣 — 怎麼維護

這張表（`verify/matrix.json`）回答一件事：**哪個工具抓得到哪一類 bug。**
重點不是表好看，是它**可被程式驗證**——`make verify-matrix` 會真的把每個工具跑一遍，
和表裡的宣稱對照，不一致就紅字 + 退 1。等於幫「你對工具的認知」上了回歸測試。

## 一列是什麼

```json
{
  "file": "src/xxx.c",              // 這個 bug 類別的最小可編譯範例
  "class": "人看的 bug 類別名稱",
  "contract": "這類 bug 違反的不變量（這是會複利的知識，工具會換它不會）",
  "note": "選填：補充 nuance，例如碰運氣的情況",
  "expect": {                        // 你『宣稱』每個工具的結果
    "fanalyzer": "MISS", "cppcheck": "MISS", "asan": "MISS", "tsan": "CATCH"
  }
}
```

`expect` 的值：

| 值       | 意思 | runner 行為 |
|----------|------|-------------|
| `CATCH`  | 這工具應該抓到 | 沒抓到 → 紅字 fail |
| `MISS`   | 這工具應該抓不到 | 抓到了 → 紅字 fail（代表有驚喜，認知要更新）|
| `CATCH?` | 碰運氣抓到（非決定性，如 ASan 撞 race）| 抓到或沒抓到都不算 fail |

## 加一類新 bug（最常做的事）

1. 撞到新爛寫法 → 寫一支**最小可編譯** `.c` 丟 `src/`，一檔一 bug。
2. 先跑 `make verify-matrix` 看它現在怎麼判（**用實際結果當事實，別憑記憶**）。
3. 在 `matrix.json` 加一列：填 `class` / `contract`，`expect` 填你**認為**的結果。
4. 再跑一次。
   - 全綠 → 你的認知和現實一致，這列進庫。
   - 紅字 → 要嘛你猜錯（更新認知），要嘛範例沒寫到位（改 `.c`）。這個「打臉」就是價值。

## 格子哪天突然翻紅

工具升級、規則更新，行為會變。某天 `make verify-matrix` 紅了，不是壞掉，是**它在通知你**：
某工具現在抓得到（或抓不到）以前相反的東西。更新 `expect`，順手在 commit 說明變在哪。

## 加一個新工具欄

1. `matrix.json` 的 `tools[]` 加工具名。
2. `run_matrix.py`：`TOOL_BIN` 加「工具名 → 可執行檔名」（給偵測有沒有裝用）；
   `DETECTORS` 加一個 `detect_xxx(src, tmp)`，回傳 `True`(抓到)/`False`(沒抓到)/`None`(編不起來)。
3. 每一列的 `expect` 補上這個工具的宣稱。沒裝的工具 runner 會標 `SKIP`，不當 fail。

## kernel 欄怎麼辦（這台跑不了）

KASAN／KCSAN／kmemleak／syzkaller 要編 kernel + 開 VM，這支 userspace runner 跑不動。
所以 kernel 的那半是**已記錄、未執行**：寫進 `~/Documents/linux_kernel` 的工具對應表當文件，
標清楚哪些是推論、哪些是在 VM 真的驗過的。別把文件宣稱混進這裡會變綠的機器驗證。

## 心智模型（可攜，工具不可攜）

三層永遠在：**靜態（不執行就看源碼）／動態 sanitizer（跑起來當場抓）／fuzzing（自動餵輸入撞）**。
userspace 和 kernel 換的是每層的工具（ASan↔KASAN、TSan↔KCSAN、libFuzzer↔syzkaller），
換不掉的是「這類 bug 違反什麼契約、該用哪一層抓」。表存的就是後者。

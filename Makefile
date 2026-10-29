# memory-safety — 一鍵驗證管線
#
# 兩層檢查，抓的東西不一樣：
#   make check   靜態：不執行，編譯期/掃源碼就抓（gcc -fanalyzer + cppcheck）
#                → 連「沒跑到的路徑」和「malloc 沒檢查」都看得到
#   make test    動態：用 ASan+UBSan 編起來跑，抓「實際執行踩到」的 leak/UAF/UB
#   make overflow 動態：clang 抓 unsigned 繞回（按需，非 UB 所以預設不開）
#   make valgrind 動態：valgrind 版（抓 leak 更細）
#   make         = check + test
#
# 這是「故意寫爛」的教學 repo：工具「有報東西」才是成功，不是失敗。

SRCS := $(wildcard src/*.c)
CFLAGS_WARN := -g -Wall -Wextra
CPPCHECK := cppcheck --enable=warning,performance,portability --inconclusive --std=c23 --quiet

.PHONY: all full check deep semgrep codeql codeql-scan test race user-test verify-matrix overflow valgrind clean

# 預設：快的日常檢查（靜態三層 + ASan 動態），不含慢的 deep/valgrind
all: check test

# 全跑：連重工具 deep + valgrind 也跑（慢，偶爾完整掃一次用）
full: check test deep valgrind

# 社群 C 規則（semgrep-rules repo 的 c/，16 條，clone 在 _ext/，gitignore 不進版控）
# 更新：git -C _ext/semgrep-rules pull   ｜ 沒 clone 也不影響，只跑你自己的規則
COMMUNITY := $(wildcard _ext/semgrep-rules/c)
SEMGREP := PATH="$(HOME)/.local/bin:$$PATH" semgrep --config .semgrep.yml $(if $(COMMUNITY),--config _ext/semgrep-rules/c,) --metrics=off

## 自訂規則層 —— 你 .semgrep.yml 裡寫的「個人版 C-Fortify」規則
semgrep:
	@echo "═══ 自訂 Semgrep 規則（.semgrep.yml）═══"
	@$(SEMGREP) src/ 2>&1 | grep -vE 'Scanning|metrics|^\s*$$|━|Ran |Scan Status|Scan Summary|Scan completed|For a detailed|limited to files' || true

## 重工具層（按需跑，不塞進每次 check）—— clang-tidy + scan-build
## 跨函式、路徑敏感；威力在「多函式真實碼」才顯現，單函式玩具上多半和 -fanalyzer 重疊
## 用法：make deep FILE=path/to/real.c（預設掃 src/）
FILE ?= $(SRCS)
deep:
	@echo "═══ 重工具（clang-tidy + scan-build，跨函式）═══"
	@for f in $(FILE); do \
		printf "\n── clang-tidy: %s ──\n" "$$f"; \
		clang-tidy --checks='-*,clang-analyzer-*,bugprone-*,cert-*' $$f -- -std=c11 2>&1 | grep -vE 'Error while|compilation database|warnings? generated|Suppressed|-header-filter|^$$' || true; \
		printf "\n── scan-build: %s ──\n" "$$f"; \
		scan-build -o /tmp/scan-build-out gcc -c $$f -o /dev/null 2>&1 | grep -iE 'warning|bug found|No bugs' || true; \
	done

## 靜態層 —— 不執行就抓（這層是 ASan 看不到的盲區補丁）
check:
	@echo "═══ 靜態分析（不執行）═══"
	@for f in $(SRCS); do \
		printf "\n── gcc -fanalyzer: $$f ──\n"; \
		gcc -fanalyzer $(CFLAGS_WARN) -c $$f -o /dev/null 2>&1 || true; \
		printf "\n── cppcheck: $$f ──\n"; \
		$(CPPCHECK) $$f 2>&1 || true; \
	done
	@printf "\n── 自訂 Semgrep 規則 ──\n"
	@$(SEMGREP) src/ 2>&1 | grep -E '❯❱|Findings:|┆' || echo "  (Semgrep 沒裝或無 finding)"
	@printf "\n── 自訂 CodeQL 查詢（codeql/）──\n"
	@$(MAKE) --no-print-directory codeql-scan
	@printf "\n═══ 靜態完成。有紅字＝它幫你抓到了 ═══\n"

## 自訂 CodeQL 層 —— 「契約型」bug（semgrep 看不穿巨集、社群包門檻太高時用）
## 一類 bug 一條查詢，放 codeql/*.ql；資料庫建在 _codeql-db/（gitignore）
## 沒裝 CodeQL 就跳過：bundle 解在 ~/.local/share/codeql
CODEQL ?= $(HOME)/.local/share/codeql/codeql
codeql:
	@echo "═══ 自訂 CodeQL 查詢（codeql/）═══"
	@$(MAKE) --no-print-directory codeql-scan

codeql-scan:
	@if [ ! -x $(CODEQL) ]; then echo "  (CodeQL 沒裝，跳過)"; exit 0; fi; \
	$(CODEQL) database create _codeql-db --language=c-cpp --source-root=. --overwrite \
		--command=codeql/build.sh >/dev/null 2>&1 \
		|| { echo "  (建資料庫失敗)"; exit 0; }; \
	$(CODEQL) database analyze _codeql-db codeql/ --format=csv --output=_codeql-db/out.csv \
		--threads=0 >/dev/null 2>&1 || { echo "  (分析失敗)"; exit 0; }; \
	if [ -s _codeql-db/out.csv ]; then \
		awk -F'","' '{ print "  ❯ " $$5 ":" $$6 "  " $$4 }' _codeql-db/out.csv; \
	else echo "  (無 finding)"; fi

## 動態層 —— ASan + UBSan 編起來跑，看它當場攔截（預期會攔，攔到就對了）
## UBSan 抓「未定義行為」（signed 溢位、移位超界、NULL+offset…），業界標配、幾乎 0 成本
test:
	@echo "═══ 動態（AddressSanitizer + UndefinedBehaviorSanitizer）═══"
	@for f in $(SRCS); do \
		bin=$${f%.c}_asan; \
		gcc $(CFLAGS_WARN) -fsanitize=address,undefined $$f -o $$bin 2>/dev/null; \
		printf "\n── 執行 $$bin（預期 ASan/UBSan 攔截）──\n"; \
		./$$bin || echo "  ↑ 被攔截，退出碼 $$?（這是預期的，代表抓到了）"; \
	done

## race 層 —— ThreadSanitizer，抓「兩 thread 沒上鎖碰同一塊記憶體」，不用等 UAF 真的發生才報
## 為什麼獨立一個 target：TSan 和 ASan 不能編進同一個 binary（連結衝突），所以分開編分開跑
## 對應 CVE-2026-98432 這類 race-UAF：ASan 只在交錯剛好踩到時碰運氣，TSan 直接報 race 本身
race:
	@echo "═══ 動態（ThreadSanitizer，抓 data race）═══"
	@for f in $(SRCS); do \
		bin=$${f%.c}_tsan; \
		gcc $(CFLAGS_WARN) -fsanitize=thread $$f -o $$bin 2>/dev/null; \
		printf "\n── 執行 $$bin（有 race 才會報）──\n"; \
		./$$bin 2>&1 | grep -m4 -E 'ThreadSanitizer|data race' || echo "  (無 race 報告)"; \
	done

## 使用者空間動態全套＝ASan/UBSan（抓 UAF/leak/UB）＋ TSan（抓 race）
## kernel 不能用這些 sanitizer：KASAN/KCSAN/kmemleak 要編 kernel＋VM，見 ~/Documents/linux_kernel 的工具對應表
user-test: test race

## 偵測能力矩陣 —— 把「哪個工具抓得到哪類 bug」寫成可驗證的宣稱（verify/matrix.json）
## runner 真的跑一遍對照，不一致就退 1。= 幫你的工具認知上回歸測試
verify-matrix:
	@python3 verify/run_matrix.py

## unsigned 繞回（按需，不進 make）—— 0-1 變 4294967295 在 C 是「定義行為」，UBSan 不管
## clang 專屬旗標；hash/加密碼常故意靠繞回，開了會吵，所以只在追根因時跑
overflow:
	@echo "═══ unsigned 繞回（clang -fsanitize=unsigned-integer-overflow）═══"
	@for f in $(SRCS); do \
		bin=$${f%.c}_uo; \
		clang $(CFLAGS_WARN) -fsanitize=unsigned-integer-overflow $$f -o $$bin 2>/dev/null; \
		printf "\n── 執行 $$bin ──\n"; \
		timeout 5 ./$$bin 2>&1 | grep -m3 'runtime error' || echo "  (無繞回報告)"; \
	done

## valgrind 版（抓 leak 更細，不需 ASan 旗標）
valgrind:
	@echo "═══ 動態（valgrind）═══"
	@for f in $(SRCS); do \
		bin=$${f%.c}_vg; \
		gcc $(CFLAGS_WARN) $$f -o $$bin 2>/dev/null; \
		printf "\n── valgrind $$bin ──\n"; \
		valgrind --leak-check=full --error-exitcode=0 ./$$bin 2>&1 | tail -20; \
	done

clean:
	rm -f src/*_asan src/*_tsan src/*_vg src/*_uo $(basename $(SRCS))

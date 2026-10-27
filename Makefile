# memory-safety — 一鍵驗證管線
#
# 兩層檢查，抓的東西不一樣：
#   make check   靜態：不執行，編譯期/掃源碼就抓（gcc -fanalyzer + cppcheck）
#                → 連「沒跑到的路徑」和「malloc 沒檢查」都看得到
#   make test    動態：用 ASan 編起來跑，抓「實際執行踩到」的 leak/UAF
#   make valgrind 動態：valgrind 版（抓 leak 更細）
#   make         = check + test
#
# 這是「故意寫爛」的教學 repo：工具「有報東西」才是成功，不是失敗。

SRCS := $(wildcard src/*.c)
CFLAGS_WARN := -g -Wall -Wextra
CPPCHECK := cppcheck --enable=warning,performance,portability --inconclusive --std=c23 --quiet

.PHONY: all full check deep semgrep codeql codeql-scan test valgrind clean

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

## 動態層 —— ASan 編起來跑，看它當場攔截（預期會攔，攔到就對了）
test:
	@echo "═══ 動態（AddressSanitizer）═══"
	@for f in $(SRCS); do \
		bin=$${f%.c}_asan; \
		gcc $(CFLAGS_WARN) -fsanitize=address $$f -o $$bin 2>/dev/null; \
		printf "\n── 執行 $$bin（預期 ASan 攔截）──\n"; \
		./$$bin || echo "  ↑ ASan 攔截，退出碼 $$?（這是預期的，代表抓到了）"; \
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
	rm -f src/*_asan src/*_vg $(basename $(SRCS))

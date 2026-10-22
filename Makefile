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
CPPCHECK := cppcheck --enable=warning,performance,portability --inconclusive --std=c11 --quiet

.PHONY: all check deep test valgrind clean

all: check test

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
	@printf "\n═══ 靜態完成。有紅字＝它幫你抓到了 ═══"

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

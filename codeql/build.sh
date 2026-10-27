#!/bin/sh
# CodeQL 建資料庫用：把 src/*.c 都編一次（只要讓 extractor 看到，不產生 binary）
for f in src/*.c; do
	gcc -c "$f" -o /dev/null
done

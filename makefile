# Makefile
#
# 前提：original.bin という名前でオリジナルの実行ファイルが存在すること
# 　（たとえば clang -O0 -g -fno-pie でコンパイルしたもの）
#
# ターゲット:
#   hook_and_restore.so  ... LD_PRELOAD用ライブラリのビルド
#   zeroed.bin           ... 関数本体を0埋めしたバイナリ
#   encrypted.h          ... xor(0xAA)暗号化済みバイナリを C array に変換したヘッダ
#   encrypted.bin        ... 暗号化済みバイナリ（中間生成物）
#
# 暗号化は python3 を用い，xxd -i でC用ヘッダに変換します．

# XOR key
XOR_KEY = 0xAA

all: hook_and_restore.so zeroed.bin

# まず original.bin から XOR 暗号化したバイナリを生成
encrypted.bin: original.bin
	@echo "XOR暗号化 (key=$(XOR_KEY))..."
	python3 -c "import sys; \
data = open('original.bin','rb').read(); \
open('encrypted.bin','wb').write(bytes([b ^ $(XOR_KEY) for b in data]))"

# 次に暗号化済みバイナリをxxdでCヘッダに変換
encrypted.h: encrypted.bin
	@echo "xxdでCヘッダ(encrypted.h)を生成..."
	xxd -i encrypted.bin > encrypted.h

# hook_and_restore.so のビルド
hook_and_restore.so: hook_and_restore.c encrypted.h
	@echo "hook_and_restore.so のビルド..."
	gcc -shared -fPIC -o hook_and_restore.so hook_and_restore.c -O0

# 0埋めバイナリの生成
# 以下のルールは、Pythonスクリプト zero_fill.py を使って original.bin から
# ELFを解析し、各関数の本体（st_size>=14 のもの）を0で上書きしたバイナリを出力します。
zeroed.bin: original.bin zero_fill.py
	@echo "0埋めバイナリ(zeroed.bin)の生成..."
	python3 zero_fill.py original.bin zeroed.bin

original.bin: target.c
	@echo "original.bin の生成..."
	gcc -O0 -g -fno-pie -no-pie -o original.bin target.c

clean:
	rm -f hook_and_restore.so encrypted.bin encrypted.h zeroed.bin 

.PHONY: all clean

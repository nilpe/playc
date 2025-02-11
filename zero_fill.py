#!/usr/bin/env python3
import sys
import re
import subprocess
import shutil
from elftools.elf.elffile import ELFFile

def get_function_symbols(binary):
    """
    objdump を用いて、シンボルテーブルから .text 内の関数シンボル（Fタイプ）の
    仮想アドレスとサイズを抽出する。ただし `_start` は除外する。
    """
    result = subprocess.run(["objdump", "-t", binary],
                            capture_output=True, text=True)
    if result.returncode != 0:
        print("objdump の実行に失敗しました。")
        sys.exit(1)

    regex = re.compile(r'([0-9a-f]+)\s+\w+\s+F\s+\.text\s+([0-9a-f]+)\s+(\S+)')
    symbols = []
    for line in result.stdout.splitlines():
        m = regex.search(line)
        if m:
            addr = int(m.group(1), 16)
            size = int(m.group(2), 16)
            name = m.group(3)

            if name == "_start":
                print(f"_start (0x{addr:x}) は無視します。")
                continue

            symbols.append((addr, size, name))
    return symbols

def vaddr_to_offset(elf, vaddr):
    """
    ELF のプログラムヘッダを用いて、仮想アドレス vaddr に対応するファイル内のオフセットを返す。
    """
    for segment in elf.iter_segments():
        seg_start = segment['p_vaddr']
        seg_end = seg_start + segment['p_memsz']
        if seg_start <= vaddr < seg_end:
            return segment['p_offset'] + (vaddr - seg_start)
    return None

def main():
    if len(sys.argv) != 3:
        print("Usage: {} <input binary> <output binary>".format(sys.argv[0]))
        sys.exit(1)

    input_binary = sys.argv[1]
    output_binary = sys.argv[2]

    # 元のバイナリをコピーして作業
    shutil.copy(input_binary, output_binary)
    print(f"元のバイナリ {input_binary} を {output_binary} にコピーしました。")

    # 関数シンボルのリストを取得
    symbols = get_function_symbols(output_binary)
    if not symbols:
        print("関数シンボルが見つかりませんでした。")
        sys.exit(0)
    print(f"発見した関数シンボル数: {len(symbols)}")

    patches = []
    with open(output_binary, 'rb') as f:
        elf = ELFFile(f)
        for addr, size, name in symbols:
            offset = vaddr_to_offset(elf, addr)
            if offset is None:
                print(f"警告: アドレス 0x{addr:x} の変換に失敗しました。({name})")
                continue
            patches.append((offset, size, name))

    if not patches:
        print("パッチ対象がありません。")
        sys.exit(0)

    # バイナリの関数コードを 0 埋め
    with open(output_binary, 'r+b') as f:
        for offset, size, name in patches:
            print(f"関数 {name} (オフセット 0x{offset:x}) を {size} バイト 0 埋めします。")
            f.seek(offset)
            f.write(b'\x00' * size)

    print("パッチ処理が完了しました。")

if __name__ == '__main__':
    main()

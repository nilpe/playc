/*
 * hook_all.c
 *
 * LD_PRELOAD用ライブラリとして，対象プログラムのシンボルテーブルから
 * 全ての関数シンボル（st_value != 0）の先頭14バイトをフックし，
 * 初回呼び出し時にその関数名を出力した上で元のコードに戻し，
 * 処理を継続する．
 *
 * 対象は gcc -O0 -g -static でコンパイルされた実行ファイルであるものとする．
 *
 * コンパイル例:
 *   gcc -shared -fPIC -o hook_all.so hook_all.c -ldl
 *
 * 実行例:
 *   LD_PRELOAD=./hook_all.so ./target_program
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

/* フック処理対象のエントリ情報 */
typedef struct HookEntry {
  char *name;                  // 関数名（malloc/strdupで確保）
  void *addr;                  // フック対象関数の開始アドレス
  unsigned char orig_code[14]; // フック前の先頭14バイト
  int hooked;                  // 既にフックしているか？
} HookEntry;

/* グローバルにリストを保持（初期化時にシンボルテーブルから取得） */
static HookEntry *g_hooks = NULL;
static size_t g_hook_count = 0;

/*
 * jump命令の書き込み
 *
 * 対象アドレス (target) の先頭14バイトに，以下のジャンプコードを書き込みます．
 *
 *   ff 25 00 00 00 00   <hook_funcの8バイトアドレス>
 *
 * により，ジャンプ先は，リップ相対アドレス0を参照し，続く8バイトに書かれているhook_funcのアドレスとなる．
 *
 * また元のコードをorig_codeに退避します．
 */
static void install_jump(void *target, void *hook_func,
                         unsigned char *orig_code) {
  unsigned char jump[14] = {0xff, 0x25, 0x00, 0x00, 0x00, 0x00};
  memcpy(jump + 6, &hook_func, sizeof(void *));

  long page_size = sysconf(_SC_PAGESIZE);
  uintptr_t addr = (uintptr_t)target;
  uintptr_t page_start = addr & ~(page_size - 1);
  if (mprotect((void *)page_start, page_size,
               PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
    perror("mprotect install_jump");
    printf("target: %p, hook_func: %p\n", target, hook_func);
    return;
  }
  memcpy(orig_code, target, sizeof(jump)); // 保存
  memcpy(target, jump, sizeof(jump));      // 上書き
  __builtin___clear_cache((char *)target, (char *)target + sizeof(jump));
}

/*
 * フック後に呼ばれる共通ハンドラ
 *
 * この関数は，各フック対象ごとに個別トランポリン経由で呼ばれる．
 * 引数として，その関数のHookEntryのポインタがレジスタ rdi
 * に入った状態で呼ばれることを前提とする．
 *
 * 本関数では，
 *   - 対象の関数先頭にあるジャンプ命令を，元のコードに復元する
 *   - 「Function <name> called for the first time.」と出力する
 *   - 元の関数へジャンプする
 *
 * ※ 本関数は決して return しない（jmpでジャンプするため）
 */
__attribute__((noreturn)) void hook_handler(HookEntry *entry) {
  long page_size = sysconf(_SC_PAGESIZE);
  uintptr_t addr = (uintptr_t)entry->addr;
  uintptr_t page_start = addr & ~(page_size - 1);
  if (mprotect((void *)page_start, page_size,
               PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
    perror("mprotect in hook_handler");
  }
  /* 元のコードを復元 */
  memcpy(entry->addr, entry->orig_code, sizeof(entry->orig_code));
  __builtin___clear_cache(entry->addr,
                          (char *)entry->addr + sizeof(entry->orig_code));

  /* フック解除済みとする（以降は通常実行） */
  entry->hooked = 0;

  /* 初回呼び出し時の出力 */
  printf("Function %s called for the first time.\n", entry->name);

  /* 元の関数へジャンプ（引数，レジスタはそのまま引き継ぐ） */
  __asm__ volatile("jmp *%0\n" : : "r"(entry->addr));
  __builtin_unreachable();
}

/*
 * 各関数ごとに，個別のトランポリンコードを生成し，
 * そのアドレスをジャンプ先として対象関数に上書きする．
 *
 * トランポリンコードは以下の処理を行う．
 *   movabs rdi, <entryのアドレス>    ; (opcode: 48 BF <8byte imm>)
 *   jmp hook_handler                 ; (opcode: E9 <4byte rel-offset>)
 *
 * すなわち，hook_handler(entry) を呼び出すようにする．
 */
static void hook_function(HookEntry *entry) {
  /* 自ライブラリ内の関数はフック対象から除外する（例えば自分自身，hook_handlerなど）
   */
  if (strstr(entry->name, "hook_handler") ||
      strstr(entry->name, "hook_function") ||
      strstr(entry->name, "init_hook_all")) {
    return;
  }

  /* トランポリン用メモリを32バイト確保（RWX属性） */
  void *trampoline = mmap(NULL, 32, PROT_READ | PROT_WRITE | PROT_EXEC,
                          MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  if (trampoline == MAP_FAILED) {
    perror("mmap trampoline");
    return;
  }

  unsigned char *code = (unsigned char *)trampoline;
  /* 0: movabs rdi, <entryのポインタ> */
  code[0] = 0x48;
  code[1] = 0xbf;
  uintptr_t entry_ptr = (uintptr_t)entry;
  memcpy(code + 2, &entry_ptr, 8);
  /* 10: jmp hook_handler */
  code[10] = 0xe9;
  uintptr_t hook_handler_addr = (uintptr_t)&hook_handler;
  /* 相対オフセット = hook_handler_addr - (trampoline address + 10 + 5) */
  int32_t rel_off = (int32_t)(hook_handler_addr - ((uintptr_t)trampoline + 15));
  memcpy(code + 11, &rel_off, 4);
  /* 残りはNOP(必要なら) */
  for (int i = 15; i < 32; i++) {
    code[i] = 0x90;
  }
  __builtin___clear_cache((char *)trampoline, (char *)trampoline + 32);

  /* 対象関数の先頭14バイトにジャンプ命令を書き込む */
  install_jump(entry->addr, trampoline, entry->orig_code);
  entry->hooked = 1;
}

/*
 * __attribute__((constructor)) により，ライブラリ読み込み時に実行される
 *
 * 対象プロセスの実行ファイル (/proc/self/exe) を mmap し，
 * ELFヘッダからシンボルテーブル (.symtab/.strtab) を探す．
 * その中から STT_FUNC かつ st_value != 0 のシンボルをフック対象とし，
 * グローバル配列に保持した上で hook_function() を呼んでフックを仕掛ける．
 */
__attribute__((constructor)) void init_hook_all(void) {
  int fd = open("/proc/self/exe", O_RDONLY);
  if (fd < 0) {
    perror("open /proc/self/exe");
    return;
  }
  struct stat st;
  if (fstat(fd, &st) < 0) {
    perror("fstat");
    close(fd);
    return;
  }
  void *data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (data == MAP_FAILED) {
    perror("mmap");
    close(fd);
    return;
  }

  Elf64_Ehdr *ehdr = (Elf64_Ehdr *)data;
  if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
    fprintf(stderr, "Not an ELF file\n");
    munmap(data, st.st_size);
    close(fd);
    return;
  }

  Elf64_Shdr *shdr = (Elf64_Shdr *)((char *)data + ehdr->e_shoff);
  const char *shstrtab = (char *)data + shdr[ehdr->e_shstrndx].sh_offset;
  Elf64_Shdr *symtab_sh = NULL;
  Elf64_Shdr *strtab_sh = NULL;
  for (int i = 0; i < ehdr->e_shnum; i++) {
    const char *secname = shstrtab + shdr[i].sh_name;
    if (strcmp(secname, ".symtab") == 0) {
      symtab_sh = &shdr[i];
    }
    if (strcmp(secname, ".strtab") == 0) {
      strtab_sh = &shdr[i];
    }
  }
  if (!symtab_sh || !strtab_sh) {
    fprintf(stderr, "No symbol table found\n");
    munmap(data, st.st_size);
    close(fd);
    return;
  }

  Elf64_Sym *symtab = (Elf64_Sym *)((char *)data + symtab_sh->sh_offset);
  const char *strtab = (char *)data + strtab_sh->sh_offset;
  size_t num_symbols = symtab_sh->sh_size / sizeof(Elf64_Sym);

  /* PIE対応：実行時のベースアドレスを取得する */
  Dl_info info;
  if (dladdr((void *)&init_hook_all, &info) == 0) {
    fprintf(stderr, "dladdr failed\n");
    munmap(data, st.st_size);
    close(fd);
    return;
  }
  uintptr_t base = (uintptr_t)info.dli_fbase;

  /* まずフック対象となる関数数を数える */
  size_t count = 0;
  for (size_t i = 0; i < num_symbols; i++) {
    if (ELF64_ST_TYPE(symtab[i].st_info) == STT_FUNC &&
        symtab[i].st_value != 0) {
      count++;
    }
  }
  if (count == 0) {
    munmap(data, st.st_size);
    close(fd);
    return;
  }
  g_hooks = (HookEntry *)calloc(count, sizeof(HookEntry));
  if (!g_hooks) {
    perror("calloc");
    munmap(data, st.st_size);
    close(fd);
    return;
  }

  size_t idx = 0;
  for (size_t i = 0; i < num_symbols; i++) {
    if (ELF64_ST_TYPE(symtab[i].st_info) == STT_FUNC &&
        symtab[i].st_value != 0) {
      const char *name = strtab + symtab[i].st_name;
      if (name[0] == '\0')
        continue;

      g_hooks[idx].name = strdup(name);
      // 特殊シンボルやライブラリ自身の関数を除外
      if (strcmp(name, "_start") == 0 || strcmp(name, "_init") == 0 ||
          strcmp(name, "_fini") == 0) {
        continue;
      }
      // シンボルテーブル Elf64_Sym における st_size
      // => 関数の大きさが記録されている（実行時のマシンコード長）
      if (symtab[i].st_size < 14) {
        continue; // 14バイトのジャンプ命令を設置できない
      }

      g_hooks[idx].addr = (void *)(symtab[i].st_value);
      g_hooks[idx].hooked = 0;
      idx++;
    }
  }
  g_hook_count = idx;

  munmap(data, st.st_size);
  close(fd);

  /* 各関数に対してフックをセット */
  for (size_t i = 0; i < g_hook_count; i++) {
    hook_function(&g_hooks[i]);
  }
}

/*
 * __attribute__((destructor)) により，ライブラリ開放時に実行される
 * （メモリ解放など必要ならここで実施）
 */
__attribute__((destructor)) void fini_hook_all(void) {
  if (g_hooks) {
    for (size_t i = 0; i < g_hook_count; i++) {
      free(g_hooks[i].name);
    }
    free(g_hooks);
  }
}
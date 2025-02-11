/*
 * hook_and_restore.c
 *
 * LD_PRELOAD用ライブラリ．
 *
 * このバージョンでは、元の実行ファイル（関数本体は0埋めされている）
 * のオリジナルバイナリを、xor(0xAA)暗号化されたバイナリとして
 * encrypted.h に埋め込んでおり、ライブラリ初期化時に復号して
 * 各関数の本体をバックアップする。
 *
 * ビルド例:
 *   make hook_and_restore.so
 *
 * 実行例:
 *   LD_PRELOAD=./hook_and_restore.so ./zeroed.bin
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <execinfo.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

/* 暗号化済みバイナリのデータ（xxd -iで生成）
   ※ 暗号化には各バイトを0xAAとのxorを用いています．*/
#include "encrypted.h"

/* グローバル変数として、復号済みオリジナルバイナリを保持 */
static unsigned char *g_payload = NULL;
static size_t g_payload_size = 0;
static Elf64_Ehdr *g_payload_ehdr = NULL;
static Elf64_Phdr *g_phdr = NULL;
static int g_phnum = 0;

/* フック処理対象のエントリ情報 */
typedef struct HookEntry {
  char *name;               // 関数名（malloc/strdupで確保）
  void *addr;               // フック対象関数の開始アドレス
  size_t size;              // 関数のバイナリサイズ (st_size)
  unsigned char *orig_code; // 関数全体を保存するための動的バッファ
  int hooked;               // 既にフックしているか？
  void *trampoline;         // トランポリンのアドレス
} HookEntry;

/* グローバルにリストを保持（初期化時にシンボルテーブルから取得） */
static HookEntry *g_hooks = NULL;
static size_t g_hook_count = 0;

/*
 * 与えられた仮想アドレス（vaddr）とサイズに対応するオリジナルコード領域を
 * g_payload 内から探す．
 * ELFのプログラムヘッダを参照し、対応するロードセグメントから
 * ファイル内オフセットを計算して返します。
 */
static void *get_payload_code(uintptr_t vaddr, size_t size) {
  for (int i = 0; i < g_phnum; i++) {
    if (g_phdr[i].p_type == PT_LOAD) {
      if (vaddr >= g_phdr[i].p_vaddr &&
          vaddr + size <= g_phdr[i].p_vaddr + g_phdr[i].p_filesz) {
        size_t offset = g_phdr[i].p_offset + (vaddr - g_phdr[i].p_vaddr);
        if (offset + size <= g_payload_size)
          return g_payload + offset;
      }
    }
  }
  return NULL;
}

/*
 * jump命令の書き込み
 *
 * 対象アドレス (target) の先頭14バイトに，以下のジャンプコードを書き込みます．
 *
 *   ff 25 00 00 00 00   <hook_funcの8バイトアドレス>
 *
 * により，ジャンプ先は，リップ相対アドレス0を参照し，続く8バイトに書かれているhook_funcのアドレスとなる．
 *
 * また元のコードを「関数全体」分、すでに HookEntry->orig_code
 * に退避していることを前提とし、 先頭14バイトのみをジャンプ命令で上書きします。
 */
static void install_jump(HookEntry *entry) {
  unsigned char jump[14] = {0xff, 0x25, 0x00, 0x00, 0x00, 0x00};
  memcpy(jump + 6, &entry->trampoline, sizeof(void *));

  long page_size = sysconf(_SC_PAGESIZE);
  uintptr_t addr = (uintptr_t)entry->addr;

  /* ページ境界までアドレスを下位切り捨て */
  uintptr_t page_start = addr & ~(page_size - 1);
  size_t aligned_size = ((entry->size + page_size - 1) / page_size) * page_size;
  /* 関数全体を読み書き可能にする */
  if (mprotect((void *)page_start, aligned_size,
               PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
    perror("mprotect install_jump");
    printf("target: %p, hook_func: %p\n", entry->addr, entry->trampoline);
    return;
  }

  /* 関数先頭14バイトをジャンプ命令で上書き */
  memcpy(entry->addr, jump, sizeof(jump));
  for (size_t i = sizeof(jump); i < entry->size; i++) {
    ((unsigned char *)entry->addr)[i] = 0x90; /* NOP */
  }
  __builtin___clear_cache((char *)entry->addr,
                          (char *)entry->addr + entry->size);
  entry->hooked = 1;
}

/*
 * 与えられたアドレスがどの関数に属するかを hook_entries 配列から探す。
 * （単純な範囲チェック: 関数開始アドレス 〜 開始＋サイズ）
 */
const char *find_function_name(void *addr) {
  for (size_t i = 0; i < g_hook_count; i++) {
    void *start = g_hooks[i].addr;
    void *end = (unsigned char *)g_hooks[i].addr + g_hooks[i].size;
    if (addr >= start && addr < end) {
      return g_hooks[i].name;
    }
  }
  return NULL;
}

size_t get_unused_function(HookEntry **out, size_t out_count,
                           HookEntry nowCalled) {
  void *stack_addrs[1000] = {0};
  int num_addrs = backtrace(stack_addrs, 1000);
  int num_used_functions = 0;
  char *used_functions_name[1000] = {0};
  for (int i = 0; i < num_addrs; i++) {
    const char *func_name = find_function_name(stack_addrs[i]);
    if (func_name) {
      used_functions_name[num_used_functions] = strdup(func_name);
      num_used_functions++;
    }
  }
  int num_unused_functions = 0;
  for (int i = 0; i < g_hook_count; i++) {
    int is_used = 0;
    for (int j = 0; j < num_used_functions; j++) {
      if (strcmp(used_functions_name[j], g_hooks[i].name) == 0 ||
          strcmp(nowCalled.name, g_hooks[i].name) == 0) {
        is_used = 1;
        break;
      }
    }
    if (!is_used && num_unused_functions < out_count) {
      out[num_unused_functions] = &g_hooks[i];
      num_unused_functions++;
    }
  }
  for (int i = 0; i < num_used_functions; i++) {
    free(used_functions_name[i]);
  }
  return num_unused_functions;
}

/*
 * フック後に呼ばれる共通ハンドラ
 *
 * この関数は，各フック対象ごとに個別トランポリン経由で呼ばれる．
 * 引数として，その関数のHookEntryのポインタがレジスタ rdi
 * に入った状態で呼ばれると仮定する． 本関数は決して return
 * しない（jmpでジャンプするため）
 */
__attribute__((noreturn)) void hook_handler(HookEntry *entry) {
  long page_size = sysconf(_SC_PAGESIZE);
  uintptr_t addr = (uintptr_t)entry->addr;
  uintptr_t page_start = addr & ~(page_size - 1);
  if (mprotect((void *)page_start, page_size,
               PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
    perror("mprotect in hook_handler");
  }
  /* オリジナルコードをバックアップから復元 */
  memcpy(entry->addr, entry->orig_code, entry->size);
  __builtin___clear_cache(entry->addr, (char *)entry->addr + entry->size);

  printf("Function %s called.\n", entry->name);
  HookEntry **unused_functions =
      (HookEntry **)calloc(g_hook_count, sizeof(HookEntry *));
  int num_unused_functions =
      get_unused_function(unused_functions, g_hook_count, *entry);
  for (int i = 0; i < num_unused_functions; i++) {
    if (!unused_functions[i]->hooked) {
      install_jump(unused_functions[i]);
    }
  }
  entry->hooked = 0;
  free(unused_functions);

  __asm__ volatile("leave\n"   /* 現在のフレームを破棄 */
                   "jmp *%0\n" /* entry->addr にジャンプ */
                   :
                   : "r"(entry->addr)
                   : "memory");
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
  if (entry->addr == 0 || entry->name[0] == '\0') {
    return;
  }
  if (strstr(entry->name, "hook_handler") ||
      strstr(entry->name, "hook_function") ||
      strstr(entry->name, "init_hook_all"))
    return;
  if (entry->size < 14)
    return;

  entry->orig_code = (unsigned char *)malloc(entry->size);
  if (!entry->orig_code) {
    perror("malloc orig_code");
    return;
  }

  /* ここで、本来のコードは実行ファイル上は0埋めになっているので、
     g_payload（復号済みオリジナルバイナリ）から読み出す */
  void *src = get_payload_code((uintptr_t)entry->addr, entry->size);
  if (!src) {
    fprintf(stderr, "Cannot locate original code for %s\n", entry->name);
    free(entry->orig_code);
    entry->orig_code = NULL;
    return;
  }
  memcpy(entry->orig_code, src, entry->size);

  /* トランポリン用メモリを32バイト確保（RWX属性） */
  void *trampoline = mmap(NULL, 32, PROT_READ | PROT_WRITE | PROT_EXEC,
                          MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  if (trampoline == MAP_FAILED) {
    perror("mmap trampoline");
    free(entry->orig_code);
    entry->orig_code = NULL;
    return;
  }
  unsigned char *code = (unsigned char *)trampoline;
  /* movabs rdi, <entryのポインタ> */
  code[0] = 0x48;
  code[1] = 0xbf;
  uintptr_t entry_ptr = (uintptr_t)entry;
  memcpy(code + 2, &entry_ptr, 8);
  /* jmp hook_handler */
  code[10] = 0xe9;
  uintptr_t hook_handler_addr = (uintptr_t)&hook_handler;
  int32_t rel_off = (int32_t)(hook_handler_addr - ((uintptr_t)trampoline + 15));
  memcpy(code + 11, &rel_off, 4);
  for (int i = 15; i < 32; i++) {
    code[i] = 0x90;
  }
  __builtin___clear_cache((char *)trampoline, (char *)trampoline + 32);
  entry->trampoline = trampoline;
  install_jump(entry);
}

/*
 * __attribute__((constructor)) により，ライブラリ読み込み時に実行される
 *
 * 復号済みのオリジナルバイナリ（encrypted.hに埋め込まれたもの）を利用して，
 * シンボルテーブルからフック対象の関数を特定し，hook_function()
 * によりフックを仕掛ける．
 */
__attribute__((constructor)) void init_hook_all(void) {
  /* まず暗号化されたバイナリ（encrypted_payload, encrypted_payload_len は
     encrypted.h にて定義済み）を復号 */
  g_payload_size = encrypted_bin_len;
  g_payload = malloc(g_payload_size);
  if (!g_payload) {
    perror("malloc g_payload");
    return;
  }
  for (size_t i = 0; i < g_payload_size; i++) {
    g_payload[i] = encrypted_bin[i] ^ 0xAA;
  }
  g_payload_ehdr = (Elf64_Ehdr *)g_payload;
  if (memcmp(g_payload_ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
    fprintf(stderr, "Embedded payload is not a valid ELF file\n");
    free(g_payload);
    g_payload = NULL;
    return;
  }
  g_phdr = (Elf64_Phdr *)(g_payload + g_payload_ehdr->e_phoff);
  g_phnum = g_payload_ehdr->e_phnum;

  /* 次に、/proc/self/exe（実行ファイル、ただし関数本体は0埋め済み）からシンボルテーブルを取得
   */
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

  /* フック対象となる関数数を数える */
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
      if (strcmp(name, "_start") == 0 || strcmp(name, "_init") == 0 ||
          strcmp(name, "_fini") == 0 || strcmp(name, "init_hook_all") == 0 ||
          strcmp(name, "fini_hook_all") == 0 ||
          strcmp(name, "hook_handler") == 0 ||
          strcmp(name, "hook_function") == 0)
        continue; //*/
      if (symtab[i].st_size < 14)
        continue;
      g_hooks[idx].name = strdup(name);
      g_hooks[idx].addr = (void *)(symtab[i].st_value);
      g_hooks[idx].size = symtab[i].st_size;
      g_hooks[idx].orig_code = NULL;
      g_hooks[idx].hooked = 0;
      idx++;
    }
  }
  g_hook_count = idx;
  munmap(data, st.st_size);
  close(fd);
  for (size_t i = 0; i < g_hook_count; i++) {
    hook_function(&g_hooks[i]);
  }
}

/*
 * __attribute__((destructor)) により，ライブラリ解放時に実行される
 */
__attribute__((destructor)) void fini_hook_all(void) {
  if (g_hooks) {
    for (size_t i = 0; i < g_hook_count; i++) {
      free(g_hooks[i].name);
      if (g_hooks[i].orig_code) {
        free(g_hooks[i].orig_code);
      }
    }
    free(g_hooks);
  }
  if (g_payload) {
    free(g_payload);
  }
}

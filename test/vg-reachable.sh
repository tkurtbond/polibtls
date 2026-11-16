#!/bin/sh
# vg-reachable.sh LOG: succeed if every "still reachable" loss record in
# the valgrind log LOG (from --show-leak-kinds=all) is memory the program
# was right not to free, and print every other record:
#
# - memory allocated by poc's collector, GarbageCollectedHeap: its heap
#   chunks and its finalization and marking tables, which it never frees
#   (its allocator is the first frame after malloc, calloc or realloc);
# - memory allocated within tls_init, which Tls's body calls once: the
#   global state of OpenSSL (providers, algorithm tables, error strings)
#   and libtls's default config, kept for the life of the process.
#   OPENSSL_cleanup() doesn't free it (PLAN.md, Phase 0). With LibreTLS
#   3.8.1 and OpenSSL 3.5.8 it is 431,784 bytes in some 800 records, all
#   of whose stacks pass through tls_init (checked 2026-11-15). The
#   whole stack is needed for that, so valgrind's --num-callers must be
#   large (60 is enough); a record whose stack is cut short of tls_init
#   is printed, never allowed.
#
# Any other still-reachable block is memory the program should have
# freed - a libtls config, context or connection, or something the C part
# allocated, whose address is held only in the Oberon heap. Adapted from
# polibfyaml's, by way of posockets'.
awk '
  function finish() {
    if (inrec && first != "" && first !~ /GarbageCollectedHeap\./ && !tlsinit) {
      print rec; print first; bad = 1
    }
    inrec = 0
  }
  / are still reachable in loss record / {
    finish(); inrec = 1; first = ""; tlsinit = 0; rec = $0; next
  }
  inrec && /(at|by) 0x/ {
    if ($0 ~ /: tls_init \(/) tlsinit = 1
    if ($0 ~ /: (malloc|calloc|realloc) \(/) next
    if (first == "") first = $0
    next
  }
  inrec && /^==[0-9]+== *$/ { finish() }
  END { finish(); exit bad }
' "$1"

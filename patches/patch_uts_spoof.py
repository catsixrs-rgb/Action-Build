#!/usr/bin/env python3
"""
Patch SUSFS set_uname handler to ALSO mirror the spoofed release/version into
init_uts_ns.name.release / init_uts_ns.name.version. This makes
/proc/version, /proc/sys/kernel/osrelease, /proc/sys/kernel/version return the
spoofed string, not just the uname() syscall. Needed to defeat Chunqiu Eros 4.6
"Tampered kernel" detector which cross-checks uname() vs /proc/sys/kernel/osrelease.
"""
import sys, re

p = sys.argv[1]
try:
    s = open(p, encoding='utf-8', errors='replace').read()
except Exception as e:
    print(f"skip {p}: {e}"); sys.exit(0)

if 'susfs_set_uname' not in s:
    print(f"[{p}] no susfs_set_uname; skip"); sys.exit(0)

marker = "/* susfs: mirror to init_uts_ns"
if marker in s:
    print(f"[{p}] uts_spoof patch already present"); sys.exit(0)

orig = s

# Insert mirror block after `write_sequnlock(&susfs_uname_seqlock);` inside susfs_set_uname.
# That line is reached unconditionally after my_uname has been populated.
inject = (
    "\twrite_sequnlock(&susfs_uname_seqlock);\n"
    "\t/* susfs: mirror to init_uts_ns so /proc/version, /proc/sys/kernel/osrelease,\n"
    "\t * /proc/sys/kernel/version see the spoofed string too. Chunqiu Eros 4.6\n"
    "\t * detects uname()/osrelease mismatch as \"Tampered kernel\". */\n"
    "\tdown_write(&uts_sem);\n"
    "\tstrscpy(init_uts_ns.name.release, my_uname.release, __NEW_UTS_LEN + 1);\n"
    "\tstrscpy(init_uts_ns.name.version, my_uname.version, __NEW_UTS_LEN + 1);\n"
    "\tup_write(&uts_sem);\n"
)

needle = "\twrite_sequnlock(&susfs_uname_seqlock);\n"
if needle not in s:
    print(f"[{p}] write_sequnlock(&susfs_uname_seqlock) not found; skip")
    sys.exit(0)

# Replace the first occurrence (inside susfs_set_uname — the only one in this file).
s = s.replace(needle, inject, 1)

# Ensure uts headers available. susfs.c already includes linux/sched.h which pulls
# in uts.h on 6.1 but add utsname.h explicitly to be safe (idempotent via marker).
if '#include <linux/utsname.h>' not in s:
    # add near top after the first #include block
    m = re.search(r'(#include [^\n]+\n)+', s)
    if m:
        end = m.end()
        s = s[:end] + "#include <linux/utsname.h>\n" + s[end:]

if s != orig:
    open(p, 'w', encoding='utf-8').write(s)
    print(f"[{p}] uts_spoof applied, WROTE")
else:
    print(f"[{p}] no change")
sys.exit(0)

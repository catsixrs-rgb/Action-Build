#!/usr/bin/env python3
import sys, re
p = sys.argv[1]
try: s = open(p, encoding='utf-8').read()
except Exception as e: print(f"skip {p}: {e}"); sys.exit(0)
orig = s
# PATCH A: gate KSU_INSTALL_MAGIC2 handshake (dispatch.c)
a_old = "    if (magic2 == KSU_INSTALL_MAGIC2)\n        return ksu_supercall_reboot_handler(arg);\n"
a_new = ("    if (magic2 == KSU_INSTALL_MAGIC2) {\n        if (!is_manager() && current_uid().val != 0)\n"
         "            return -EINVAL;\n        return ksu_supercall_reboot_handler(arg);\n    }\n")
if a_old in s: s = s.replace(a_old, a_new, 1); print(f"[{p}] PATCH A applied")
# PATCH B: version-leaking ioctls -> manager_or_root (dispatch.c)
def flip(name, s):
    pat = re.compile(r'(\.name\s*=\s*"'+re.escape(name)+r'"\s*,.*?\.perm_check\s*=\s*)always_allow', re.S)
    s2, n = pat.subn(r'\1manager_or_root', s)
    if n: print(f"[{p}] PATCH B {name} applied")
    return s2
for name in ("GET_INFO","GET_INFO_LEGACY","CHECK_SAFEMODE","GET_FULL_VERSION"): s = flip(name, s)
# gate_sucompat: su->sh redirect only for root/manager (sucompat.c) -> kills /system/bin/su leak
GATE = ("    if (!ksu_su_compat_enabled)\n        return 0;\n    if (likely(test_thread_flag(TIF_SECCOMP)))\n"
        "        return 0;\n    if (!ksu_is_allow_uid_for_current(current_uid().val))\n        return 0;\n\n")
fa = "int ksu_handle_faccessat(int *dfd, struct filename **filename, int *mode,\n             int *__unused_flags)\n{\n"
if fa in s: s = s.replace(fa, fa + GATE, 1); print(f"[{p}] gate_sucompat faccessat applied")
st = "int ksu_handle_stat(int *dfd, struct filename **filename, int *flags) {\n"
if st in s: s = s.replace(st, st + GATE, 1); print(f"[{p}] gate_sucompat stat applied")
if s != orig: open(p,'w',encoding='utf-8').write(s); print(f"[{p}] WROTE")
else: print(f"[{p}] no change")
sys.exit(0)

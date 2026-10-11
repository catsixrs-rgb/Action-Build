#!/usr/bin/env python3
import sys, re
p = sys.argv[1]
try:
    s = open(p, encoding='utf-8').read()
except Exception as e:
    print(f"skip {p}: {e}"); sys.exit(0)
orig = s
a_old = "    if (magic2 == KSU_INSTALL_MAGIC2)\n        return ksu_supercall_reboot_handler(arg);\n"
a_new = ("    if (magic2 == KSU_INSTALL_MAGIC2) {\n"
         "        if (!is_manager() && current_uid().val != 0)\n"
         "            return -EINVAL;\n"
         "        return ksu_supercall_reboot_handler(arg);\n"
         "    }\n")
if a_old in s:
    s = s.replace(a_old, a_new, 1); print(f"[{p}] PATCH A: applied")
elif a_new in s:
    print(f"[{p}] PATCH A: already applied")
else:
    print(f"[{p}] PATCH A: anchor not present (ok for non-SUSFS variant)")
def flip(name, s):
    pat = re.compile(r'(\.name\s*=\s*"'+re.escape(name)+r'"\s*,.*?\.perm_check\s*=\s*)always_allow', re.S)
    s2, n = pat.subn(r'\1manager_or_root', s)
    if n: print(f"[{p}] PATCH B {name}: applied")
    return s2
for name in ("GET_INFO","GET_INFO_LEGACY","CHECK_SAFEMODE"):
    s = flip(name, s)
if s != orig:
    open(p,'w',encoding='utf-8').write(s); print(f"[{p}] WROTE")
else:
    print(f"[{p}] no change")
sys.exit(0)

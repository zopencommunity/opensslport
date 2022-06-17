+#!/bin/sh -k
+#
+# Re-order arguments so that -L comes first
+#
+opts=""
+lopts=""
+        
+for arg in $* ; do
+  case $arg in
+    -L*) lopts="$lopts $arg" ;;
+    *) opts="$opts $arg" ;;
+  esac
+done
+
+c99 -Wl,dll $lopts $opts
+#c99 -DOPENSSL_THREADS -D_OPEN_THREADS -O -Wc,XPLINK -DB_ENDIAN -DCHARSET_EBCDIC -DNO_SYS_PARAM_H -D_ALL_SOURCE -qlongname -qlanglvl=extc99 $lopts $opts

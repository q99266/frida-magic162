#!/system/bin/sh
# Quarantine pentest / frida artifacts from /data/local/tmp
Q=/data/local/tmp/.quarantine
mkdir -p "$Q"
cd /data/local/tmp || exit 1

for f in *helper*.dex .*.dex frida* *launcher* fs fs-* fs* magicfs* phantom* f178ser* fsarm64 ecapture memdumper hide-port.so; do
  [ -e "$f" ] && mv "$f" "$Q/" 2>/dev/null
done

for f in .f .f-* .srv .srv.log .listen .launcher.log launcher*.log .[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]; do
  [ -f "$f" ] && mv "$f" "$Q/" 2>/dev/null
done

for f in .v-* .ff*; do
  [ -f "$f" ] && mv "$f" "$Q/" 2>/dev/null
done

echo "remaining suspicious:"
ls -la 2>/dev/null | grep -iE 'helper|frida|fs-|magic|phantom|\.srv|launcher|\.f' | wc -l

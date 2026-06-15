#!/bin/bash
# install.sh — build and install the cockblock watcher+guard system
# Usage:  sudo ./install.sh
#         sudo COCKBLOCK_SEED=12345678 ./install.sh   # (reinstall with same seed)
set -e

if [ "$(id -u)" != "0" ]; then
    echo "Must run as root" >&2; exit 1
fi

# ── seed ──────────────────────────────────────────────────────────────────────
if [ -z "$COCKBLOCK_SEED" ]; then
    COCKBLOCK_SEED=$(od -An -N4 -tu4 /dev/urandom | tr -d ' \n')
fi
echo "[*] Seed: $COCKBLOCK_SEED  (save this to reinstall)"

# ── paths (disguised as systemd helpers) ──────────────────────────────────────
INSTALL_DIR="/usr/lib/systemd"

INJECTOR_NAME="systemd-resolved-inject"
WATCHER_NAME="systemd-resolved-update"
GUARD_NAME="systemd-resolved-monitor"

INJECTOR_BIN="${INSTALL_DIR}/${INJECTOR_NAME}"
WATCHER_BIN="${INSTALL_DIR}/${WATCHER_NAME}"
GUARD_BIN="${INSTALL_DIR}/${GUARD_NAME}"

WATCHER_SVC="/etc/systemd/system/${WATCHER_NAME}.service"
GUARD_SVC="/etc/systemd/system/${GUARD_NAME}.service"

# ── compile ────────────────────────────────────────────────────────────────────
echo "[*] Compiling injector..."
gcc -std=c99 -D_GNU_SOURCE -O2 -z noexecstack -fno-stack-protector \
    -fPIC -shared -Wl,-e,_start \
    -DCOCKBLOCK_SEED=${COCKBLOCK_SEED}UL \
    -o "$INJECTOR_BIN" injector.c -ldl

echo "[*] Compiling watcher..."
gcc -std=c99 -D_GNU_SOURCE -O2 \
    -DCOCKBLOCK_SEED=${COCKBLOCK_SEED}UL \
    -DINJECTOR_BINARY_PATH=\"${INJECTOR_BIN}\" \
    -DGUARD_BINARY_PATH=\"${GUARD_BIN}\" \
    -DGUARD_SERVICE_PATH=\"${GUARD_SVC}\" \
    -o "$WATCHER_BIN" watcher.c

echo "[*] Compiling guard..."
gcc -std=c99 -D_GNU_SOURCE -O2 \
    -DCOCKBLOCK_SEED=${COCKBLOCK_SEED}UL \
    -DWATCHER_BINARY_PATH=\"${WATCHER_BIN}\" \
    -o "$GUARD_BIN" guard.c

chmod 755 "$INJECTOR_BIN" "$WATCHER_BIN" "$GUARD_BIN"

# ── systemd services ───────────────────────────────────────────────────────────
echo "[*] Writing service files..."

cat > "$WATCHER_SVC" <<EOF
[Unit]
Description=Resolved Update Helper
After=network.target

[Service]
Type=simple
ExecStartPre=/usr/bin/chattr +i ${INJECTOR_BIN} ${WATCHER_BIN} ${GUARD_BIN}
ExecStart=${WATCHER_BIN}
Restart=always
RestartSec=1
StartLimitIntervalSec=0

[Install]
WantedBy=multi-user.target
EOF

cat > "$GUARD_SVC" <<EOF
[Unit]
Description=Resolved Monitor Service
After=network.target ${WATCHER_NAME}.service

[Service]
Type=simple
ExecStartPre=/usr/bin/chattr +i ${INJECTOR_BIN} ${WATCHER_BIN} ${GUARD_BIN}
ExecStart=${GUARD_BIN}
Restart=always
RestartSec=3
StartLimitIntervalSec=0

[Install]
WantedBy=multi-user.target
EOF

# ── lock down ──────────────────────────────────────────────────────────────────
echo "[*] Applying chattr +i to all protected files..."
chattr +i "$INJECTOR_BIN" "$WATCHER_BIN" "$GUARD_BIN"
chattr +i "$WATCHER_SVC" "$GUARD_SVC"

# ── enable + start ─────────────────────────────────────────────────────────────
echo "[*] Enabling and starting services..."
systemctl daemon-reload
systemctl enable "${WATCHER_NAME}.service" "${GUARD_NAME}.service"
systemctl start  "${WATCHER_NAME}.service" "${GUARD_NAME}.service"

echo ""
echo "Done.  Seed=${COCKBLOCK_SEED}"
echo ""
echo "To fully uninstall (requires all steps in sequence):"
echo "  chattr -i ${INJECTOR_BIN} ${WATCHER_BIN} ${GUARD_BIN}"
echo "  chattr -i ${WATCHER_SVC} ${GUARD_SVC}"
echo "  systemctl stop  ${WATCHER_NAME} ${GUARD_NAME}"
echo "  systemctl disable ${WATCHER_NAME} ${GUARD_NAME}"
echo "  rm ${INJECTOR_BIN} ${WATCHER_BIN} ${GUARD_BIN}"
echo "  rm ${WATCHER_SVC} ${GUARD_SVC}"
echo "  systemctl daemon-reload"

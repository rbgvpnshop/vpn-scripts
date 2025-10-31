#!/usr/bin/env bash
set -Eeuo pipefail
# ใช้: ./make_license.sh <KEY> <IP> <จำนวนวัน> <MAX_USER> [PRIVATE_PEM] [OUT_DIR]
KEY="${1:?KEY required}"
IP="${2:?IP required}"
DAYS="${3:-30}"
MAX="${4:-2500}"
PRIV="${5:-./keys/license_priv.pem}"
OUT="${6:-./licenses}"

mkdir -p "$OUT"
EXP=$(date -d "+${DAYS} days" +%s)

PAYLOAD="$(jq -n --arg key "$KEY" --arg ip "$IP" --argjson exp "$EXP" --argjson max "$MAX" \
  '{key:$key, ip:$ip, exp:$exp, max:$max}')"

TMPDIR="$(mktemp -d)"
printf '%s' "$PAYLOAD" > "$TMPDIR/payload.json"
openssl dgst -sha256 -sign "$PRIV" -out "$TMPDIR/payload.sig" "$TMPDIR/payload.json"

b64(){ base64 -w 0 2>/dev/null || base64; }
PAY_B64="$(b64 < "$TMPDIR/payload.json")"
SIG_B64="$(b64 < "$TMPDIR/payload.sig")"

jq -n --arg payload "$PAY_B64" --arg sig "$SIG_B64" \
  '{payload:$payload, sig:$sig}' > "$OUT/${KEY}.lic"

echo "✅ สร้างไฟล์: $OUT/${KEY}.lic  (อัปขึ้นโดเมน: /licenses/<KEY>.lic)"
rm -rf "$TMPDIR"

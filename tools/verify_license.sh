#!/usr/bin/env bash
set -Eeuo pipefail
# ใช้: ./verify_license.sh <FILE.lic> [PUBLIC_PEM]
LIC="${1:?license file required}"
PUB="${2:-./keys/license_pub.pem}"

TMPDIR="$(mktemp -d)"
jq -r '.payload' "$LIC" | base64 -d > "$TMPDIR/payload.json"
jq -r '.sig'     "$LIC" | base64 -d > "$TMPDIR/payload.sig"

if openssl dgst -sha256 -verify "$PUB" -signature "$TMPDIR/payload.sig" "$TMPDIR/payload.json" >/dev/null 2>&1; then
  echo "✅ ลายเซ็นถูกต้อง"
else
  echo "❌ ลายเซ็นไม่ถูกต้อง"; rm -rf "$TMPDIR"; exit 1
fi

echo "---- PAYLOAD ----"
cat "$TMPDIR/payload.json" | jq .
NOW=$(date +%s); EXP=$(jq -r '.exp' "$TMPDIR/payload.json")
LEFT=$(( (EXP-NOW+86399)/86400 ))
echo "เหลือวันใช้งานประมาณ: $(( LEFT<0 ? 0 : LEFT )) วัน"
rm -rf "$TMPDIR"

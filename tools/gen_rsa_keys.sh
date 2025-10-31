#!/usr/bin/env bash
set -Eeuo pipefail

OUT_DIR="${1:-./keys}"
mkdir -p "$OUT_DIR"

# สร้างคีย์ลับ (เก็บไว้เครื่องเดียวเท่านั้น)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$OUT_DIR/license_priv.pem"

# สร้างคีย์สาธารณะ (อันนี้ให้อัพขึ้น GitHub เป็น license_pub.pem)
openssl rsa -in "$OUT_DIR/license_priv.pem" -pubout -out "$OUT_DIR/license_pub.pem"

echo "✅ Private: $OUT_DIR/license_priv.pem (ห้ามแชร์)"
echo "✅ Public : $OUT_DIR/license_pub.pem  (อัพขึ้น repo เป็นไฟล์ license_pub.pem)"

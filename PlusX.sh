#!/usr/bin/env bash
# PlusX – Server Manager (TH)  (Merged + PackageName Lock + Online App + License + Update)
# - [1] ออกใบ client + export .ovpn (inline)
# - [2] ออกไฟล์ .ovpn ที่ "ผูกแพ็กเกจเนม" (1 ไฟล์/1 แอพ)
# - [16] Security(OpenVPN): เตรียม PKI/CRL/CCD, เปิด Package-Lock Hook, รายชื่อใบ, รีโวค, ปรับค่า
# - [18] ONLINE APP (หน้าเว็บดู Online / JSON API)
# - [19] License (RSA payload verify + แสดงวันหมดอายุ)
# - [20] Reboot/Timer, [21] Backup/Restore/Uninstall, [22] Ports/UFW
# - [98] Self-Update จาก GitHub, [99] เมนูเดิม (LEGACY)
# รองรับ: Ubuntu 20.04/22.04/24.04, Debian 11/12

set -Eeuo pipefail

#====================[ ปรับค่าได้ ]====================
LICENSE_BASE="https://thwed-key.bnetray.online/licenses"
PUBKEY_URL="https://thwed-key.bnetray.online/license_pub.pem"
LEGACY_BIN="${LEGACY_BIN:-/usr/local/bin/plusx_legacy.sh}"



# OVPN / PKI
OVPN_ENV="${OVPN_ENV:-/etc/plusx/ovpn.env}"
EASYRSA_DIR="${EASYRSA_DIR:-/etc/easy-rsa}"
CLIENT_EXPORT_DIR="${CLIENT_EXPORT_DIR:-/etc/openvpn/clients}"
OPENVPN_DIR="${OPENVPN_DIR:-/etc/openvpn}"
DEFAULT_CA_CN="${DEFAULT_CA_CN:-ChangeMe}"
DEFAULT_CERT_DAYS="${DEFAULT_CERT_DAYS:-3650}"

# SELF-UPDATE
UPDATE_URL="${UPDATE_URL:-https://raw.githubusercontent.com/rbgvpnshop/vpn-scripts/main/plusx.sh}"

#====================[ ไฟล์ระบบ ]======================
STATE_DIR="/etc/plusx"; install -d "$STATE_DIR" >/dev/null 2>&1 || true
PUBKEY_PATH="$STATE_DIR/license_pub.pem"
CACHE_TOKEN="$STATE_DIR/license.token"
PAYLOAD_JSON="$STATE_DIR/payload.json"
PAYLOAD_SIG="$STATE_DIR/payload.sig"
LOG_DIR="/var/log/plusx"; install -d "$LOG_DIR" >/dev/null 2>&1 || true
LOG_FILE="$LOG_DIR/plusx-actions.log"
BK_DIR="/root/plusx-backups"; install -d "$BK_DIR" >/dev/null 2>&1 || true

#====================[ Utils ]==========================
need(){ command -v "$1" >/dev/null 2>&1; }
ensure_tools(){
  local miss=0; for c in curl jq openssl awk sed grep tee ss ufw; do need "$c" || miss=1; done
  if [[ $miss -eq 1 ]]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y curl jq openssl coreutils gawk sed grep iproute2 ufw >/dev/null 2>&1 || true
  fi
  need easy-rsa || apt-get install -y easy-rsa >/dev/null 2>&1 || true
  need openvpn  || apt-get install -y openvpn  >/dev/null 2>&1 || true
}
log(){ printf '[%(%F %T)T] %s\n' -1 "$1" | tee -a "$LOG_FILE" >/dev/null; }
sysip(){ curl -fsSL -4 https://ifconfig.co || hostname -I | awk '{print $1}'; }
is_root(){ [[ $EUID -eq 0 ]]; }
pause(){ read -rp "กด Enter เพื่อกลับเมนู..."; }

#====================[ LICENSE ]========================
download_pubkey(){ [[ -s "$PUBKEY_PATH" ]] || { curl -fsSL "$PUBKEY_URL" -o "$PUBKEY_PATH"; chmod 644 "$PUBKEY_PATH"; }; }
ask_key(){
  local cur=""; [[ -s "$CACHE_TOKEN" ]] && cur=$(jq -r '.key // empty' "$CACHE_TOKEN" 2>/dev/null || true)
  if [[ -n "$cur" ]]; then read -rp "พบคีย์เดิม: $cur ใช้ต่อ? [Y/n]: " a; [[ "${a,,}" =~ ^n ]] && cur=""; fi
  [[ -n "$cur" ]] && KEY="$cur" || read -rp "ใส่คีย์เพื่อใช้งานสคริปต์: " KEY
}
fetch_and_verify(){
  echo "[+] ตรวจคีย์กับเซิร์ฟเวอร์ลิขสิทธิ์..."
  local doc; doc=$(curl -fsSL --max-time 8 "$LICENSE_BASE/$KEY.lic" || true)
  [[ -n "$doc" ]] || { echo "❌ ไม่พบคีย์บนเซิร์ฟเวอร์"; exit 1; }
  local pay_b64 sig_b64; pay_b64=$(jq -r '.payload // empty' <<<"$doc"); sig_b64=$(jq -r '.sig // empty' <<<"$doc")
  [[ -n "$pay_b64" && -n "$sig_b64" ]] || { echo "❌ โทเค็นไม่ถูกต้อง"; exit 1; }
  printf %s "$pay_b64" | base64 -d > "$PAYLOAD_JSON"
  printf %s "$sig_b64" | base64 -d > "$PAYLOAD_SIG"
  if ! openssl dgst -sha256 -verify "$PUBKEY_PATH" -signature "$PAYLOAD_SIG" "$PAYLOAD_JSON" >/dev/null 2>&1; then echo "❌ ลายเซ็นไม่ผ่าน"; exit 1; fi
  local L_KEY L_IP L_EXP L_MAX NOW MYIP
  L_KEY=$(jq -r '.key' "$PAYLOAD_JSON"); L_IP=$(jq -r '.ip' "$PAYLOAD_JSON"); L_EXP=$(jq -r '.exp' "$PAYLOAD_JSON"); L_MAX=$(jq -r '.max // 2500' "$PAYLOAD_JSON")
  NOW=$(date +%s); MYIP=$(sysip)
  [[ "$L_KEY" == "$KEY" ]] || { echo "❌ คีย์ไม่ตรง"; exit 1; }
  (( NOW <= L_EXP )) || { echo "❌ คีย์หมดอายุแล้ว"; exit 1; }
  [[ "$L_IP" == "$MYIP" ]] || { echo "❌ IP เครื่อง ($MYIP) ไม่ตรงกับใบอนุญาต ($L_IP)"; exit 1; }
  jq -n --arg key "$L_KEY" --arg ip "$L_IP" --argjson exp "$L_EXP" --argjson max "$L_MAX" '{key:$key, ip:$ip, exp:$exp, max:$max}' > "$CACHE_TOKEN"
  export LICENSED_MAX="$L_MAX"
  echo "✅ คีย์ถูกต้อง (หมดอายุ: $(date -d @${L_EXP} +%F))  IP: $L_IP  Max: $L_MAX"
}
read_cached_license(){ if [[ -s "$CACHE_TOKEN" ]]; then L_KEY=$(jq -r '.key' "$CACHE_TOKEN" 2>/dev/null || echo "-"); L_EXP=$(jq -r '.exp' "$CACHE_TOKEN" 2>/dev/null || echo "0"); L_MAX=$(jq -r '.max // 2500' "$CACHE_TOKEN" 2>/dev/null || echo "2500"); else L_KEY="-" ; L_EXP=0 ; L_MAX=2500 ; fi; }
header(){
  read_cached_license
  local exp_str now dleft; now=$(date +%s)
  if (( L_EXP>0 )); then dleft=$(( (L_EXP-now+86399)/86400 )); (( dleft<0 )) && dleft=0; exp_str="$(date -d @${L_EXP} +%F) (เหลือ ${dleft} วัน)"
  else exp_str="-"; fi
  clear
  echo "============================================================"
  echo " PlusX – ระบบจัดการเซิร์ฟเวอร์      IP: $(sysip)"
  echo " KEY: ${L_KEY:0:4}******   Max: ${L_MAX}   หมดอายุ: ${exp_str}"
  echo "============================================================"
}

#====================[ OVPN defaults ]===================
ensure_ovpn_env(){
  if [[ ! -s "$OVPN_ENV" ]]; then
    install -d "$(dirname "$OVPN_ENV")"
    cat >"$OVPN_ENV" <<'EOF'
REMOTE_HOST=th-app01.example.com
PROTO=tcp
PORT=1194
TLS_MODE=tls-auth         # tls-auth | tls-crypt
CIPHER=AES-256-CBC
AUTH=SHA256
SERVER_CONF=/etc/openvpn/server.conf
EOF
  fi
  # shellcheck disable=SC1090
  source "$OVPN_ENV"
}
set_ovpn_defaults(){
  ensure_ovpn_env
  echo "ค่าเดิม: REMOTE_HOST=$REMOTE_HOST  PROTO=$PROTO  PORT=$PORT  TLS_MODE=$TLS_MODE"
  read -rp "REMOTE_HOST: " _h; [[ -n "${_h:-}" ]] && REMOTE_HOST="$_h"
  read -rp "PROTO [tcp/udp] (ปัจจุบัน $PROTO): " _p; [[ -n "${_p:-}" ]] && PROTO="$_p"
  read -rp "PORT (ปัจจุบัน $PORT): " _pt; [[ -n "${_pt:-}" ]] && PORT="$_pt"
  read -rp "TLS_MODE [tls-auth/tls-crypt] (ปัจจุบัน $TLS_MODE): " _tm; [[ -n "${_tm:-}" ]] && TLS_MODE="$_tm"
  cat >"$OVPN_ENV" <<EOF
REMOTE_HOST=$REMOTE_HOST
PROTO=$PROTO
PORT=$PORT
TLS_MODE=$TLS_MODE
CIPHER=$CIPHER
AUTH=$AUTH
SERVER_CONF=${SERVER_CONF:-/etc/openvpn/server.conf}
EOF
  echo "✔ บันทึกแล้วที่ $OVPN_ENV"
}

#====================[ Easy-RSA / PKI ]==================
ensure_easy_rsa_tree(){ install -d "$EASYRSA_DIR" "$CLIENT_EXPORT_DIR" "$OPENVPN_DIR"; [[ -d "$EASYRSA_DIR/pki" ]] || cp -r /usr/share/easy-rsa/* "$EASYRSA_DIR"/; }
pki_init_if_needed(){
  ensure_easy_rsa_tree
  export EASYRSA_BATCH=1 EASYRSA_ALGO=rsa EASYRSA_KEY_SIZE=2048 EASYRSA_CA_EXPIRE=36500 EASYRSA_CERT_EXPIRE="${DEFAULT_CERT_DAYS}"
  export EASYRSA_REQ_COUNTRY=TH EASYRSA_REQ_PROVINCE=Bangkok EASYRSA_REQ_CITY=Bangkok EASYRSA_REQ_ORG=BNET EASYRSA_REQ_EMAIL=admin@yourdomain.com EASYRSA_REQ_OU=VPN EASYRSA_REQ_CN="${DEFAULT_CA_CN}"
  pushd "$EASYRSA_DIR" >/dev/null
  [[ -f pki/ca.crt ]] || { ./easyrsa init-pki; ./easyrsa build-ca nopass; log "สร้าง CA ใหม่แล้ว (CN=$DEFAULT_CA_CN)"; }
  [[ -f pki/issued/server.crt ]] || { ./easyrsa gen-req server nopass; ./easyrsa sign-req server server; log "ออกใบ server แล้ว"; }
  popd >/dev/null
}
ensure_tls_key(){ pushd "$EASYRSA_DIR" >/dev/null; if [[ "${TLS_MODE:-tls-auth}" == "tls-crypt" ]]; then [[ -f tls-crypt.key ]] || openvpn --genkey secret tls-crypt.key; else [[ -f ta.key ]] || openvpn --genkey secret ta.key; fi; popd >/dev/null; }

#====================[ Client issue / export ]============
issue_client_cert(){ local CLIENT="$1"; pushd "$EASYRSA_DIR" >/dev/null; if [[ ! -f "pki/issued/${CLIENT}.crt" ]]; then EASYRSA_REQ_CN="${CLIENT}" ./easyrsa gen-req "$CLIENT" nopass; ./easyrsa sign-req client "$CLIENT"; else log "พบใบ client เดิม: ${CLIENT} (ข้าม gen/sign)"; fi; popd >/dev/null; }
# ฝังแพ็กเกจเนมใน CN และ OU (CN=CLIENT#pkg=PACKAGE)
issue_client_cert_with_pkg(){ local CLIENT="$1" PKG="$2"; pushd "$EASYRSA_DIR" >/dev/null; EASYRSA_REQ_CN="${CLIENT}#pkg=${PKG}" EASYRSA_REQ_OU="${PKG}" ./easyrsa gen-req "$CLIENT" nopass; ./easyrsa sign-req client "$CLIENT"; popd >/dev/null; echo "✔ ออกใบ client: CN=${CLIENT}#pkg=${PKG}"; }

build_inline_ovpn(){ # arg1=CLIENT arg2=REMOTE arg3=PROTO arg4=PORT
  local CLIENT="$1" REMOTE="$2" PROTO="$3" PORT="$4"
  local OUT="$CLIENT_EXPORT_DIR/${CLIENT}.ovpn" MODE="${TLS_MODE:-tls-auth}"
  local CA="$EASYRSA_DIR/pki/ca.crt" CRT="$EASYRSA_DIR/pki/issued/${CLIENT}.crt" KEY="$EASYRSA_DIR/pki/private/${CLIENT}.key" TA="$EASYRSA_DIR/ta.key" TC="$EASYRSA_DIR/tls-crypt.key"
  local CN PKG; CN=$(openssl x509 -in "$CRT" -noout -subject 2>/dev/null | sed -n 's/.*CN=\([^,]*\).*/\1/p' || true); PKG=$(sed -n 's/.*#pkg=\([^#]*\).*/\1/p' <<<"$CN" || true)

  {
    echo "# Generated by PlusX $(date -u +%F)"; [[ -n "$PKG" ]] && echo "# pkg: $PKG"
    cat <<EOF
client
dev tun
proto ${PROTO}
remote ${REMOTE} ${PORT}
resolv-retry infinite
nobind
persist-key
persist-tun
auth-user-pass
remote-cert-tls server
cipher ${CIPHER}
auth ${AUTH}
verb 3
EOF
    [[ -n "$PKG" ]] && echo "# hint: bound-package ${PKG}"
    echo "<ca>";  cat "$CA";  echo "</ca>"
    echo "<cert>"; awk '/-----BEGIN CERTIFICATE-----/{f=1} f; /-----END CERTIFICATE-----/{print; f=0}' "$CRT"; echo "</cert>"
    echo "<key>";  cat "$KEY"; echo "</key>"
    if [[ "$MODE" == "tls-crypt" && -f "$TC" ]]; then
      echo "<tls-crypt>"; cat "$TC"; echo "</tls-crypt>"
    else
      echo "key-direction 1"; echo "<tls-auth>"; cat "$TA"; echo "</tls-auth>"
    fi
  } > "$OUT"
  chmod 600 "$OUT"; cp -f "$OUT" "/root/${CLIENT}.ovpn"
  echo "✅ ไฟล์: $OUT (สำเนา /root/${CLIENT}.ovpn)"
}

list_clients(){ pushd "$EASYRSA_DIR" >/dev/null; [[ -d pki/issued ]] && { echo "Client certificates:"; ls -1 pki/issued | sed 's/\.crt$//' | nl -w2 -s') '; } || echo "ยังไม่มีใบ client"; popd >/dev/null; }

#====================[ Package Lock – Server Hook ]======
CCD_DIR="${CCD_DIR:-${OPENVPN_DIR}/ccd}"
PKG_ALLOWED_LIST="${OPENVPN_DIR}/allowed_pkgs.list"   # ว่าง = ไม่จำกัด
PKG_MAP_DIR="${OPENVPN_DIR}/ccd-pkg"                  # ไฟล์ชื่อ USER เก็บ package ที่อนุญาต
PKG_CHECK_SCRIPT="${OPENVPN_DIR}/check_pkg.sh"        # client-connect hook

ensure_pkg_lock_hook(){
  ensure_ovpn_env
  install -d "$CCD_DIR" "$PKG_MAP_DIR"
  [[ -f "$PKG_ALLOWED_LIST" ]] || : > "$PKG_ALLOWED_LIST"

  cat >"$PKG_CHECK_SCRIPT" <<'SH'
#!/usr/bin/env bash
set -e
CN="${common_name:-}"
ALLOWED="/etc/openvpn/allowed_pkgs.list"
MAPDIR="/etc/openvpn/ccd-pkg"
log(){ logger -t openvpn "[pkg-check] $*"; }

PKG="$(sed -n 's/.*#pkg=\([^#]*\).*/\1/p' <<<"$CN")"
BASE="${CN%%#pkg=*}"
if [[ -z "$PKG" ]]; then log "reject CN=$CN (ไม่มี #pkg=...)"; exit 1; fi

if [[ -f "$MAPDIR/$BASE" ]]; then
  EXPECTED="$(tr -d '\r\n' < "$MAPDIR/$BASE")"
  [[ "$PKG" == "$EXPECTED" ]] || { log "reject CN=$CN (pkg=$PKG != expected=$EXPECTED)"; exit 1; }
else
  if [[ -s "$ALLOWED" ]] && ! grep -xq "$PKG" "$ALLOWED"; then
    log "reject CN=$CN (pkg=$PKG not in allowed list)"; exit 1
  fi
fi
log "allow CN=$CN (pkg=$PKG)"; exit 0
SH
  chmod +x "$PKG_CHECK_SCRIPT"

  grep -q '^script-security' "$SERVER_CONF" 2>/dev/null || echo "script-security 2" >> "$SERVER_CONF"
  grep -q '^client-connect ' "$SERVER_CONF" 2>/dev/null || echo "client-connect ${PKG_CHECK_SCRIPT}" >> "$SERVER_CONF"
  grep -q '^client-config-dir ' "$SERVER_CONF" 2>/dev/null || echo "client-config-dir ${CCD_DIR}" >> "$SERVER_CONF"
  grep -q '^crl-verify ' "$SERVER_CONF" 2>/dev/null || echo "crl-verify /etc/openvpn/crl.pem" >> "$SERVER_CONF"
  sed -i '/^[[:space:]]*duplicate-cn[[:space:]]*$/d' "$SERVER_CONF" 2>/dev/null || true
  grep -q '^status ' "$SERVER_CONF" 2>/dev/null || echo "status /var/log/openvpn/status.log" >> "$SERVER_CONF"

  systemctl restart openvpn* >/dev/null 2>&1 || true
  echo "✔ เปิดใช้ Package-Lock Hook แล้ว"
}

export_pkg_bound_ovpn(){  # arg1=user  arg2=pkg
  ensure_ovpn_env; ensure_tls_key; pki_init_if_needed
  local CLIENT="${1:-}"; local PKG="${2:-}"
  [[ -n "$CLIENT" ]] || read -rp "Client name: " CLIENT
  [[ -n "$PKG"    ]] || read -rp "Package name (เช่น co.netrgb.vpn): " PKG
  issue_client_cert_with_pkg "$CLIENT" "$PKG"
  build_inline_ovpn "$CLIENT" "$REMOTE_HOST" "$PROTO" "$PORT"
  echo "➡️  สร้างแล้ว: $CLIENT_EXPORT_DIR/${CLIENT}.ovpn (pkg=$PKG)"
  echo "   * บังคับ user นี้ใช้ได้เฉพาะแพ็กเกจนี้: echo \"$PKG\" > ${PKG_MAP_DIR}/${CLIENT}"
}

pkg_allowed_list(){ [[ -s "$PKG_ALLOWED_LIST" ]] && nl -ba "$PKG_ALLOWED_LIST" || echo "(ว่าง)"; }
pkg_allowed_add(){ local p="$1"; [[ -z "$p" ]] && { read -rp "แพ็กเกจเนม: " p; }; grep -xq "$p" "$PKG_ALLOWED_LIST" 2>/dev/null || echo "$p" >> "$PKG_ALLOWED_LIST"; echo "✔ เพิ่ม $p"; }
pkg_allowed_rm(){ local p="$1"; [[ -z "$p" ]] && { read -rp "แพ็กเกจเนมที่ลบ: " p; }; [[ -f "$PKG_ALLOWED_LIST" ]] && grep -vx "$p" "$PKG_ALLOWED_LIST" > "$PKG_ALLOWED_LIST.tmp" && mv -f "$PKG_ALLOWED_LIST.tmp" "$PKG_ALLOWED_LIST"; echo "✔ ลบ $p"; }
pkg_map_set_user(){ local u="$1" p="$2"; [[ -z "$u" ]] && read -rp "Client: " u; [[ -z "$p" ]] && read -rp "Package: " p; echo "$p" > "${PKG_MAP_DIR}/${u}"; echo "✔ กำหนด $u → $p"; }
pkg_map_rm_user(){ local u="$1"; [[ -z "$u" ]] && read -rp "Client: " u; rm -f "${PKG_MAP_DIR}/${u}"; echo "✔ ลบ mapping ของ $u"; }
pkg_map_show(){ ls -1 "${PKG_MAP_DIR}" 2>/dev/null | while read -r f; do printf "%-24s -> %s\n" "$f" "$(cat "${PKG_MAP_DIR}/$f")"; done || echo "(ว่าง)"; }

#====================[ ONLINE APP ]======================
ONLINE_ENV="/etc/online-app.env"
write_online_env(){ cat >"$ONLINE_ENV" <<EOF
STATUS_LOG=${1:-/var/log/openvpn/status.log}
HOST=0.0.0.0
PORT=${2:-8081}
CAPACITY=${3:-${LICENSED_MAX:-2500}}
EOF
}
install_online_app(){
  local status="${1:-/var/log/openvpn/status.log}" port="${2:-8081}" max="${3:-${LICENSED_MAX:-2500}}"
  cat >/usr/local/bin/online_app.py <<'PY'
#!/usr/bin/env python3
import os, json, time
from http.server import BaseHTTPRequestHandler, HTTPServer
STATUS_LOG = os.environ.get("STATUS_LOG","/var/log/openvpn/status.log")
CAPACITY   = int(os.environ.get("CAPACITY","2500") or "2500")
if CAPACITY < 1: CAPACITY = 1
def read_status(path):
    out=[]
    try:
        with open(path,'r') as f:
            for line in f:
                if line.startswith('CLIENT_LIST,'):
                    p=line.strip().split(',')
                    if len(p)>=7:
                        out.append({"user":p[1],"real":p[2],"bytes_recv":int(p[3]),
                                    "bytes_sent":int(p[4]),"since":p[5],"virtual":p[6]})
    except Exception:
        pass
    return out
HTML = """<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>ONLINE APP</title><style>
body{font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;padding:16px}
.top{display:flex;align-items:center;gap:12px}
.progress{width:260px;height:14px;background:#eee;border-radius:7px;overflow:hidden}
.bar{height:100%;width:{bar}%;background:#3b82f6}
table{border-collapse:collapse;width:100%;margin-top:12px}
th,td{border:1px solid #ddd;padding:8px}th{background:#f5f5f5;text-align:left}
.small{color:#666;font-size:12px}
</style></head><body>
<h2>OpenVPN Online</h2>
<div class="top"><div><strong>Online:</strong> {count} / {maxc} ({pct:.1f}%)</div>
<div class="progress"><div class="bar"></div></div></div>
<p class="small">Status file: {status}</p>
<table><thead><tr><th>User</th><th>Real IP</th><th>Virtual IP</th><th>Since</th><th>RX</th><th>TX</th></tr></thead>
<tbody>{rows}</tbody></table>
<p>JSON: <a href='/api/online'>/api/online</a></p>
<script>document.querySelector('.bar').style.width='{bar}%'</script>
</body></html>"""
class H(BaseHTTPRequestHandler):
    def _h(self,code=200,ctype='text/html'):
        self.send_response(code); self.send_header('Content-Type',ctype)
        self.send_header('Cache-Control','no-store')
        self.send_header('Access-Control-Allow-Origin','*'); self.end_headers()
    def do_GET(self):
        data=read_status(STATUS_LOG); count=len(data)
        pct=min(100.0,(count/CAPACITY)*100.0) if CAPACITY else 0.0
        if self.path.startswith('/api/online'):
            self._h(200,'application/json')
            self.wfile.write(json.dumps({"online":data,"count":count,"max":CAPACITY,
                                         "remaining":max(0,CAPACITY-count),
                                         "percent":round(pct,2),"ts":int(time.time())}).encode())
        else:
            rows=''.join(f"<tr><td>{d['user']}</td><td>{d['real']}</td><td>{d['virtual']}</td><td>{d['since']}</td><td>{d['bytes_recv']}</td><td>{d['bytes_sent']}</td></tr>" for d in data)
            if not rows: rows="<tr><td colspan='6'>No clients</td></tr>"
            html=HTML.format(status=STATUS_LOG,rows=rows,count=count,maxc=CAPACITY,pct=pct,bar=pct)
            self._h(); self.wfile.write(html.encode())
def main():
    host=os.environ.get('HOST','0.0.0.0'); port=int(os.environ.get('PORT','8081'))
    HTTPServer((host,port),H).serve_forever()
if __name__=='__main__': main()
PY
  chmod +x /usr/local/bin/online_app.py
  write_online_env "$status" "$port" "$max"
  cat >/etc/systemd/system/online-app.service <<'EOF'
[Unit]
Description=ONLINE APP (OpenVPN online status)
After=network-online.target
[Service]
EnvironmentFile=/etc/online-app.env
ExecStart=/usr/local/bin/online_app.py
Restart=always
RestartSec=2
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now online-app.service
  ufw allow "${port}"/tcp >/dev/null 2>&1 || true
  echo "✅ ONLINE APP:  http://$(sysip):${port}/"
}
stop_online_app(){ systemctl disable --now online-app.service || true; echo "❎ ปิด ONLINE APP แล้ว"; }
show_online_link(){ local port; port=$(grep -E '^PORT=' "$ONLINE_ENV" 2>/dev/null | cut -d= -f2 || echo 8081); echo "ลิงก์: http://$(sysip):${port}/  | JSON: /api/online"; }
set_online_capacity(){
  local cur max; cur=$(grep -E '^CAPACITY=' "$ONLINE_ENV" 2>/dev/null | cut -d= -f2 || echo 2500)
  read -rp "Max (ปัจจุบัน=${cur}): " max; max=${max:-$cur}
  sed -i -E "s/^CAPACITY=.*/CAPACITY=${max}/" "$ONLINE_ENV"
  systemctl restart online-app.service || true
  echo "✔ ตั้งค่า Max=${max}"
}
set_online_status_or_port(){
  read -rp "ไฟล์สถานะ (เช่น /var/log/openvpn/status.log): " s
  read -rp "พอร์ตบริการ (เช่น 8081): " p
  s=${s:-/var/log/openvpn/status.log}; p=${p:-8081}
  write_online_env "$s" "$p" "$(grep -E '^CAPACITY=' "$ONLINE_ENV" 2>/dev/null | cut -d= -f2 || echo 2500)"
  systemctl restart online-app.service || true
  echo "✔ ปรับแล้ว"
}

#====================[ Reboot / Backup / Ports ]================
install_reboot_timer(){
  local oncal="$1"
  cat >/etc/systemd/system/plusx-reboot.service <<'EOF'
[Unit]
Description=PlusX scheduled reboot
[Service]
Type=oneshot
ExecStart=/usr/sbin/shutdown -r now "PlusX auto reboot"
EOF
  cat >/etc/systemd/system/plusx-reboot.timer <<EOF
[Unit]
Description=Run PlusX scheduled reboot ($oncal)
[Timer]
OnCalendar=$oncal
Persistent=true
[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now plusx-reboot.timer
  systemctl restart plusx-reboot.timer
  echo "✔ ตั้งออโต้รีบูตแล้ว ($oncal)"
}
disable_reboot_timer(){ systemctl disable --now plusx-reboot.timer 2>/dev/null || true; rm -f /etc/systemd/system/plusx-reboot.timer; systemctl daemon-reload; echo "✔ ปิดออโต้รีบูตแล้ว"; }
show_reboot_status(){
  if systemctl status plusx-reboot.timer >/dev/null 2>&1; then
    systemctl status --no-pager plusx-reboot.timer | sed -n '1,12p'
    echo; systemctl list-timers --all | grep plusx-reboot.timer || true
  else
    echo "ℹ️ ยังไม่ได้ตั้งออโต้รีบูต"
  fi
}
backup_config(){
  local ts bk tmp; ts=$(date +%F_%H%M%S); bk="$BK_DIR/plusx-backup_${ts}.tar.gz"; tmp=$(mktemp)
  for d in /etc/openvpn /etc/xray /etc/caddy /etc/stunnel /etc/squid /etc/3proxy /etc/ssh /etc/systemd/system; do [[ -d "$d" ]] && echo "$d" >> "$tmp"; done
  [[ -f /etc/systemd/system/plusx-reboot.service ]] && echo "/etc/systemd/system/plusx-reboot.service" >> "$tmp"
  [[ -f /etc/systemd/system/plusx-reboot.timer"  ]] && echo "/etc/systemd/system/plusx-reboot.timer"  >> "$tmp"
  if [[ -s "$tmp" ]]; then tar -czpf "$bk" -T "$tmp" && echo "✔ สำรอง: $bk"; else echo "ℹ️ ไม่มีคอนฟิกจะสำรอง"; fi
  rm -f "$tmp"
}
restore_config(){ read -rp "พาธไฟล์ .tar.gz: " f; [[ -f "$f" ]] || { echo "ไม่พบไฟล์"; return; }; tar -xzpf "$f" -C /; systemctl daemon-reload; echo "✔ กู้คืนแล้ว"; }
ufw_menu_allow_defaults(){
  ufw allow OpenSSH >/dev/null 2>&1 || true
  for p in 80 81 443 444 446 1080 8081; do ufw allow ${p}/tcp >/dev/null 2>&1 || true; done
  ufw allow 1194/udp >/dev/null 2>&1 || true
  ufw --force enable >/dev/null 2>&1 || true
  echo "✔ เปิด UFW และพอร์ตหลักแล้ว"
}

#====================[ Self Update / Legacy ]===================
self_update(){
  echo "🔄 อัปเดตจาก: $UPDATE_URL"
  curl -fsSL "$UPDATE_URL" -o /usr/local/bin/plusx.sh.new || { echo "❌ ดาวน์โหลดไม่สำเร็จ"; return 1; }
  chmod +x /usr/local/bin/plusx.sh.new
  cp -f /usr/local/bin/plusx.sh /usr/local/bin/plusx.sh.bak 2>/dev/null || true
  mv -f /usr/local/bin/plusx.sh.new /usr/local/bin/plusx.sh
  echo "✔ อัปเดตแล้ว (สำรองไว้ /usr/local/bin/plusx.sh.bak)"
}
legacy_or_hint(){ if [[ -x "$LEGACY_BIN" ]]; then "$LEGACY_BIN"; else echo "ℹ️ ยังไม่มีเมนูเดิม (ตั้ง LEGACY_BIN ให้ชี้ไฟล์เดิมถ้ามี)"; pause; fi; }

#====================[ เมนูย่อย ]=======================
menu_install(){
  while true; do
    header
    cat <<'MENU'
[ติดตั้งระบบต่าง ๆ]
 1) OpenSSH
 2) Squid Proxy (:8080)
 3) OpenVPN (server)
 4) stunnel4
 5) Xray (installer script)
 0) กลับ
MENU
    read -rp "เลือก: " k
    case "$k" in
      1) apt -y install openssh-server; systemctl restart ssh || systemctl restart sshd; echo "✔ OpenSSH พร้อม"; pause;;
      2) apt -y install squid; systemctl enable --now squid; echo "✔ Squid :8080"; pause;;
      3) apt -y install openvpn easy-rsa; echo "✔ ติดตั้ง OpenVPN + easy-rsa แล้ว"; pause;;
      4) apt -y install stunnel4; systemctl enable --now stunnel4; echo "✔ stunnel พร้อม"; pause;;
      5) bash -lc 'curl -fsSL https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh | bash' || true; echo "✔ ติดตั้ง Xray แล้ว"; pause;;
      0) break;;
      *) echo "เมนูไม่ถูกต้อง"; sleep 1;;
    esac
  done
}

menu_online(){
  while true; do
    header
    cat <<'MENU'
[18] ONLINE APP
 1) ติดตั้ง/เปิด ONLINE APP
 2) ปิด ONLINE APP
 3) แสดงลิงก์การใช้งาน
 4) ตั้งค่า Max/Capacity
 5) ปรับไฟล์สถานะ/พอร์ต
 0) กลับ
MENU
    read -rp "เลือก: " a
    case "$a" in
      1) read -rp "ไฟล์สถานะ (/var/log/openvpn/status.log): " s; s=${s:-/var/log/openvpn/status.log}
         read -rp "พอร์ต (8081): " p; p=${p:-8081}
         read -rp "Max/Capacity (${LICENSED_MAX:-2500}): " m; m=${m:-${LICENSED_MAX:-2500}}
         install_online_app "$s" "$p" "$m"; pause;;
      2) stop_online_app; pause;;
      3) show_online_link; pause;;
      4) set_online_capacity; pause;;
      5) set_online_status_or_port; pause;;
      0) break;;
      *) echo "เมนูไม่ถูกต้อง"; sleep 1;;
    esac
  done
}

menu_license(){
  while true; do
    header
    cat <<'MENU'
[19] ใบอนุญาต/คีย์
 1) ใส่/เปลี่ยนคีย์ใบอนุญาต (ดึง/ยืนยันจากเซิร์ฟเวอร์)
 2) ตรวจสอบคีย์อีกครั้ง
 3) แสดงรายละเอียดคีย์ (วันหมดอายุ / เหลือกี่วัน)
 4) ล้างคีย์ที่แคชไว้
 0) กลับ
MENU
    read -rp "เลือก: " a
    case "$a" in
      1) ensure_tools; download_pubkey; ask_key; fetch_and_verify; pause;;
      2) ensure_tools; download_pubkey; read_cached_license; KEY="${L_KEY:-}"; [[ -z "$KEY" || "$KEY" = "-" ]] && read -rp "ใส่คีย์: " KEY; fetch_and_verify; pause;;
      3) header; pause;;
      4) rm -f "$CACHE_TOKEN" "$PAYLOAD_JSON" "$PAYLOAD_SIG"; echo "✔ ล้างคีย์แล้ว"; pause;;
      0) break;;
      *) echo "เมนูไม่ถูกต้อง"; sleep 1;;
    esac
  done
}

menu_reboot(){
  while true; do
    header
    cat <<'MENU'
[20] รีบูต/ตั้งเวลารีบูต
 1) รีบูตเครื่องทันที
 2) ตั้งเวลารีบูตอัตโนมัติ (รายวัน/สัปดาห์/เดือน/กำหนดเอง)
 3) ปิดออโต้รีบูต
 4) ดูสถานะ/รอบถัดไป
 0) กลับ
MENU
    read -rp "เลือก: " a
    case "$a" in
      1) read -rp "พิมพ์ YES เพื่อยืนยัน: " ok; [[ "$ok" == "YES" ]] && shutdown -r now "Manual reboot" || echo "ยกเลิก";;
      2) echo "เลือกรูปแบบ"; echo "  [1] ทุกวัน  [2] รายสัปดาห์  [3] รายเดือน  [4] กำหนดเอง"
         read -rp "เลือก: " m
         case "$m" in
           1) read -rp "เวลา HH:MM: " hm; hm=${hm:-03:30}; install_reboot_timer "--* ${hm}:00" ;;
           2) read -rp "วัน (Mon/Tue/...): " dow; read -rp "เวลา HH:MM: " hm; hm=${hm:-04:00}; install_reboot_timer "${dow} --* ${hm}:00" ;;
           3) read -rp "วันที่ (1-31): " dom; read -rp "เวลา HH:MM: " hm; dom=${dom:-1}; hm=${hm:-05:00}; install_reboot_timer "--${dom} ${hm}:00" ;;
           4) read -rp "OnCalendar string: " oc; [[ -n "$oc" ]] && install_reboot_timer "$oc" || echo "ยกเลิก";;
           *) echo "เมนูไม่ถูกต้อง";;
         esac; pause;;
      3) disable_reboot_timer; pause;;
      4) show_reboot_status; pause;;
      0) break;;
      *) echo "เมนูไม่ถูกต้อง"; sleep 1;;
    esac
  done
}

menu_backup(){
  while true; do
    header
    cat <<'MENU'
[21] สำรอง/กู้คืน/ถอนติดตั้ง
 1) สำรองคอนฟิกทั้งหมด
 2) กู้คืนจากไฟล์ .tar.gz
 3) ดูไฟล์สำรองล่าสุด
 4) ถอนติดตั้งบริการหลักอย่างปลอดภัย
 0) กลับ
MENU
    read -rp "เลือก: " a
    case "$a" in
      1) backup_config; pause;;
      2) restore_config; pause;;
      3) ls -lh "$BK_DIR" | tail -n 20; pause;;
      4) read -rp "พิมพ์ DELETE เพื่อยืนยัน: " c; [[ "$c" == "DELETE" ]] || { echo "ยกเลิก"; continue; }
         systemctl stop openvpn@server openvpn-server@server xray stunnel4 squid 3proxy sockd || true
         systemctl disable openvpn@server openvpn-server@server xray stunnel4 squid 3proxy sockd || true
         apt -y purge openvpn xray stunnel4 squid 3proxy dante-server || true
         apt -y autoremove --purge || true
         echo "✔ ถอนติดตั้งแล้ว"; pause;;
      0) break;;
      *) echo "เมนูไม่ถูกต้อง"; sleep 1;;
    esac
  done
}

menu_ports(){
  while true; do
    header
    cat <<'MENU'
[22] พอร์ต & ไฟร์วอลล์ (UFW)
 1) อนุญาตพอร์ตมาตรฐาน + เปิด UFW
 2) เปิด/ปิด UFW
 3) แสดงกฎ UFW ปัจจุบัน
 4) รีเซ็ต UFW (ระวัง)
 5) ตรวจสอบพอร์ตที่กำลังฟัง
 0) กลับ
MENU
    read -rp "เลือก: " a
    case "$a" in
      1) ufw_menu_allow_defaults; pause;;
      2) read -rp "เลือก [on/off]: " s; if [[ "${s,,}" == "on" ]]; then ufw --force enable; else ufw --force disable; fi; pause;;
      3) ufw status verbose; pause;;
      4) read -rp "พิมพ์ RESET เพื่อยืนยัน: " r; [[ "$r" == "RESET" ]] && ufw --force reset; pause;;
      5) ss -luntp; pause;;
      0) break;;
      *) echo "เมนูไม่ถูกต้อง"; sleep 1;;
    esac
  done
}

#====================[ เมนู 16 – Security / Package Lock ]===================
menu_security16(){
  ensure_ovpn_env
  while true; do
    header
    cat <<'MENU'
[16] ระบบด้านความปลอดภัย (OpenVPN)
 1) เตรียม/แข็ง OpenVPN (สร้าง CA/Server ถ้ายัง, เปิด CRL/CCD)
 2) เปิดใช้ Package-Lock Hook บนเซิร์ฟเวอร์
 3) รายชื่อใบ client ที่มีอยู่
 4) ออกใบ client ปกติ + export .ovpn (inline)
 5) ออก CRL / รีโวคใบ client
 6) แสดง/แก้ค่า OVPN Defaults (REMOTE/PROTO/PORT/TLS)

 [ย่อย: Package Name]
 7) เพิ่ม/ลบ/ดู Allowed Package List
 8) ออกไฟล์ OVPN ที่ “ผูกแพ็กเกจ” (CN=ชื่อ#pkg=แพ็กเกจ)
 9) จัดการ Mapping รายผู้ใช้ (บังคับ user → package เดียว)

 0) กลับเมนูหลัก
MENU
    read -rp "เลือก: " k
    case "$k" in
      1) pki_init_if_needed; ensure_tls_key; echo "✔ เตรียมระบบ OVPN แล้ว"; pause;;
      2) ensure_pkg_lock_hook; pause;;
      3) list_clients; pause;;
      4) read -rp "Client name: " u; issue_client_cert "$u"; build_inline_ovpn "$u" "$REMOTE_HOST" "$PROTO" "$PORT"; pause;;
      5) pushd "$EASYRSA_DIR" >/dev/null; read -rp "รีโวค client: " u; ./easyrsa revoke "$u"; ./easyrsa gen-crl; install -m 0644 pki/crl.pem /etc/openvpn/crl.pem; popd >/dev/null; systemctl restart openvpn* || true; echo "✔ revoke $u แล้ว"; pause;;
      6) set_ovpn_defaults; pause;;
      7) echo " [a] เพิ่ม  [r] ลบ  [l] ดู"; read -rp "เลือก: " s
         case "$s" in
           a) read -rp "แพ็กเกจเนม: " p; pkg_allowed_add "$p";;
           r) read -rp "แพ็กเกจเนม: " p; pkg_allowed_rm "$p";;
           l) pkg_allowed_list;;
           *) echo "ยกเลิก";;
         esac; pause;;
      8) read -rp "Client: " u; read -rp "Package (เช่น co.netrgb.vpn): " p; export_pkg_bound_ovpn "$u" "$p"; pause;;
      9) echo " [s] ตั้งค่า  [d] ลบ  [l] ดูทั้งหมด"; read -rp "เลือก: " s
         case "$s" in
           s) read -rp "Client: " u; read -rp "Package: " p; pkg_map_set_user "$u" "$p";;
           d) read -rp "Client: " u; pkg_map_rm_user "$u";;
           l) pkg_map_show;;
           *) echo "ยกเลิก";;
         esac; pause;;
      0) break;;
      *) echo "เมนูไม่ถูกต้อง"; sleep 1;;
    esac
  done
}

#====================[ เมนูหลัก ]========================
main_menu(){
  is_root || { echo "กรุณารันด้วย root หรือ sudo"; exit 1; }
  ensure_tools; download_pubkey || true; ensure_ovpn_env || true
  while true; do
    header
    cat <<'MENU'
[เมนูหลัก – PlusX]
 1) ออกใบ client + export .ovpn (inline)
 2) ออก .ovpn ที่ผูกแพ็กเกจ (CN=ชื่อ#pkg=แพ็กเกจ)
 3) รายชื่อใบ client
 4) รีโวค client / ออก CRL
 5) ตั้งค่า OVPN Defaults (REMOTE/PROTO/PORT/TLS)

 10) ติดตั้งระบบต่าง ๆ
 16) ระบบด้านความปลอดภัย (Package-Lock/CRL/CCD)
 18) ONLINE APP
 19) ใบอนุญาต/คีย์
 20) รีบูต/ตั้งเวลารีบูต
 21) สำรอง/กู้คืน/ถอนติดตั้ง
 22) พอร์ต & ไฟร์วอลล์

 98) อัปเดตสคริปต์จาก GitHub
 99) เมนูเพิ่มเติม/เมนูเดิม (LEGACY)
 00) ออกจากสคริปต์
MENU
    read -rp "เลือกเมนู: " m
    case "$m" in
      1) read -rp "Client name: " u; pki_init_if_needed; ensure_tls_key; issue_client_cert "$u"; build_inline_ovpn "$u" "$REMOTE_HOST" "$PROTO" "$PORT"; pause;;
      2) read -rp "Client: " u; read -rp "Package (เช่น co.netrgb.vpn): " p; export_pkg_bound_ovpn "$u" "$p"; pause;;
      3) list_clients; pause;;
      4) pushd "$EASYRSA_DIR" >/dev/null; read -rp "รีโวค client: " u; ./easyrsa revoke "$u"; ./easyrsa gen-crl; install -m 0644 pki/crl.pem /etc/openvpn/crl.pem; popd >/dev/null; systemctl restart openvpn* || true; echo "✔ revoke $u แล้ว"; pause;;
      5) set_ovpn_defaults; pause;;

      10) menu_install;;
      16) menu_security16;;
      18) menu_online;;
      19) menu_license;;
      20) menu_reboot;;
      21) menu_backup;;
      22) menu_ports;;

      98) self_update; pause;;
      99) legacy_or_hint;;
      0|00) exit 0;;
      *) echo "เมนูไม่ถูกต้อง"; sleep 1;;
    esac
  done
}

main_menu

#!/usr/bin/env bash
# PlusX (Secure License) — V2Ray/Xray, stunnel, OpenSSH, SOCKS5, ONLINE APP(+Max)
# รองรับ Ubuntu 20.04/22.04/24.04 และ Debian 11/12

set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "กรุณารันเป็น root หรือใส่ sudo"; exit 1; }
export DEBIAN_FRONTEND=noninteractive

#====================[ SECURE LICENSE CHECK ]====================
# แก้สองตัวแปรนี้ให้เป็นของคุณ
LICENSE_BASE="${LICENSE_BASE:-https://license.yourdomain.com/licenses}"   # <- โดเมนใบอนุญาตของคุณ
PUBKEY_URL="${PUBKEY_URL:-https://raw.githubusercontent.com/rbgvpnshop/vpn-scripts/main/license_pub.pem}"  # <- ลิงก์ public key

STATE_DIR="/etc/plusx"; mkdir -p "$STATE_DIR"
PUBKEY_PATH="$STATE_DIR/license_pub.pem"
CACHE_TOKEN="$STATE_DIR/license.token"

need(){ command -v "$1" >/dev/null 2>&1 || return 1; }
ensure_tools(){
  local miss=0
  for c in curl jq openssl; do command -v "$c" >/dev/null 2>&1 || miss=1; done
  if [[ $miss -eq 1 ]]; then
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y curl jq openssl >/dev/null 2>&1 || true
  fi
}
get_ip(){ curl -fsSL -4 https://ifconfig.co || hostname -I | awk '{print $1}'; }

download_pubkey(){
  if [[ ! -s "$PUBKEY_PATH" ]]; then
    echo "[+] โหลด public key สำหรับตรวจลายเซ็น"
    curl -fsSL "$PUBKEY_URL" -o "$PUBKEY_PATH"
    chmod 644 "$PUBKEY_PATH"
  fi
}

ask_key(){
  local cur=""
  if [[ -s "$CACHE_TOKEN" ]]; then
    cur=$(jq -r '.key // empty' "$CACHE_TOKEN" 2>/dev/null || true)
    if [[ -n "$cur" ]]; then
      read -rp "พบคีย์เดิม: $cur  ใช้ต่อ? [Y/n]: " a
      [[ "${a,,}" == "n" || "${a,,}" == "no" ]] && cur=""
    fi
  fi
  [[ -n "$cur" ]] && KEY="$cur" || read -rp "ใส่คีย์เพื่อใช้งานสคริปต์: " KEY
}

fetch_and_verify(){
  echo "[+] ตรวจคีย์กับเซิร์ฟเวอร์ลิขสิทธิ์..."
  local doc
  doc=$(curl -fsSL --max-time 8 "$LICENSE_BASE/$KEY.lic" || true)
  [[ -n "$doc" ]] || { echo "❌ ไม่พบคีย์บนเซิร์ฟเวอร์: $LICENSE_BASE/$KEY.lic"; exit 1; }

  local pay_b64 sig_b64
  pay_b64=$(jq -r '.payload // empty' <<<"$doc"); sig_b64=$(jq -r '.sig // empty' <<<"$doc")
  [[ -n "$pay_b64" && -n "$sig_b64" ]] || { echo "❌ โทเค็นไม่ถูกต้อง"; exit 1; }

  printf %s "$pay_b64" | base64 -d > "$STATE_DIR/payload.json"
  printf %s "$sig_b64" | base64 -d > "$STATE_DIR/payload.sig"

  # verify signature (RSA+SHA256)
  if ! openssl dgst -sha256 -verify "$PUBKEY_PATH" -signature "$STATE_DIR/payload.sig" "$STATE_DIR/payload.json" >/dev/null 2>&1; then
    echo "❌ ลายเซ็นไม่ผ่าน (ไฟล์ถูกแก้ไข/ปลอม)"; exit 1
  fi

  local L_KEY L_IP L_EXP L_MAX NOW MYIP
  L_KEY=$(jq -r '.key' "$STATE_DIR/payload.json")
  L_IP=$(jq -r '.ip' "$STATE_DIR/payload.json")
  L_EXP=$(jq -r '.exp' "$STATE_DIR/payload.json")
  L_MAX=$(jq -r '.max // 2500' "$STATE_DIR/payload.json")
  NOW=$(date +%s); MYIP=$(get_ip)

  [[ "$L_KEY" == "$KEY" ]] || { echo "❌ คีย์ไม่ตรงกับโทเค็น"; exit 1; }
  (( NOW <= L_EXP )) || { echo "❌ คีย์หมดอายุแล้ว"; exit 1; }
  [[ "$L_IP" == "$MYIP" ]] || { echo "❌ เครื่องนี้ IP=$MYIP ไม่ตรงกับใบอนุญาต ($L_IP)"; exit 1; }

  # cache for other parts & export licensed MAX
  jq -n --arg key "$L_KEY" --arg ip "$L_IP" --argjson exp "$L_EXP" --argjson max "$L_MAX" \
     '{key:$key, ip:$ip, exp:$exp, max:$max}' > "$CACHE_TOKEN"
  export LICENSED_MAX="$L_MAX"

  echo "✅ คีย์ถูกต้อง (หมดอายุ: $(date -d @${L_EXP}))  IP: $L_IP  Max: $L_MAX"
}

apply_max_to_online_app_if_exists(){
  if [[ -f /etc/online-app.env && -n "${LICENSED_MAX:-}" ]]; then
    sed -i -E "s/^CAPACITY=.*/CAPACITY=${LICENSED_MAX}/" /etc/online-app.env || true
    systemctl restart online-app.service >/dev/null 2>&1 || true
  fi
}

ensure_tools
download_pubkey
ask_key
fetch_and_verify
apply_max_to_online_app_if_exists
#================[ END SECURE LICENSE CHECK ]====================

echo "[+] Update/Upgrade"
apt update -y || true
apt upgrade -y || true

echo "[+] Install base deps"
apt install -y curl wget jq zip iproute2 lsb-release ufw git uuid-runtime openssl python3

echo "[+] Install stunnel & caddy & speedtest-cli"
apt install -y stunnel4 caddy speedtest-cli || true

echo "[+] Firewall (UFW) – allow SSH/80/81/443/444/446/1080/8081"
ufw allow OpenSSH || true
ufw allow 80/tcp   || true
ufw allow 81/tcp   || true
ufw allow 443/tcp  || true
ufw allow 444/tcp  || true
ufw allow 446/tcp  || true
ufw allow 1080/tcp || true
ufw allow 8081/tcp || true
ufw --force enable || true

#====================[ NET MENU BIN ]====================
cat >/usr/local/bin/net-menu <<'NETMENU'
#!/usr/bin/env bash
set -euo pipefail

need(){ command -v "$1" >/dev/null 2>&1 || { echo "❗ ต้องติดตั้ง: $1"; exit 1; }; }
pause(){ read -rp "กด Enter เพื่อกลับเมนู..."; }
ensure_root(){ [[ $EUID -eq 0 ]] || { echo "กรุณา sudo / รันเป็น root"; exit 1; }; }
sysip(){ curl -fsSL -4 https://ifconfig.co || hostname -I | awk '{print $1}'; }
iface(){ ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'; }

ensure_xray(){
  if ! command -v xray >/dev/null 2>&1; then
    echo "[+] ติดตั้ง Xray-core"
    bash <(curl -fsSL https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh) install
  fi
  install -d /etc/xray
}

# ---------- V2Ray/Xray ----------
install_vless_ws_tls(){  # WS+TLS via Caddy (ต้องมีโดเมน)
  ensure_xray
  read -rp "โดเมน (ต้องชี้ A มายัง IP เครื่องนี้): " DOMAIN
  [[ -z "$DOMAIN" ]] && { echo "ยกเลิก (ต้องใส่โดเมน)"; return; }
  UUID=$(uuidgen); WS_PATH=${WS_PATH:-/ray}; XRAY_PORT=10000
  cat >/etc/xray/config.json <<XR
{
  "inbounds": [{
    "listen": "127.0.0.1",
    "port": ${XRAY_PORT},
    "protocol": "vless",
    "settings": { "decryption": "none", "clients": [{ "id": "${UUID}" }] },
    "streamSettings": { "network": "ws", "wsSettings": { "path": "${WS_PATH}" } }
  }],
  "outbounds": [{ "protocol": "freedom" }]
}
XR
  cat >/etc/caddy/Caddyfile <<CADDY
${DOMAIN} {
    encode zstd gzip
    @vless_ws path ${WS_PATH}
    reverse_proxy @vless_ws 127.0.0.1:${XRAY_PORT}
}
CADDY
  systemctl enable xray --now
  systemctl reload caddy || systemctl enable caddy --now
  LINK="vless://${UUID}@${DOMAIN}:443?encryption=none&security=tls&type=ws&host=${DOMAIN}&path=${WS_PATH}#vless-ws-tls"
  echo "$LINK" | tee /root/vless_ws_tls.txt
  echo "✅ ติดตั้งเสร็จ (WS+TLS) → $LINK"
  pause
}

add_vless_ws_user(){   # เพิ่ม UUID ผู้ใช้ WS+TLS
  need jq; ensure_xray
  [[ -f /etc/xray/config.json ]] || { echo "ไม่พบ /etc/xray/config.json"; pause; return; }
  UUID=$(uuidgen)
  jq --arg id "$UUID" '
    (.inbounds[] | select(.protocol=="vless" and .streamSettings.network=="ws") | .settings.clients) += [{"id":$id}]
  ' /etc/xray/config.json > /etc/xray/config.tmp && mv /etc/xray/config.tmp /etc/xray/config.json
  systemctl restart xray
  DOMAIN=$(grep -E '^[a-z0-9.-]+\s*\{' /etc/caddy/Caddyfile | head -n1 | awk '{print $1}')
  WS_PATH=$(jq -r '.inbounds[] | select(.protocol=="vless" and .streamSettings.network=="ws") | .streamSettings.wsSettings.path' /etc/xray/config.json | head -n1)
  LINK="vless://${UUID}@${DOMAIN}:443?encryption=none&security=tls&type=ws&host=${DOMAIN}&path=${WS_PATH}#extra"
  echo "$LINK" | tee -a /root/vless_ws_tls.txt
  echo "✅ เพิ่มผู้ใช้: $LINK"
  pause
}

install_vless_reality(){ # REALITY (ไม่ต้องโดเมน)
  ensure_xray
  PORT=443; ss -ltn | grep -q ':443 ' && PORT=8443
  KP="$(xray x25519)"; PRIV=$(echo "$KP"|awk '/Private/{print $3}'); PUB=$(echo "$KP"|awk '/Public/{print $3}')
  UUID=$(uuidgen); SNI="www.cloudflare.com"; DEST="www.cloudflare.com:443"
  cat >/etc/xray/config.json <<XR
{
  "inbounds": [{
    "port": ${PORT},
    "protocol": "vless",
    "settings": { "decryption": "none", "clients": [{ "id": "${UUID}" }] },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "show": false, "dest": "${DEST}", "xver": 0,
        "serverNames": ["${SNI}"], "privateKey": "${PRIV}", "shortIds": [""]
      }
    }
  }],
  "outbounds": [{ "protocol": "freedom" }]
}
XR
  systemctl enable xray --now
  IP=$(sysip)
  LINK="vless://${UUID}@${IP}:${PORT}?encryption=none&security=reality&sni=${SNI}&pbk=${PUB}&sid=&type=tcp&fp=chrome#vless-reality"
  echo "$LINK" | tee /root/vless_reality.txt
  echo "✅ REALITY :$PORT → $LINK"
  pause
}

# ---------- stunnel (SSL Tunnel) ----------
ensure_stunnel_cert(){
  install -d /etc/stunnel
  if [[ ! -f /etc/stunnel/stunnel.pem ]]; then
    openssl req -new -x509 -days 3650 -nodes \
      -subj "/CN=$(hostname -f)" \
      -out /etc/stunnel/stunnel.crt \
      -keyout /etc/stunnel/stunnel.key
    cat /etc/stunnel/stunnel.key /etc/stunnel/stunnel.crt > /etc/stunnel/stunnel.pem
    chmod 600 /etc/stunnel/stunnel.pem
  fi
  sed -i 's/ENABLED=0/ENABLED=1/' /etc/default/stunnel4 || true
  systemctl enable stunnel4 --now
}

install_stunnel_ovpn(){ # :444 -> 127.0.0.1:1194
  ensure_stunnel_cert
  OPORT=${1:-444}
  cat >/etc/stunnel/ovpn443.conf <<ST
[openvpn]
accept = ${OPORT}
connect = 127.0.0.1:1194
cert = /etc/stunnel/stunnel.pem
key  = /etc/stunnel/stunnel.pem
ST
  ufw allow ${OPORT}/tcp || true
  systemctl restart stunnel4
  echo "✅ OpenVPN over TLS :${OPORT} -> 1194"
  pause
}

install_stunnel_ssh(){  # :446 -> 127.0.0.1:22
  ensure_stunnel_cert
  SPORT=${1:-446}
  cat >/etc/stunnel/ssh-tls.conf <<ST
[ssh-tls]
accept = ${SPORT}
connect = 127.0.0.1:22
cert = /etc/stunnel/stunnel.pem
key  = /etc/stunnel/stunnel.pem
ST
  ufw allow ${SPORT}/tcp || true
  systemctl restart stunnel4
  echo "✅ SSH over TLS :${SPORT} -> 22"
  pause
}

# ---------- OpenSSH ----------
setup_openssh(){
  apt install -y openssh-server
  SSHCFG="/etc/ssh/sshd_config"
  read -rp "พอร์ต SSH (ค่าเดิมส่วนใหญ่ 22) : " NEWPORT
  NEWPORT=${NEWPORT:-22}
  sed -i -E "s/^#?Port .*/Port ${NEWPORT}/" "$SSHCFG"
  sed -i -E "s/^#?PasswordAuthentication .*/PasswordAuthentication yes/" "$SSHCFG"
  sed -i -E "s/^#?PermitRootLogin .*/PermitRootLogin prohibit-password/" "$SSHCFG"
  ufw allow ${NEWPORT}/tcp || true
  systemctl restart ssh || systemctl restart sshd || true
  echo "✅ ตั้งค่า OpenSSH แล้ว (Port=${NEWPORT}, PasswordAuth=YES)"
  pause
}

# ---------- SOCKS5 (Dante) ----------
install_socks_dante(){
  apt install -y dante-server || apt install -y dante || true
  IF=$(iface); PORT=${1:-1080}
  read -rp "ชื่อผู้ใช้ SOCKS (เช่น socks): " U; U=${U:-socks}
  read -srp "รหัสผ่านสำหรับ ${U}: " P; echo
  id -u "$U" >/dev/null 2>&1 || useradd -M -s /usr/sbin/nologin "$U"
  echo "${U}:${P}" | chpasswd
  for CFG in /etc/danted.conf /etc/dante/sockd.conf; do
    mkdir -p "$(dirname "$CFG")" || true
    cat >"$CFG" <<CONF
logoutput: syslog
internal: 0.0.0.0 port = ${PORT}
external: ${IF}
clientmethod: none
socksmethod: username
user.privileged: root
user.notprivileged: nobody
client pass { from: 0.0.0.0/0 to: 0.0.0.0/0 log: connect disconnect error }
socks  pass { from: 0.0.0.0/0 to: 0.0.0.0/0 command: bind connect udpassociate log: connect disconnect error }
CONF
  done
  ufw allow ${PORT}/tcp || true
  SVC=""; for s in sockd danted dante-server; do systemctl list-unit-files | grep -q "^$s\.service" && SVC="$s"; done
  [[ -z "$SVC" ]] && SVC="sockd"
  systemctl enable "$SVC" || true
  systemctl restart "$SVC" || true
  echo "✅ ติดตั้ง SOCKS5 แล้ว ที่พอร์ต ${PORT}  ผู้ใช้: ${U}"
  pause
}

add_socks_user(){
  read -rp "ชื่อผู้ใช้ใหม่: " U; [[ -z "$U" ]] && { echo "ยกเลิก"; return; }
  read -srp "รหัสผ่านสำหรับ ${U}: " P; echo
  id -u "$U" >/dev/null 2>&1 || useradd -M -s /usr/sbin/nologin "$U"
  echo "${U}:${P}" | chpasswd
  echo "✅ เพิ่มผู้ใช้ SOCKS5: ${U} แล้ว"
  pause
}

# ---------- ONLINE APP (พร้อม Max) ----------
ONLINE_ENV="/etc/online-app.env"

write_online_env(){
  local status="$1" port="$2" max="$3"
  cat > "$ONLINE_ENV" <<EOF
STATUS_LOG=${status}
HOST=0.0.0.0
PORT=${port}
CAPACITY=${max}
EOF
}

install_online_app(){
  STATUS="${1:-/var/log/openvpn/status.log}"
  PORT="${2:-8081}"
  MAXC="${3:-${LICENSED_MAX:-2500}}"

  # เว็บ Python แบบไร้ dependency ภายนอก
  cat >/usr/local/bin/online_app.py <<'PY'
#!/usr/bin/env python3
import os, json, time
from http.server import BaseHTTPRequestHandler, HTTPServer

STATUS_LOG = os.environ.get("STATUS_LOG", "/var/log/openvpn/status.log")
CAPACITY   = int(os.environ.get("CAPACITY", "2500") or "2500")
if CAPACITY < 1: CAPACITY = 1

def read_openvpn_status(path):
    out=[]
    try:
        with open(path,'r') as f:
            for line in f:
                if line.startswith('CLIENT_LIST,'):
                    p=line.strip().split(',')
                    if len(p)>=7:
                        out.append({
                            "user": p[1],
                            "real": p[2],
                            "bytes_recv": int(p[3]),
                            "bytes_sent": int(p[4]),
                            "since": p[5],
                            "virtual": p[6]
                        })
    except Exception:
        pass
    return out

HTML = """<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>ONLINE APP</title>
<style>
body{font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;padding:16px}
.top{display:flex;align-items:center;gap:12px}
.progress{width:260px;height:14px;background:#eee;border-radius:7px;overflow:hidden}
.bar{height:100%;width:{bar}%;background:#3b82f6}
table{border-collapse:collapse;width:100%;margin-top:12px}
th,td{border:1px solid #ddd;padding:8px}th{background:#f5f5f5;text-align:left}
.small{color:#666;font-size:12px}
</style>
</head><body>
<h2>OpenVPN Online</h2>
<div class="top">
  <div><strong>Online:</strong> {count} / {maxc} ({pct:.1f}%)</div>
  <div class="progress"><div class="bar"></div></div>
</div>
<p class="small">Status file: {status}</p>
<table><thead><tr><th>User</th><th>Real IP</th><th>Virtual IP</th><th>Since</th><th>RX</th><th>TX</th></tr></thead><tbody>{rows}</tbody></table>
<p>JSON: <a href='/api/online'>/api/online</a></p>
<script>document.querySelector('.bar').style.width='{bar}%'</script>
</body></html>"""

class H(BaseHTTPRequestHandler):
    def _hdr(self, code=200, ctype='text/html'):
        self.send_response(code); self.send_header('Content-Type', ctype)
        self.send_header('Cache-Control','no-store')
        self.send_header('Access-Control-Allow-Origin','*'); self.end_headers()
    def do_GET(self):
        data = read_openvpn_status(STATUS_LOG)
        count = len(data)
        pct = min(100.0, (count / CAPACITY) * 100.0) if CAPACITY else 0.0
        if self.path.startswith('/api/online'):
            self._hdr(200,'application/json')
            self.wfile.write(json.dumps({
                "online": data, "count": count, "max": CAPACITY,
                "remaining": max(0, CAPACITY-count), "percent": round(pct,2),
                "ts": int(time.time())
            }).encode())
        else:
            rows = ''.join(f"<tr><td>{d['user']}</td><td>{d['real']}</td><td>{d['virtual']}</td><td>{d['since']}</td><td>{d['bytes_recv']}</td><td>{d['bytes_sent']}</td></tr>" for d in data)
            if not rows: rows = "<tr><td colspan='6'>No clients</td></tr>"
            html = HTML.format(status=STATUS_LOG, rows=rows, count=count, maxc=CAPACITY, pct=pct, bar=pct)
            self._hdr(); self.wfile.write(html.encode())

def main():
    host=os.environ.get('HOST','0.0.0.0'); port=int(os.environ.get('PORT','8081'))
    HTTPServer((host,port),H).serve_forever()

if __name__=='__main__': main()
PY
  chmod +x /usr/local/bin/online_app.py

  # environment + service
  write_online_env "$STATUS" "$PORT" "$MAXC"

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
  ufw allow ${PORT}/tcp || true

  # Caddy path :81/online_app -> :${PORT}
  if command -v caddy >/dev/null 2>&1; then
    touch /etc/caddy/Caddyfile
    if ! grep -q "/online_app" /etc/caddy/Caddyfile; then
      cat >>/etc/caddy/Caddyfile <<CADDY
:81 {
    handle_path /online_app* {
        reverse_proxy 127.0.0.1:${PORT}
    }
}
CADDY
      ufw allow 81/tcp || true
      systemctl reload caddy || systemctl enable caddy --now
    fi
  fi

  IP=$(sysip)
  echo "✅ ONLINE APP พร้อมใช้งาน"
  echo " - เว็บ  : http://${IP}:${PORT}/"
  echo " - JSON  : http://${IP}:${PORT}/api/online"
  echo " - Caddy : http://${IP}:81/online_app"
  echo " - Max   : ${MAXC} (สามารถปรับเมนู [23])"
  pause
}

stop_online_app(){ systemctl disable --now online-app.service || true; echo "❎ ปิด ONLINE APP แล้ว"; pause; }

show_online_link(){
  IP=$(sysip)
  PORT=$(grep -E '^PORT=' /etc/online-app.env 2>/dev/null | cut -d= -f2); [[ -z "${PORT:-}" ]] && PORT=8081
  MAX=$(grep -E '^CAPACITY=' /etc/online-app.env 2>/dev/null | cut -d= -f2); [[ -z "${MAX:-}" ]] && MAX=2500
  echo "ลิงก์ ONLINE APP:"
  echo " - http://${IP}:${PORT}/"
  echo " - http://${IP}:${PORT}/api/online"
  if grep -q "/online_app" /etc/caddy/Caddyfile 2>/dev/null; then
    echo " - http://${IP}:81/online_app  (JSON: /online_app/api/online)"
  fi
  echo "Max capacity: ${MAX}"
  pause
}

set_online_capacity(){
  [[ -f /etc/online-app.env ]] || { echo "ยังไม่ติดตั้ง ONLINE APP (ไปเมนู [20] ก่อน)"; pause; return; }
  CUR_MAX=$(grep -E '^CAPACITY=' /etc/online-app.env | cut -d= -f2); [[ -z "${CUR_MAX:-}" ]] && CUR_MAX=2500
  read -rp "กำหนดยอดสูงสุด (Max) ปัจจุบัน=${CUR_MAX} : " NEWMAX
  NEWMAX=${NEWMAX:-$CUR_MAX}
  [[ "$NEWMAX" =~ ^[0-9]+$ ]] && [[ "$NEWMAX" -ge 1 ]] || { echo "ค่าไม่ถูกต้อง"; pause; return; }
  sed -i -E "s/^CAPACITY=.*/CAPACITY=${NEWMAX}/" /etc/online-app.env
  systemctl restart online-app.service
  STATUS=$(grep -E '^STATUS_LOG=' /etc/online-app.env | cut -d= -f2); [[ -z "${STATUS:-}" ]] && STATUS="/var/log/openvpn/status.log"
  X=$(awk -F, '/^CLIENT_LIST/{c++} END{print c+0}' "$STATUS" 2>/dev/null || echo 0)
  PCT=$(awk -v x="$X" -v m="$NEWMAX" 'BEGIN{ if(m<1){print 0}else{printf "%.1f", (x/m)*100} }')
  echo "✅ ตั้งค่า Max=${NEWMAX} แล้ว  (Online ปัจจุบัน: ${X} / ${NEWMAX} = ${PCT}%)"
  pause
}

show_online_ratio(){
  [[ -f /etc/online-app.env ]] || { echo "ยังไม่ติดตั้ง ONLINE APP (ไปเมนู [20] ก่อน)"; pause; return; }
  MAX=$(grep -E '^CAPACITY=' /etc/online-app.env | cut -d= -f2); [[ -z "${MAX:-}" ]] && MAX=2500
  STATUS=$(grep -E '^STATUS_LOG=' /etc/online-app.env | cut -d= -f2); [[ -z "${STATUS:-}" ]] && STATUS="/var/log/openvpn/status.log"
  X=$(awk -F, '/^CLIENT_LIST/{c++} END{print c+0}' "$STATUS" 2>/dev/null || echo 0)
  PCT=$(awk -v x="$X" -v m="$MAX" 'BEGIN{ if(m<1){print 0}else{printf "%.1f", (x/m)*100} }')
  echo "ออนไลน์ตอนนี้: ${X} / ${MAX}  (${PCT}%)"
  pause
}

# ---------- EXTRAS ----------
show_links(){
  echo "=== ลิงก์/ไฟล์ที่บันทึกไว้ ==="
  [[ -f /root/vless_ws_tls.txt ]]   && echo "VLESS WS+TLS:   $(tail -n1 /root/vless_ws_tls.txt)"
  [[ -f /root/vless_reality.txt ]] && echo "VLESS REALITY:  $(tail -n1 /root/vless_reality.txt)"
  [[ -f /etc/xray/config.json ]]   && echo " - /etc/xray/config.json"
  [[ -f /etc/caddy/Caddyfile ]]    && echo " - /etc/caddy/Caddyfile"
  [[ -f /etc/stunnel/ovpn443.conf ]] && echo " - /etc/stunnel/ovpn443.conf"
  [[ -f /etc/stunnel/ssh-tls.conf ]]  && echo " - /etc/stunnel/ssh-tls.conf"
  [[ -f /etc/danted.conf ]]           && echo " - /etc/danted.conf"
  [[ -f /etc/dante/sockd.conf ]]      && echo " - /etc/dante/sockd.conf"
  [[ -f /etc/systemd/system/online-app.service ]] && echo " - /usr/local/bin/online_app.py + /etc/online-app.env"
  echo "IP: $(sysip)"
  pause
}

extras(){
  echo "[1] รีสตาร์ต xray   [2] รีโหลด caddy   [3] ดู log xray"
  echo "[4] รีสตาร์ต stunnel [5] เช็ค service SOCKS   [6] system info"
  read -rp "เลือก: " k
  case "$k" in
    1) systemctl restart xray; journalctl -u xray -n 30 --no-pager;;
    2) systemctl reload caddy || systemctl restart caddy; journalctl -u caddy -n 30 --no-pager;;
    3) journalctl -u xray -n 80 --no-pager;;
    4) systemctl restart stunnel4; journalctl -u stunnel4 -n 50 --no-pager;;
    5) for s in sockd danted dante-server; do systemctl status $s --no-pager 2>/dev/null && break; done;;
    6) echo "OS: $(grep PRETTY_NAME /etc/os-release|cut -d= -f2-|tr -d '"')  Kernel: $(uname -r)  IP: $(sysip)";;
  esac
  pause
}

menu(){
  clear
  echo "== NET MENU =="
  echo " * [1]  : ติดตั้ง V2Ray/Xray (VLESS WS+TLS via Caddy)  :443"
  echo " * [2]  : เพิ่มผู้ใช้ VLESS (WS+TLS)"
  echo " * [3]  : ติดตั้ง V2Ray/Xray (VLESS REALITY)           :443(หรือ 8443)"
  echo " * [4]  : ติดตั้ง OpenVPN over TLS (stunnel)           :444 -> 1194"
  echo " * [5]  : ติดตั้ง SSH over TLS (stunnel)               :446 -> 22"
  echo " * [6]  : แสดงลิงก์/ไฟล์คอนฟิก"
  echo " --"
  echo " * [10] : ติดตั้ง/ตั้งค่า OpenSSH (เปลี่ยนพอร์ต/เปิด PasswordAuth)"
  echo " * [11] : ติดตั้ง SOCKS5 Proxy (Dante) + สร้างผู้ใช้"
  echo " * [12] : เพิ่มผู้ใช้ SOCKS5 เพิ่มเติม"
  echo " --"
  echo " * [20] : 🔵 ONLINE APP — เปิดใช้งาน (สร้างลิ้งก์เช็คออนไลน์)"
  echo " * [21] : ⛔ ONLINE APP — ปิดใช้งาน"
  echo " * [22] : 🔗 ONLINE APP — แสดงลิ้งก์"
  echo " * [23] : ⚙️  ONLINE APP — ตั้งค่า 'ยอดสูงสุด (Max)'"
  echo " * [24] : 📊 ONLINE APP — แสดง x / Max (%) ตอนนี้"
  echo " --"
  echo " * [99] : เมนูเสริม/ดู log"
  echo " * [00] : ออก"
  read -rp "เลือกเมนู: " c
  case "$c" in
    1) install_vless_ws_tls ;;
    2) add_vless_ws_user ;;
    3) install_vless_reality ;;
    4) read -rp "พอร์ตรับ TLS สำหรับ OpenVPN (ดีฟอลต์ 444): " P; install_stunnel_ovpn "${P:-444}" ;;
    5) read -rp "พอร์ตรับ TLS สำหรับ SSH (ดีฟอลต์ 446): " P; install_stunnel_ssh  "${P:-446}" ;;
    6) show_links ;;
    10) setup_openssh ;;
    11) read -rp "พอร์ต SOCKS5 (ดีฟอลต์ 1080): " SP; install_socks_dante "${SP:-1080}" ;;
    12) add_socks_user ;;
    20) read -rp "พอร์ตเว็บ (ดีฟอลต์ 8081): " WP; read -rp "พาธ status.log (ดีฟอลต์ /var/log/openvpn/status.log): " ST; read -rp "กำหนด Max เริ่มต้น (ว่าง = ใช้จาก License: ${LICENSED_MAX:-2500}): " MX; install_online_app "${ST:-/var/log/openvpn/status.log}" "${WP:-8081}" "${MX:-${LICENSED_MAX:-2500}}" ;;
    21) stop_online_app ;;
    22) show_online_link ;;
    23) set_online_capacity ;;
    24) show_online_ratio ;;
    99) extras ;;
    0|00) exit 0 ;;
    *) echo "เมนูไม่ถูกต้อง"; sleep 1 ;;
  esac
}

ensure_root
while true; do menu; done
NETMENU
#===================[ END NET MENU BIN ]===================

chmod 755 /usr/local/bin/net-menu
echo "[+] เสร็จแล้ว — เรียกเมนูด้วยคำสั่ง:  net-menu"
/usr/local/bin/net-menu

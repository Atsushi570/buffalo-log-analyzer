// Buffalo AirStation ログのパーサ。
// 行形式: "YYYY/MM/DD HH:MM:SS<空白>CATEGORY\t message"
// 解析は全てブラウザ内で行い、ログを外部へ送信しない。

const LINE_RE = /^(\d{4})\/(\d{2})\/(\d{2})\s+(\d{2}):(\d{2}):(\d{2})\s+([A-Z0-9-]+)\s+(.*)$/;
const HEADER_MODEL_RE = /^#\s*Model=\s*(.+?)\s*$/;
const HEADER_MAC_RE = /^#\s*LAN MAC=\s*(.+?)\s*$/;
const HEADER_DATE_RE = /^#\s*Date=\s*(.+?)\s*$/;

// 機器が時刻同期前に吐いた行の目印。NTP前は 2025/01/01 に固定される。
const PRE_NTP_YEAR = 2025;

export const EVENT_DEFS = [
  // --- DHCP クライアント側（この機器が上位からIPを貰う動き）---
  { id: 'dhcpc_bound',     cat: 'DHCPC', label: 'IP取得完了 (bound)',      kind: 'dhcp',  severity: 'info',
    re: /^bound to (\S+) -- renewal in (\d+) seconds/ , fields: m => ({ ip: m[1], renewal: +m[2] }) },
  { id: 'dhcpc_release',   cat: 'DHCPC', label: 'IP解放 (RELEASE)',        kind: 'dhcp',  severity: 'warn',
    re: /^DHCPRELEASE on (\S+) to (\S+)/, fields: m => ({ iface: m[1], server: m[2] }) },
  { id: 'dhcpc_discover',  cat: 'DHCPC', label: 'IP要求開始 (DISCOVER)',   kind: 'dhcp',  severity: 'info',
    re: /^DHCPDISCOVER on (\S+)/, fields: m => ({ iface: m[1] }) },
  { id: 'dhcpc_request',   cat: 'DHCPC', label: 'IP要求 (REQUEST)',        kind: 'dhcp',  severity: 'info',
    re: /^DHCPREQUEST on (\S+)/, fields: m => ({ iface: m[1] }) },
  { id: 'dhcpc_offer',     cat: 'DHCPC', label: 'IP提示 (OFFER)',          kind: 'dhcp',  severity: 'info',
    re: /^DHCPOFFER from (\S+)/, fields: m => ({ from: m[1] }) },
  { id: 'dhcpc_ack',       cat: 'DHCPC', label: 'IP確定 (ACK)',            kind: 'dhcp',  severity: 'info',
    re: /^DHCPACK from (\S+)/, fields: m => ({ from: m[1] }) },
  { id: 'dhcpc_nak',       cat: 'DHCPC', label: 'IP拒否 (NAK)',            kind: 'dhcp',  severity: 'error',
    re: /^DHCPNAK/ },
  { id: 'dhcpc_arping_eintr', cat: 'DHCPC', label: 'ARPING中断(良性)',      kind: 'dhcp',  severity: 'info', noise: true,
    re: /^Error on ARPING request: Interrupted system call/ },
  { id: 'dhcpc_arping_err',cat: 'DHCPC', label: 'ARPINGエラー',            kind: 'dhcp',  severity: 'warn',
    re: /^Error on ARPING request: (.+)$/, fields: m => ({ detail: m[1] }) },
  { id: 'dhcpc_v6',        cat: 'DHCPC', label: 'DHCPv6 情報要求',         kind: 'dhcp',  severity: 'info', noise: true,
    re: /^(?:XMT:|RCV:|PRC:)/ },
  { id: 'dhcpc_detail',    cat: 'DHCPC', label: 'DHCPC付随ログ',           kind: 'dhcp',  severity: 'info', noise: true,
    re: /^adapter index/ },

  // --- DHCP サーバ側（この機器が配るIP。子機ごとの動き）---
  { id: 'dhcps_discover',  cat: 'DHCPS', label: '子機からの要求 (DISCOVER)', kind: 'dhcp', severity: 'info',
    re: /^DHCPDISCOVER from ([0-9a-f:]+)(?: \(([^)]*)\))? via (\S+)/, fields: m => ({ mac: m[1], host: m[2], via: m[3] }) },
  { id: 'dhcps_offer',     cat: 'DHCPS', label: 'IP提示 (OFFER)',          kind: 'dhcp',  severity: 'info',
    re: /^DHCPOFFER on (\S+) to ([0-9a-f:]+)(?: \(([^)]*)\))? via (\S+)/, fields: m => ({ ip: m[1], mac: m[2], host: m[3], via: m[4] }) },
  { id: 'dhcps_request',   cat: 'DHCPS', label: 'IP要求 (REQUEST)',        kind: 'dhcp',  severity: 'info',
    re: /^DHCPREQUEST for (\S+?)(?: \(([^)]*)\))? from ([0-9a-f:]+)(?: \(([^)]*)\))? via (\S+)/,
    fields: m => ({ ip: m[1], mac: m[3], host: m[4], via: m[5] }) },
  { id: 'dhcps_ack',       cat: 'DHCPS', label: 'IP確定 (ACK)',            kind: 'dhcp',  severity: 'info',
    re: /^DHCPACK on (\S+) to ([0-9a-f:]+)(?: \(([^)]*)\))? via (\S+)/, fields: m => ({ ip: m[1], mac: m[2], host: m[3], via: m[4] }) },
  { id: 'dhcps_release',   cat: 'DHCPS', label: '子機がIP解放 (RELEASE)',  kind: 'dhcp',  severity: 'info',
    re: /^DHCPRELEASE of (\S+) from ([0-9a-f:]+)(?: \(([^)]*)\))? via (\S+)/, fields: m => ({ ip: m[1], mac: m[2], host: m[3], via: m[4] }) },
  { id: 'dhcps_nak',       cat: 'DHCPS', label: 'IP拒否 (NAK)',            kind: 'dhcp',  severity: 'error',
    re: /^DHCPNAK on (\S+) to ([0-9a-f:]+)/, fields: m => ({ ip: m[1], mac: m[2] }) },
  // 「プールが定義されていない」と「空きが無い」は別物。
  // 前者（特にIPv6）はRA/SLAACで配る構成なら正常な動作であり、枯渇ではない。
  { id: 'dhcps_no_pool',   cat: 'DHCPS', label: 'DHCPプール未設定',         kind: 'dhcp',  severity: 'info', noise: true,
    re: /^Unable to pick client address: no (IPv6|IPv4)? ?pools? on this shared network/,
    fields: m => ({ family: m[1] || 'IPv4' }) },
  { id: 'dhcps_pool_empty',cat: 'DHCPS', label: 'IPプール枯渇',            kind: 'dhcp',  severity: 'critical',
    re: /^(?:Unable to pick client address: (?!no (?:IPv6|IPv4)? ?pools? on)|no free leases|No free leases)(.*)$/,
    fields: m => ({ detail: (m[1] || '').trim() }) },
  { id: 'dhcps_no_free',   cat: 'DHCPS', label: '空きリースなし',           kind: 'dhcp',  severity: 'critical',
    re: /^(?:peer holds all free leases|no address available|out of leases)/ },
  // Interrupted system call (EINTR) はシステムコールが割り込まれただけで、
  // IP競合ではない。直後にDHCPのやりとりが正常完了する。
  { id: 'dhcps_arping_eintr', cat: 'DHCPS', label: 'ARPING中断(良性)',      kind: 'dhcp',  severity: 'info', noise: true,
    re: /^Error on ARPING request: Interrupted system call/ },
  { id: 'dhcps_arping_err',cat: 'DHCPS', label: 'ARPINGエラー',            kind: 'dhcp',  severity: 'warn',
    re: /^Error on ARPING request: (.+)$/, fields: m => ({ detail: m[1] }) },
  { id: 'dhcps_v6_info',   cat: 'DHCPS', label: 'DHCPv6 情報要求',         kind: 'dhcp',  severity: 'info', noise: true,
    re: /^(?:Information-request message|Sending Reply|Solicit message|Sending Advertise)/ },
  { id: 'dhcps_v6_unknown',cat: 'DHCPS', label: 'DHCPv6 不明メッセージ',   kind: 'dhcp',  severity: 'warn',
    re: /^(?:Discarding unknown DHCPv6 message type|Unknown message type) (\d+) from (\S+)/, fields: m => ({ type: m[1], from: m[2] }) },

  // --- Wi-Fi 認証（子機の接続）---
  { id: 'auth_ok',         cat: 'AUTH',  label: 'Wi-Fi認証成功',           kind: 'wifi',  severity: 'info',
    re: /^(\S+?): Authenticated User - ([0-9a-f:]+)/, fields: m => ({ iface: m[1], mac: m[2] }) },
  { id: 'auth_fail',       cat: 'AUTH',  label: 'Wi-Fi認証失敗',           kind: 'wifi',  severity: 'error',
    re: /^(\S+?): (?:Authentication failed|Failed)/, fields: m => ({ iface: m[1] }) },
  { id: 'auth_deauth',     cat: 'AUTH',  label: 'Wi-Fi切断 (Deauth)',      kind: 'wifi',  severity: 'warn',
    re: /^(\S+?): (?:Deauthenticated|Disassociated)\D*([0-9a-f:]+)?/, fields: m => ({ iface: m[1], mac: m[2] }) },

  // --- 有線リンク ---
  { id: 'wired_up',        cat: 'WIRED', label: '有線リンクUP',            kind: 'link',  severity: 'info',
    re: /^Link Status Changed - (\S+) Link UP/, fields: m => ({ port: m[1] }) },
  { id: 'wired_down',      cat: 'WIRED', label: '有線リンクDOWN',          kind: 'link',  severity: 'warn',
    re: /^Link Status Changed - (\S+) Link DOWN/, fields: m => ({ port: m[1] }) },

  // --- NTP 時刻同期（上位到達性の代理指標）---
  { id: 'ntp_ok',          cat: 'NTP',   label: 'NTP同期成功',             kind: 'ntp',   severity: 'info',
    re: /^SUCCESS: set time/ },
  { id: 'ntp_unknown_host',cat: 'NTP',   label: 'NTP名前解決失敗',         kind: 'ntp',   severity: 'error',
    re: /^(\S+) : Unknown host/, fields: m => ({ host: m[1] }) },
  { id: 'ntp_start',       cat: 'NTP',   label: 'NTP同期開始',             kind: 'ntp',   severity: 'info',
    re: /^start ntpclient/ },
  { id: 'ntp_detail',      cat: 'NTP',   label: 'NTP付随ログ',             kind: 'ntp',   severity: 'info', noise: true,
    re: /^(?:probe_count=|ntp server address|exit ntpclient)/ },

  // --- 起動・システム ---
  { id: 'boot',            cat: 'BOOT',  label: '機器の再起動',            kind: 'system', severity: 'critical',
    re: /^(.+)$/, fields: m => ({ model: m[1] }) },
  { id: 'sys_link_undetected', cat: 'SYSTEM', label: 'リンクUP未検出',      kind: 'system', severity: 'warn',
    re: /^\[LINK\|\w+\] Undetected link-up/ },
  { id: 'sys_mape',        cat: 'SYSTEM', label: 'MAP-E ルール受信',        kind: 'system', severity: 'info',
    re: /^\[MAP-E\|\w+\] (.+)$/, fields: m => ({ detail: m[1] }) },
  { id: 'sys_route',       cat: 'SYSTEM', label: '経路情報受信',            kind: 'system', severity: 'info',
    re: /^\[NRI\|\w+\] (.+)$/, fields: m => ({ detail: m[1] }) },
  { id: 'sys_conf',        cat: 'SYSTEM', label: '設定チェック',            kind: 'system', severity: 'info', noise: true,
    re: /^\[CONF\|\w+\] (.+)$/, fields: m => ({ detail: m[1] }) },
];

// BOOT の総取りパターンを最後に回すため、カテゴリ別に索引しておく。
const DEFS_BY_CAT = EVENT_DEFS.reduce((acc, d) => {
  (acc[d.cat] ||= []).push(d);
  return acc;
}, {});

export const EVENT_DEF_BY_ID = new Map(EVENT_DEFS.map(d => [d.id, d]));

export const SEVERITY_ORDER = ['critical', 'error', 'warn', 'info'];

/** 1ファイル分のログを解析する。戻り値の events は時刻昇順。 */
export function parseLog(text, fileName = '') {
  const meta = { fileName, model: '', mac: '', exportDate: '', role: guessRole(fileName) };
  const events = [];
  const unparsed = [];
  let total = 0;

  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trimEnd();
    if (!line) continue;

    if (line.startsWith('#')) {
      const model = HEADER_MODEL_RE.exec(line);
      if (model) { meta.model = model[1]; continue; }
      const mac = HEADER_MAC_RE.exec(line);
      if (mac) { meta.mac = mac[1]; continue; }
      const date = HEADER_DATE_RE.exec(line);
      if (date) { meta.exportDate = date[1]; continue; }
      continue;
    }

    const m = LINE_RE.exec(line);
    if (!m) { unparsed.push(line); continue; }
    total++;

    const [, y, mo, d, h, mi, s, cat, message] = m;
    const year = +y;
    const ts = new Date(year, +mo - 1, +d, +h, +mi, +s);
    const def = matchDef(cat, message);

    events.push({
      ts,
      t: ts.getTime(),
      cat,
      message,
      id: def ? def.id : `other_${cat.toLowerCase()}`,
      label: def ? def.label : `${cat} その他`,
      kind: def ? def.kind : 'other',
      severity: def ? def.severity : 'info',
      noise: def ? !!def.noise : false,
      fields: def && def.fields ? def.fields(def.re.exec(message)) : {},
      preNtp: year <= PRE_NTP_YEAR,
      src: fileName,
    });
  }

  events.sort((a, b) => a.t - b.t);
  return { meta, events, total, unparsed };
}

function matchDef(cat, message) {
  const defs = DEFS_BY_CAT[cat];
  if (!defs) return null;
  for (const def of defs) {
    if (def.re.test(message)) return def;
  }
  return null;
}

/** ファイル名から役割を推測する。AP機かルーター機かでグラフの読み方が変わる。 */
function guessRole(fileName) {
  const n = fileName.toLowerCase();
  if (n.includes('router')) return 'ルーター';
  if (n.includes('_ap') || n.includes('ap_')) return 'AP';
  return '';
}

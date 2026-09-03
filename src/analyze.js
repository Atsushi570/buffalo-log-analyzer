// 解析エンジン。頻度集計・異常時間帯の検出・トラブル兆候の判定を行う。

import { SEVERITY_ORDER } from './parser.js';

const HOUR_MS = 3600_000;

/** 時刻を時間バケットの開始時刻に丸める。 */
function floorTo(t, bucketMs) {
  return Math.floor(t / bucketMs) * bucketMs;
}

/**
 * 複数ファイルの解析結果を1つのデータセットにまとめる。
 * @param {Array<{meta:object, events:Array}>} logs
 */
export function buildDataset(logs) {
  const devices = logs.map((log, i) => ({
    idx: i,
    name: deviceName(log.meta, i),
    meta: log.meta,
    events: log.events,
  }));

  const all = devices.flatMap(d => d.events.map(e => ({ ...e, dev: d.idx })));
  all.sort((a, b) => a.t - b.t);

  // NTP同期前（2025/01/01固定）の行は時間軸を歪めるので範囲計算から除く。
  const dated = all.filter(e => !e.preNtp);
  const range = dated.length
    ? { from: dated[0].t, to: dated[dated.length - 1].t }
    : { from: 0, to: 0 };

  return { devices, events: all, range, preNtpCount: all.length - dated.length };
}

/** 指定範囲・条件でイベントを絞り込む。 */
export function filterEvents(dataset, { from, to, devices, kinds, severities, includeNoise, mac } = {}) {
  return dataset.events.filter(e => {
    if (e.preNtp) return false;
    if (from != null && e.t < from) return false;
    if (to != null && e.t > to) return false;
    if (devices && !devices.has(e.dev)) return false;
    if (kinds && !kinds.has(e.kind)) return false;
    if (severities && !severities.has(e.severity)) return false;
    if (!includeNoise && e.noise) return false;
    if (mac && e.fields.mac !== mac) return false;
    return true;
  });
}

/** イベント種別ごとの発生件数。頻度表の元データ。 */
export function countByEvent(events) {
  const map = new Map();
  for (const e of events) {
    const cur = map.get(e.id) || { id: e.id, label: e.label, kind: e.kind, severity: e.severity, count: 0, first: e.t, last: e.t };
    cur.count++;
    if (e.t < cur.first) cur.first = e.t;
    if (e.t > cur.last) cur.last = e.t;
    map.set(e.id, cur);
  }
  return [...map.values()].sort((a, b) =>
    SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) || b.count - a.count);
}

/**
 * 時系列ビン。指定した系列ごとに件数を数える。
 * @param {Array} events
 * @param {number} bucketMs ビン幅（ミリ秒）
 * @param {Array<{key:string,label:string,test:Function}>} series
 */
export function timeSeries(events, bucketMs, series, range) {
  const bins = new Map();
  const ensure = t => {
    let b = bins.get(t);
    if (!b) {
      b = { t, total: 0 };
      for (const s of series) b[s.key] = 0;
      bins.set(t, b);
    }
    return b;
  };

  // 範囲全体を空ビンで埋める。空白期間もグラフ上で「無かった」と読めるようにする。
  if (range && range.to > range.from) {
    const start = floorTo(range.from, bucketMs);
    const end = floorTo(range.to, bucketMs);
    // ビン数が過大にならないよう上限を設ける。
    if ((end - start) / bucketMs <= 20000) {
      for (let t = start; t <= end; t += bucketMs) ensure(t);
    }
  }

  for (const e of events) {
    const b = ensure(floorTo(e.t, bucketMs));
    b.total++;
    for (const s of series) {
      if (s.test(e)) b[s.key]++;
    }
  }
  return [...bins.values()].sort((a, b) => a.t - b.t);
}

/**
 * 異常時間帯の検出。各ビンの件数を全体の中央値・MADと比較し、
 * 突出したビンを「異常」として返す。平均+標準偏差ではなく中央値+MADを使うのは、
 * 異常値そのものに指標が引っ張られないようにするため。
 */
export function findAnomalies(bins, key = 'total', { minCount = 3, k = 4 } = {}) {
  const vals = bins.map(b => b[key]);
  // 何も起きていない空ビンを含めて中央値を取ると基準が0に張り付き、
  // 「平常の300倍」のような誇張された倍率になる。稼働しているビンだけを平常時とみなす。
  const active = vals.filter(v => v > 0);
  const med = median(active);
  const mad = median(active.map(v => Math.abs(v - med))) || 1;
  const threshold = Math.max(med + k * mad, minCount);
  const baseline = med || 1;

  return bins
    .filter(b => b[key] >= threshold && b[key] > 0)
    .map(b => ({ t: b.t, count: b[key], threshold, median: med, ratio: b[key] / baseline }))
    .sort((a, b) => b.count - a.count);
}

/**
 * 倍率の言い回し。平常時の件数が少ないと倍率は極端な値になり
 * （例: 2件→118件で59倍）数字が独り歩きするため、上限を設けてぼかす。
 */
function ratioText(ratio) {
  if (!isFinite(ratio) || ratio <= 1.5) return '';
  if (ratio >= 20) return '・平常より大幅に多い';
  return `・平常の約${ratio.toFixed(0)}倍`;
}

function median(arr) {
  if (!arr.length) return 0;
  const s = [...arr].sort((a, b) => a - b);
  const mid = s.length >> 1;
  return s.length % 2 ? s[mid] : (s[mid - 1] + s[mid]) / 2;
}

/**
 * DHCPリース更新の異常検出。
 * bound 時の renewal 値（=次の更新までの秒数）に対し、実際に次の bound が
 * 極端に早く来ていれば「リースが保たれていない」＝不安定と判定する。
 */
export function dhcpLeaseChurn(events) {
  const bounds = events.filter(e => e.id === 'dhcpc_bound').sort((a, b) => a.t - b.t);
  // 自発的なリース返却。これが再取得の直前にあるかで原因の所在が変わる。
  const releases = events.filter(e => e.id === 'dhcpc_release').sort((a, b) => a.t - b.t);
  const naks = events.filter(e => e.id === 'dhcpc_nak');

  const cycles = [];
  for (let i = 1; i < bounds.length; i++) {
    const prev = bounds[i - 1];
    const gapSec = (bounds[i].t - prev.t) / 1000;
    // renewal の値は T1（更新開始時刻）。次の更新はこの時間後に来るのが正常。
    const expected = prev.fields.renewal || 0;
    // 直前(5分以内)に自分がRELEASEを送っていたか。
    const selfReleased = releases.some(r => r.t > prev.t && r.t < bounds[i].t
      && bounds[i].t - r.t <= 300_000);
    cycles.push({
      t: bounds[i].t,
      gapSec,
      expected,
      selfReleased,
      // 想定更新間隔の25%未満で再取得していたら早すぎる＝異常。
      premature: expected > 0 && gapSec < expected * 0.25,
    });
  }
  const premature = cycles.filter(c => c.premature);
  const selfReleasedCount = premature.filter(c => c.selfReleased).length;
  const t1 = bounds.length ? median(bounds.map(b => b.fields.renewal || 0)) : 0;
  return {
    bindCount: bounds.length,
    cycles,
    prematureCount: premature.length,
    medianGapSec: median(cycles.map(c => c.gapSec)),
    // T1（更新までの時間）。ログに出るのはこの値。
    t1Sec: t1,
    // RFC 2131 では T1 = リース期間の約50%。リース期間はログに出ないため推定値。
    estimatedLeaseSec: t1 ? t1 * 2 : 0,
    // 早期再取得のうち、自分でRELEASEを送っていた件数。
    selfReleasedCount,
    nakCount: naks.length,
    // 期間中にIPが変わったか（競合や別サブネットへの移動の手がかり）。
    boundIps: [...new Set(bounds.map(b => b.fields.ip).filter(Boolean))],
  };
}

/** 子機（MAC）ごとの挙動集計。特定端末が原因か切り分けるために使う。 */
export function perClient(events) {
  const map = new Map();
  for (const e of events) {
    const mac = e.fields.mac;
    if (!mac) continue;
    const cur = map.get(mac) || {
      mac, host: '', total: 0, auth: 0, dhcpReq: 0, dhcpAck: 0, dhcpRelease: 0, nak: 0,
      // 期間中に割り当てられたIPを、確定(ACK)したものとそれ以外に分けて保持する。
      // 同じ子機のIPが期間中に変わるのは、リースが維持できていない兆候。
      ipHits: new Map(), ipLast: new Map(), ipSeen: new Set(),
      first: e.t, last: e.t,
    };
    if (e.fields.host && !cur.host) cur.host = e.fields.host;
    cur.total++;
    if (e.id === 'auth_ok') cur.auth++;
    if (e.id === 'dhcps_request') cur.dhcpReq++;
    if (e.id === 'dhcps_ack') cur.dhcpAck++;
    if (e.id === 'dhcps_release') cur.dhcpRelease++;
    if (e.id === 'dhcps_nak' || e.id === 'dhcpc_nak') cur.nak++;

    const ip = e.fields.ip;
    if (ip) {
      cur.ipSeen.add(ip);
      // ACK は「実際に確定したIP」。OFFER/REQUEST は候補にとどまるため区別する。
      if (e.id === 'dhcps_ack') {
        cur.ipHits.set(ip, (cur.ipHits.get(ip) || 0) + 1);
        cur.ipLast.set(ip, Math.max(cur.ipLast.get(ip) || 0, e.t));
      }
    }

    cur.first = Math.min(cur.first, e.t);
    cur.last = Math.max(cur.last, e.t);
    map.set(mac, cur);
  }

  for (const c of map.values()) {
    // 最後に確定したIPを代表として見せる。確定が無ければ候補から補う。
    const acked = [...c.ipLast.entries()].sort((a, b) => b[1] - a[1]);
    c.ip = acked.length ? acked[0][0] : ([...c.ipSeen][0] || '');
    c.ipConfirmed = acked.length > 0;
    c.ipCount = acked.length || c.ipSeen.size;
    c.ipHistory = acked.length
      ? acked.map(([ip, t]) => ({ ip, last: t, hits: c.ipHits.get(ip) || 0 }))
      : [...c.ipSeen].map(ip => ({ ip, last: c.last, hits: 0 }));
    delete c.ipHits; delete c.ipLast; delete c.ipSeen;
  }
  return [...map.values()].sort((a, b) => b.total - a.total);
}

/**
 * トラブル兆候の判定。数値の羅列ではなく「何が起きているか」を文章で返す。
 * トラブルシュート時に最初に読む部分。
 */
export function diagnose(dataset, events, bins) {
  const findings = [];
  const byId = id => events.filter(e => e.id === id);
  const spanHours = Math.max((dataset.range.to - dataset.range.from) / HOUR_MS, 1);
  const spanDays = Math.max(spanHours / 24, 1 / 24);

  // --- 1. AP自身のDHCPリースが保たれているか ---
  for (const dev of dataset.devices) {
    const devEvents = events.filter(e => e.dev === dev.idx);
    const churn = dhcpLeaseChurn(devEvents);
    if (churn.prematureCount >= 3) {
      // 障害が特定日に集中している場合、全期間で割ると実態が薄まる。
      // 実際に発生した日だけを母数にする。
      const days = new Set(churn.cycles.filter(c => c.premature)
        .map(c => new Date(c.t).toDateString()));
      const worstDay = worstDayOf(churn.cycles.filter(c => c.premature));
      // 大半が自発的なRELEASE起点なら、リースを「失った」のではなく「自分で返している」。
      // 原因の所在（上位側か自機側か）が正反対になるため、必ず区別する。
      const mostlySelf = churn.selfReleasedCount >= churn.prematureCount * 0.8;
      const ipStable = churn.boundIps.length === 1;

      const common = `${churn.prematureCount}回、更新予定（T1 約${fmtDur(churn.t1Sec)}`
        + `／推定リース期間 約${fmtDur(churn.estimatedLeaseSec)}）より極端に早くIPを再取得している`
        + `（間隔の中央値 ${fmtDur(churn.medianGapSec)}）。`
        + `発生は${days.size}日間に集中し、最多の日は ${worstDay.date}（${worstDay.count}回）。`;

      findings.push({
        severity: churn.prematureCount >= 20 ? 'critical' : 'error',
        kind: 'dhcp',
        title: mostlySelf
          ? `${dev.name}: IPの解放と再取得を繰り返している`
          : `${dev.name}: DHCPリースが保持できていない`,
        detail: mostlySelf
          ? common
            + `うち${churn.selfReleasedCount}回は直前に自機がDHCPRELEASE（自発的なリース返却）を`
            + `送っており、リースを失ったのではなく自ら返して取り直している。`
            + (ipStable
              ? `IPは${churn.boundIps[0]}のまま変わらず、DHCPNAKも${churn.nakCount}件のため、`
                + `IP競合やサーバ側の拒否は考えにくい。`
              : '')
            + `${dev.name}自身でインターフェースの再初期化が繰り返されている可能性が高い。`
          : common
            + `DHCPRELEASEを伴わない再取得が主で、リースを保持できていない。`,
        hint: mostlySelf
          ? `原因は上位側ではなく${dev.name}自身にある可能性が高い。`
            + `同時刻の有線リンク断の有無、ファームウェア版数、省電力／無線設定の自動変更、`
            + `熱やACアダプタの不安定を確認する。同時刻に他機器のログが静かなら自機側を優先して切り分ける。`
          : 'ルーター側のDHCPリース設定と、機器間の有線リンク／電波状況を確認する。固定IP化で切り分け可能。',
        count: churn.prematureCount,
      });
    }
  }

  // --- 2. NTP同期失敗（上位ネットワーク到達性の代理指標）---
  const ntpFail = byId('ntp_unknown_host');
  const ntpOk = byId('ntp_ok');
  if (ntpFail.length >= 3) {
    // 失敗の直後(10分以内)に成功しているかを見る。回復しているなら一時的な
    // 名前解決の失敗であり、「通信が切れていた」と断定はできない。
    const recovered = ntpFail.filter(f =>
      ntpOk.some(ok => ok.t > f.t && ok.t - f.t <= 600_000)).length;
    const mostlyRecovered = recovered >= ntpFail.length * 0.7;
    findings.push({
      severity: mostlyRecovered ? 'warn' : 'error',
      kind: 'ntp',
      title: mostlyRecovered
        ? 'NTPの名前解決が一時的に失敗している'
        : 'NTPの名前解決が繰り返し失敗し、回復していない',
      detail: `${ntpFail.length}回失敗（同期成功は${ntpOk.length}回）。`
        + (mostlyRecovered
          ? `うち${recovered}回は10分以内に同期成功しており、一時的な失敗にとどまっている。`
            + `DHCPの再取得直後はDNSが引けずに失敗しやすいため、IP再取得が多い場合はその副作用の可能性が高い。`
          : `失敗後に同期成功が続かない区間があり、DNSまたは上位回線への到達性に問題がある可能性がある。`),
      hint: 'DHCPでの再取得と同時刻に集中していれば、NTP失敗は結果であって原因ではない。まずDHCP側を見る。',
      count: ntpFail.length,
    });
  }

  // --- 3. 機器の再起動 ---
  const boots = byId('boot');
  if (boots.length) {
    findings.push({
      severity: 'critical',
      kind: 'system',
      title: `機器の再起動を${boots.length}回検出`,
      detail: `再起動時刻: ${boots.map(b => fmtDateTime(b.ts)).join('、')}。`
        + `意図しない再起動であれば電源・熱・ファームウェアの問題が疑われる。`,
      hint: '再起動直後はログの時刻が2025/01/01固定になるため、その区間の時刻は信頼できない。',
      count: boots.length,
    });
  }

  // --- 4. 有線リンクのフラップ ---
  const linkDown = byId('wired_down');
  if (linkDown.length >= 2) {
    const byPort = {};
    for (const e of linkDown) byPort[e.fields.port] = (byPort[e.fields.port] || 0) + 1;
    const worst = Object.entries(byPort).sort((a, b) => b[1] - a[1]);
    // リンク断の直後(60秒以内)にDHCPの再取得が起きているかを見る。
    // 連動していれば、IP再取得の原因が有線側にあると言える。
    const releases = events.filter(e => e.id === 'dhcpc_release' || e.id === 'dhcpc_discover');
    const correlated = linkDown.filter(d =>
      releases.some(r => r.t >= d.t && r.t - d.t <= 60_000)).length;
    findings.push({
      severity: linkDown.length >= 5 ? 'error' : 'warn',
      kind: 'link',
      title: `有線リンクの断を${linkDown.length}回検出`,
      detail: `ポート別: ${worst.map(([p, c]) => `${p} ${c}回`).join('、')}。`
        + (correlated
          ? `うち${correlated}回は直後にDHCPの再取得が続いており、IP再取得の引き金になっている。`
          : `同一ポートで繰り返していればケーブル／ポート／相手機器側の問題。`),
      hint: 'LANケーブルの差し直しと、別ポートへの差し替えで切り分ける。',
      count: linkDown.length,
    });
  }

  // --- 5. IPプール枯渇 ---
  // 「プール未設定」(dhcps_no_pool) は枯渇ではないため、ここでは扱わない。
  // IPv6をRA/SLAACで配る一般的な構成では正常に出るメッセージ。
  const poolEmpty = [...byId('dhcps_pool_empty'), ...byId('dhcps_no_free')];
  if (poolEmpty.length) {
    findings.push({
      severity: 'critical',
      kind: 'dhcp',
      title: 'DHCPのIPアドレスプールが枯渇している',
      detail: `${poolEmpty.length}回発生。空きIPが無く、子機にアドレスを配れていない。`,
      hint: 'DHCP配布範囲を広げる、またはリース期間を短くして回収を早める。',
      count: poolEmpty.length,
    });
  }

  // --- 6. Wi-Fi認証の再試行集中 ---
  const authOk = byId('auth_ok');
  const authFail = byId('auth_fail');
  if (authFail.length >= 3) {
    findings.push({
      severity: 'error', kind: 'wifi',
      title: `Wi-Fi認証の失敗を${authFail.length}回検出`,
      detail: `認証成功${authOk.length}回に対し失敗${authFail.length}回。パスフレーズ誤りか電波品質の問題。`,
      hint: '特定の子機に偏っていれば端末側、複数端末に跨っていればAP側の設定・電波環境を確認。',
      count: authFail.length,
    });
  }
  // 同一MACの短時間での再認証は、電波が不安定で切断・再接続を繰り返す兆候。
  const reauth = repeatedReauth(authOk);
  if (reauth.total >= 5) {
    // このログには Deauth/Disassoc が記録されないため「切断」の証拠が無い。
    // 原因を断定せず、分布（1台集中か複数台か）で切り分けを促す。
    const hasDeauthLog = byId('auth_deauth').length > 0;
    const topShare = reauth.top.length ? reauth.top[0].count / reauth.total : 0;
    const concentrated = topShare >= 0.5;
    findings.push({
      severity: reauth.total >= 30 ? 'error' : 'warn',
      kind: 'wifi',
      title: '短時間に同じ子機の再認証が繰り返されている',
      detail: `5分以内の再認証が${reauth.total}回。`
        + `最多の子機: ${reauth.top.map(c => `${c.host || c.mac}（${c.count}回）`).join('、')}。`
        + (concentrated
          ? `全体の${Math.round(topShare * 100)}%が1台に集中している。`
          : `複数の子機に分散している。`)
        + (hasDeauthLog ? '' : `このログには切断(Deauth/Disassoc)が記録されないため、`
          + `切断を伴う再接続か、WPA再キーや省電力からの復帰による記録かは判別できない。`),
      hint: concentrated
        ? '1台に集中しているため、まず該当端末の省電力設定・無線ドライバを確認する。AP側の電波環境が原因なら複数台に分散するはず。'
        : '複数台に分散しているため、チャンネル干渉や電波の届きにくさなどAP側の電波環境を確認する。',
      count: reauth.total,
    });
  }

  // --- 7. IP拒否（NAK）---
  const naks = [...byId('dhcps_nak'), ...byId('dhcpc_nak')];
  if (naks.length) {
    findings.push({
      severity: 'error', kind: 'dhcp',
      title: `DHCPのIP拒否(NAK)を${naks.length}回検出`,
      detail: `子機が要求したIPをサーバが拒否している。リース情報の不整合やIP競合で発生する。`,
      hint: 'ルーターのDHCPリース一覧を確認し、固定IPとDHCP配布範囲の重複が無いか調べる。',
      count: naks.length,
    });
  }

  // --- 8. ARPINGエラー ---
  // Interrupted system call は除外済み（良性のため）。
  const arping = [...byId('dhcps_arping_err'), ...byId('dhcpc_arping_err')];
  if (arping.length >= 2) {
    const reasons = [...new Set(arping.map(e => e.fields.detail).filter(Boolean))];
    findings.push({
      severity: 'warn', kind: 'dhcp',
      title: `ARPINGエラーを${arping.length}回検出`,
      detail: `IPアドレスの重複確認に失敗している${reasons.length ? `（${reasons.join('、')}）` : ''}。`
        + `IP競合の可能性があるが、このメッセージ単体では断定できない。`,
      hint: '手動設定したIPがDHCP配布範囲と重なっていないか確認する。',
      count: arping.length,
    });
  }

  // --- 9. 異常時間帯の集中 ---
  // 機器ごとにログのカバー期間が違う場合、合算した時系列は
  // 「両方のログがある期間」だけイベント密度が上がり、判定がそこに偏る。
  const spans = dataset.devices.map(d => {
    const de = events.filter(e => e.dev === d.idx);
    return de.length ? (de[de.length - 1].t - de[0].t) / 86400_000 : 0;
  }).filter(v => v > 0);
  const spanMismatch = spans.length >= 2
    && Math.max(...spans) > Math.min(...spans) * 1.5;

  const anomalies = findAnomalies(bins, 'total');
  if (anomalies.length) {
    const top = anomalies.slice(0, 3);
    findings.push({
      severity: 'warn', kind: 'other',
      title: `イベントが集中している時間帯が${anomalies.length}区間ある`,
      detail: `最も多い区間: ${top.map(a => `${fmtDateTime(new Date(a.t))}（${a.count}件${ratioText(a.ratio)}）`).join('、')}。`
        + `平常時（イベントのある区間）の中央値は${Math.round(anomalies[0].median)}件程度。`
        + (spanMismatch
          ? `なお読み込んだログはカバー期間が異なる（最長${Math.round(Math.max(...spans))}日／最短${Math.round(Math.min(...spans))}日）ため、`
            + `全機器のログが揃っている期間はイベント数が多く出る。機器を1台ずつ選んで確認することを推奨。`
          : ''),
      hint: 'その時刻に現場で何が起きていたか（電源、天候、利用者数）と突き合わせる。',
      count: anomalies.length,
    });
  }

  findings.sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) || b.count - a.count);
  return findings;
}

/** 最も発生件数が多かった日を返す。 */
function worstDayOf(items) {
  const byDay = new Map();
  for (const it of items) {
    const d = new Date(it.t);
    const key = `${d.getFullYear()}/${String(d.getMonth() + 1).padStart(2, '0')}/${String(d.getDate()).padStart(2, '0')}`;
    byDay.set(key, (byDay.get(key) || 0) + 1);
  }
  const top = [...byDay.entries()].sort((a, b) => b[1] - a[1])[0];
  return top ? { date: top[0], count: top[1] } : { date: '不明', count: 0 };
}

/** 5分以内に同一MACが再認証している回数を数える。 */
function repeatedReauth(authEvents, windowMs = 300_000) {
  const byMac = new Map();
  for (const e of authEvents) {
    const mac = e.fields.mac;
    if (!mac) continue;
    (byMac.get(mac) || byMac.set(mac, []).get(mac)).push(e);
  }
  let total = 0;
  const per = [];
  for (const [mac, list] of byMac) {
    list.sort((a, b) => a.t - b.t);
    let n = 0;
    for (let i = 1; i < list.length; i++) {
      if (list[i].t - list[i - 1].t <= windowMs) n++;
    }
    if (n) {
      total += n;
      per.push({ mac, host: list.find(e => e.fields.host)?.fields.host || '', count: n });
    }
  }
  per.sort((a, b) => b.count - a.count);
  return { total, top: per.slice(0, 3), per };
}

export function fmtDur(sec) {
  if (!sec) return '不明';
  if (sec < 60) return `${Math.round(sec)}秒`;
  if (sec < 3600) return `${Math.round(sec / 60)}分`;
  if (sec < 86400) return `${(sec / 3600).toFixed(1)}時間`;
  return `${(sec / 86400).toFixed(1)}日`;
}

export function fmtDateTime(d) {
  const p = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}/${p(d.getMonth() + 1)}/${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

function deviceName(meta, i) {
  const base = meta.fileName.replace(/\.log$/i, '');
  return meta.role ? `${meta.role}機` : (base || `機器${i + 1}`);
}

/**
 * 子機×時刻のマトリクス。全期間を時刻(0〜23)で重ねて集計する。
 * 「この子機は毎朝8時に集中している」といった周期性を子機単位で見つけるため。
 * @param {Array} events
 * @param {number} limit 上位何台までを対象にするか
 */
export function clientHourMatrix(events, { limit = 30, minTotal = 2 } = {}) {
  const map = new Map();
  for (const e of events) {
    const mac = e.fields.mac;
    if (!mac) continue;
    let row = map.get(mac);
    if (!row) {
      row = { mac, host: '', hours: new Array(24).fill(0), total: 0, first: e.t, last: e.t };
      map.set(mac, row);
    }
    if (e.fields.host && !row.host) row.host = e.fields.host;
    row.hours[e.ts.getHours()]++;
    row.total++;
    row.first = Math.min(row.first, e.t);
    row.last = Math.max(row.last, e.t);
  }

  const rows = [...map.values()]
    .filter(r => r.total >= minTotal)
    .sort((a, b) => b.total - a.total)
    .slice(0, limit);

  // 各行のピーク時刻と、活動が特定時刻に偏っているかを添える。
  for (const r of rows) {
    const peak = r.hours.reduce((best, v, h) => v > r.hours[best] ? h : best, 0);
    r.peakHour = peak;
    r.peakCount = r.hours[peak];
    // 活動している時刻数。少なければ特定の時間帯に偏っている。
    r.activeHours = r.hours.filter(v => v > 0).length;
  }

  return { rows, max: Math.max(...rows.flatMap(r => r.hours), 1) };
}

/**
 * 指定した子機の、種別ごとの時系列。詳細表示用。
 * 子機のイベントは DHCPS と AUTH に跨るため、種別内訳が切り分けの手がかりになる。
 */
export function clientTimeline(events, mac, bucketMs, range) {
  const mine = events.filter(e => e.fields.mac === mac);
  const series = [
    { key: 'auth', label: 'Wi-Fi認証', color: '--series-2', test: e => e.kind === 'wifi' },
    { key: 'dhcp', label: 'DHCP', color: '--series-1', test: e => e.kind === 'dhcp' },
    { key: 'other', label: 'その他', color: '--series-5', test: e => e.kind !== 'wifi' && e.kind !== 'dhcp' },
  ].filter(s => mine.some(s.test));
  return { events: mine, series, bins: timeSeries(mine, bucketMs, series, range) };
}

// 画面の組み立てとイベント配線。

import { parseLog, EVENT_DEFS } from './parser.js';
import {
  buildDataset, filterEvents, countByEvent, timeSeries, findAnomalies,
  diagnose, perClient, dhcpLeaseChurn, fmtDateTime, fmtDur,
} from './analyze.js';
import { renderStackedBars, renderLines, renderHeatmap } from './charts.js';

const $ = id => document.getElementById(id);

// イベント種別と色の対応。dataviz の検証済みカテゴリ配色に従う。
const KINDS = [
  { key: 'dhcp',   label: 'DHCP',      color: '--series-1' },
  { key: 'wifi',   label: 'Wi-Fi認証', color: '--series-2' },
  { key: 'ntp',    label: 'NTP',       color: '--series-3' },
  { key: 'link',   label: '有線リンク', color: '--series-4' },
  { key: 'system', label: 'システム',   color: '--series-5' },
];
const DEVICE_COLORS = ['--series-1', '--series-2', '--series-3', '--series-4', '--series-5'];
const SEV_LABEL = { critical: '重大', error: 'エラー', warn: '注意', info: '情報' };
const SEV_ICON = { critical: '⛔', error: '⚠️', warn: '⚠️', info: 'ℹ️' };

const state = {
  logs: [],
  dataset: null,
  activeKinds: new Set(KINDS.map(k => k.key)),
  activeDevices: new Set(),
  bucketMs: 3600_000,
  rangeDays: 'all',
  tab: 'events',
  sort: { events: { col: 'count', dir: -1 }, clients: { col: 'total', dir: -1 } },
};

// ---------- ファイル投入 ----------

const drop = $('drop');
['dragenter', 'dragover'].forEach(ev =>
  drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add('over'); }));
['dragleave', 'drop'].forEach(ev =>
  drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove('over'); }));
drop.addEventListener('drop', e => handleFiles([...e.dataTransfer.files]));

$('pick').addEventListener('click', () => $('file').click());

// サンプルログ。実際の障害ログを匿名化したもの。
$('demo').addEventListener('click', async () => {
  const btn = $('demo');
  btn.disabled = true;
  btn.textContent = '読み込み中…';
  try {
    const names = ['sample/sample_ap.log', 'sample/sample_router.log'];
    const texts = await Promise.all(names.map(async n => {
      const res = await fetch(n);
      if (!res.ok) throw new Error(`${n} を取得できませんでした (${res.status})`);
      return { name: n.split('/').pop(), text: await res.text() };
    }));
    loadParsed(texts);
  } catch (err) {
    alert(`サンプルの読み込みに失敗しました。${err.message}`);
  } finally {
    btn.disabled = false;
    btn.textContent = 'サンプルログで試す';
  }
});
$('file').addEventListener('change', e => handleFiles([...e.target.files]));
$('reset').addEventListener('click', () => {
  state.logs = [];
  state.dataset = null;
  $('result').hidden = true;
  $('intake').hidden = false;
  $('reset').hidden = true;
  $('file').value = '';
});

// テーマ切替。OS設定を上書きする。
$('theme-toggle').addEventListener('click', () => {
  const cur = document.documentElement.getAttribute('data-theme');
  const isDark = cur === 'dark'
    || (!cur && matchMedia('(prefers-color-scheme: dark)').matches);
  document.documentElement.setAttribute('data-theme', isDark ? 'light' : 'dark');
  if (state.dataset) render();
});

async function handleFiles(files) {
  const texts = await Promise.all(
    files.filter(f => f.size > 0).map(async f => ({ name: f.name, text: await f.text() })));
  loadParsed(texts);
}

/** パース済みテキストを画面に反映する。ファイル投入・サンプル投入の共通経路。 */
function loadParsed(texts) {
  const all = texts.map(t => parseLog(t.text, t.name));
  const parsed = all.filter(p => p.events.length);
  if (!parsed.length) {
    alert('ログとして読み取れる行が見つかりませんでした。AirStation のログファイルを指定してください。');
    return;
  }
  // 読み取れなかったファイルは黙って捨てず、名前を伝える。
  state.skipped = all.filter(p => !p.events.length).map(p => p.meta.fileName);
  state.logs = parsed;
  state.dataset = buildDataset(parsed);
  state.activeDevices = new Set(state.dataset.devices.map(d => d.idx));
  applyInitialView();
  $('intake').hidden = true;
  $('result').hidden = false;
  $('reset').hidden = false;
  buildFilters();
  render();
}

// ---------- フィルタUI ----------

function buildFilters() {
  const tags = $('file-tags');
  tags.textContent = '';
  for (const dev of state.dataset.devices) {
    const btn = document.createElement('button');
    btn.className = 'chip';
    btn.setAttribute('aria-pressed', 'true');
    btn.style.color = `var(${DEVICE_COLORS[dev.idx % DEVICE_COLORS.length]})`;
    const dot = document.createElement('span');
    dot.className = 'dot';
    const label = document.createElement('span');
    label.style.color = 'var(--text-primary)';
    label.textContent = `${dev.name}（${dev.events.length.toLocaleString('ja-JP')}件）`;
    btn.append(dot, label);
    btn.addEventListener('click', () => {
      const on = btn.getAttribute('aria-pressed') === 'true';
      if (on && state.activeDevices.size === 1) return; // 最低1台は残す
      btn.setAttribute('aria-pressed', String(!on));
      if (on) state.activeDevices.delete(dev.idx);
      else state.activeDevices.add(dev.idx);
      render();
    });
    tags.appendChild(btn);
  }

  const chips = $('kind-chips');
  chips.textContent = '';
  for (const k of KINDS) {
    const btn = document.createElement('button');
    btn.className = 'chip';
    btn.setAttribute('aria-pressed', 'true');
    btn.style.color = `var(${k.color})`;
    const dot = document.createElement('span');
    dot.className = 'dot';
    const label = document.createElement('span');
    label.style.color = 'var(--text-primary)';
    label.textContent = k.label;
    btn.append(dot, label);
    btn.addEventListener('click', () => {
      const on = btn.getAttribute('aria-pressed') === 'true';
      if (on && state.activeKinds.size === 1) return;
      btn.setAttribute('aria-pressed', String(!on));
      if (on) state.activeKinds.delete(k.key);
      else state.activeKinds.add(k.key);
      render();
    });
    chips.appendChild(btn);
  }

  $('bucket').addEventListener('change', e => {
    state.bucketMs = +e.target.value;
    state.bucketPinned = true; // 明示的に選ばれた粒度は自動変更しない
    render();
  });
  $('range').addEventListener('change', e => {
    state.rangeDays = e.target.value;
    if (!state.bucketPinned) {
      const ds = state.dataset;
      const days = e.target.value === 'all'
        ? (ds.range.to - ds.range.from) / 86400_000 : +e.target.value;
      state.bucketMs = pickBucket(days);
      $('bucket').value = String(state.bucketMs);
    }
    render();
  });
  for (const tab of document.querySelectorAll('.tab')) {
    tab.addEventListener('click', () => {
      state.tab = tab.dataset.tab;
      for (const t of document.querySelectorAll('.tab')) {
        t.setAttribute('aria-selected', String(t.dataset.tab === state.tab));
      }
      for (const name of ['events', 'clients', 'anomalies']) {
        $(`tab-${name}`).hidden = name !== state.tab;
      }
    });
  }
}

/**
 * 初期表示の範囲と粒度を決める。
 * ログは数ヶ月に及ぶ一方トラブルは特定の日に集中するため、
 * 全期間を1時間粒度で出すと肝心の区間が1〜2ピクセルに潰れて読めない。
 * 「エラー以上のイベントが最も多い日」を含む範囲を初期表示にする。
 */
function applyInitialView() {
  const ds = state.dataset;
  const spanDays = (ds.range.to - ds.range.from) / 86400_000;

  // 深刻なイベントが集中している日を探す。
  const byDay = new Map();
  for (const e of ds.events) {
    if (e.preNtp || e.noise) continue;
    if (e.severity !== 'critical' && e.severity !== 'error') continue;
    const d = new Date(e.t);
    const key = new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();
    byDay.set(key, (byDay.get(key) || 0) + 1);
  }
  const worst = [...byDay.entries()].sort((a, b) => b[1] - a[1])[0];

  // 期間が長く、かつ問題の日が最終日付近にあるなら直近に寄せる。
  let rangeDays = 'all';
  if (spanDays > 10) {
    const daysFromEnd = worst ? (ds.range.to - worst[0]) / 86400_000 : 0;
    if (!worst) rangeDays = '7';
    else if (daysFromEnd <= 1.5) rangeDays = '1';
    else if (daysFromEnd <= 3) rangeDays = '3';
    else if (daysFromEnd <= 7) rangeDays = '7';
    else rangeDays = '30';
  }
  state.rangeDays = rangeDays;
  $('range').value = rangeDays;

  state.bucketMs = pickBucket(rangeDays === 'all' ? spanDays : +rangeDays);
  $('bucket').value = String(state.bucketMs);
}

/** 表示日数に対して、棒が潰れず粗すぎない粒度を選ぶ。 */
function pickBucket(days) {
  if (days <= 1.5) return 1800_000;    // 30分
  if (days <= 4) return 3600_000;      // 1時間
  if (days <= 21) return 21600_000;    // 6時間
  return 86400_000;                    // 1日
}

function currentRange() {
  const { from, to } = state.dataset.range;
  if (state.rangeDays === 'all') return { from, to };
  return { from: Math.max(from, to - state.rangeDays * 86400_000), to };
}

// ---------- 描画 ----------

function render() {
  const ds = state.dataset;
  const range = currentRange();
  const events = filterEvents(ds, {
    ...range,
    devices: state.activeDevices,
    kinds: state.activeKinds,
  });

  const kindSeries = KINDS
    .filter(k => state.activeKinds.has(k.key))
    .map(k => ({ ...k, test: e => e.kind === k.key }));
  const bins = timeSeries(events, state.bucketMs, kindSeries, range);
  const anomalies = findAnomalies(bins, 'total');

  renderKpis(ds, events, range, anomalies);
  renderFindings(ds, events, bins);

  renderStackedBars($('chart-timeline'), { bins, series: kindSeries, bucketMs: state.bucketMs, anomalies });
  renderLegend($('legend-timeline'), kindSeries, 'rect');
  // 区間数が多いとグラフは横スクロールになる。読み方を添える。
  const scrolls = bins.length * 6 > $('chart-timeline').clientWidth;
  $('scroll-note').textContent = scrolls
    ? `${bins.length}区間あるため横スクロールします。粒度を粗くするか期間を絞ると全体が収まります。` : '';

  // 機器比較は2台以上のときだけ意味がある
  const devs = ds.devices.filter(d => state.activeDevices.has(d.idx));
  $('card-compare').hidden = devs.length < 2;
  if (devs.length >= 2) {
    const devSeries = devs.map(d => ({
      key: `dev${d.idx}`, label: d.name,
      color: DEVICE_COLORS[d.idx % DEVICE_COLORS.length],
      test: e => e.dev === d.idx,
    }));
    const devBins = timeSeries(events, state.bucketMs, devSeries, range);
    renderLines($('chart-compare'), { bins: devBins, series: devSeries, bucketMs: state.bucketMs });
    renderLegend($('legend-compare'), devSeries, 'line');
  }

  renderHeatmap($('chart-heatmap'), { events });
  renderEventTable(events);
  renderClientTable(events);
  renderAnomalyTable(anomalies, events);
  renderRawPicker(anomalies, events);

  // 全期間より狭い範囲を見ているときは、その旨を明示する。
  const full = ds.range;
  const narrowed = range.from > full.from + 60_000;
  $('range-note').textContent = narrowed
    ? `全期間は ${fmtDateTime(new Date(full.from))} 〜 ${fmtDateTime(new Date(full.to))}（${Math.round((full.to - full.from) / 86400_000)}日分）`
    : '';

  const unparsed = state.logs.reduce((n, l) => n + l.unparsed.length, 0);
  $('parse-note').textContent =
    `読み込み ${state.logs.length}ファイル / 全${ds.events.length.toLocaleString('ja-JP')}行を解析`
    + (unparsed ? `（形式が一致しなかった行 ${unparsed}行）` : '（解析できなかった行なし）')
    + (ds.preNtpCount ? ` / 時刻同期前の行 ${ds.preNtpCount}行は時間軸から除外` : '')
    + (state.skipped && state.skipped.length
      ? ` / 読み取れず除外: ${state.skipped.join('、')}` : '');
}

function renderLegend(container, series, shape) {
  container.textContent = '';
  if (series.length < 2) return; // 1系列なら凡例は不要（見出しが示している）
  for (const s of series) {
    const item = document.createElement('span');
    item.className = 'item';
    const key = document.createElement('span');
    key.className = shape === 'line' ? 'key line' : 'key';
    key.style.background = `var(${s.color})`;
    const label = document.createElement('span');
    label.textContent = s.label;
    item.append(key, label);
    container.appendChild(item);
  }
}

function renderKpis(ds, events, range, anomalies) {
  const box = $('kpis');
  box.textContent = '';

  const problems = events.filter(e => e.severity === 'critical' || e.severity === 'error');
  const days = Math.max((range.to - range.from) / 86400_000, 1 / 24);

  // AP機自身のIP再取得回数。DHCP不安定の主指標。
  const churn = ds.devices
    .filter(d => state.activeDevices.has(d.idx))
    .map(d => dhcpLeaseChurn(events.filter(e => e.dev === d.idx)))
    .reduce((a, c) => ({
      prematureCount: a.prematureCount + c.prematureCount,
      bindCount: a.bindCount + c.bindCount,
    }), { prematureCount: 0, bindCount: 0 });

  const reconnects = events.filter(e => e.id === 'auth_ok').length;

  const kpis = [
    {
      label: '重大・エラー イベント', value: problems.length, hero: true,
      note: problems.length ? '下の診断サマリを確認' : '問題は検出されていません',
    },
    { label: 'IPの早期再取得', value: churn.prematureCount, note: `IP取得 ${churn.bindCount}回中` },
    { label: 'Wi-Fi認証', value: reconnects, note: `1日あたり約${(reconnects / days).toFixed(0)}回` },
    { label: '異常な時間帯', value: anomalies.length, note: `全${(state.bucketMs === 86400_000 ? '日' : '区間')}中` },
    {
      label: '対象期間',
      value: days < 1 ? `${Math.max(Math.round(days * 24), 1)}時間` : `${Math.round(days)}日`,
      note: `${fmtDateTime(new Date(range.from))} 〜`,
      isText: true,
    },
  ];

  for (const k of kpis) {
    const div = document.createElement('div');
    div.className = 'kpi' + (k.hero ? ' hero' : '');
    const l = document.createElement('div');
    l.className = 'label';
    l.textContent = k.label;
    const v = document.createElement('div');
    v.className = 'value';
    v.textContent = k.isText ? k.value : k.value.toLocaleString('ja-JP');
    if (k.hero && k.value > 0) v.style.color = 'var(--critical)';
    const n = document.createElement('div');
    n.className = 'note';
    n.textContent = k.note;
    div.append(l, v, n);
    box.appendChild(div);
  }
}

function renderFindings(ds, events, bins) {
  const box = $('findings');
  box.textContent = '';
  const findings = diagnose(ds, events, bins);

  if (!findings.length) {
    const ok = document.createElement('div');
    ok.className = 'ok-msg';
    ok.textContent = '✅ この期間・条件では、目立ったトラブルの兆候は検出されませんでした。';
    box.appendChild(ok);
    return;
  }

  for (const f of findings) {
    const row = document.createElement('div');
    row.className = 'finding';
    const icon = document.createElement('span');
    icon.className = 'icon';
    icon.textContent = SEV_ICON[f.severity];
    const body = document.createElement('div');
    body.className = 'body';

    const title = document.createElement('div');
    title.className = 'title';
    const badge = document.createElement('span');
    badge.className = `badge ${f.severity}`;
    badge.textContent = SEV_LABEL[f.severity];
    const tt = document.createElement('span');
    tt.textContent = f.title;
    title.append(badge, tt);

    const detail = document.createElement('div');
    detail.className = 'detail';
    detail.textContent = f.detail;

    body.append(title, detail);
    if (f.hint) {
      const hint = document.createElement('div');
      hint.className = 'hint';
      const b = document.createElement('b');
      b.textContent = '確認すべきこと: ';
      hint.append(b, document.createTextNode(f.hint));
      body.appendChild(hint);
    }
    row.append(icon, body);
    box.appendChild(row);
  }
}

/** 汎用テーブル描画。列見出しクリックで並べ替える。 */
function renderTable(table, cols, rows, sortKey) {
  table.textContent = '';
  const sort = state.sort[sortKey];
  if (sort) {
    const col = cols.find(c => c.key === sort.col);
    if (col) {
      rows = [...rows].sort((a, b) => {
        const av = col.sortVal ? col.sortVal(a) : a[col.key];
        const bv = col.sortVal ? col.sortVal(b) : b[col.key];
        if (typeof av === 'string') return av.localeCompare(bv, 'ja') * sort.dir;
        return (av - bv) * sort.dir;
      });
    }
  }

  const thead = document.createElement('thead');
  const tr = document.createElement('tr');
  for (const c of cols) {
    const th = document.createElement('th');
    if (c.num) th.className = 'num';
    th.textContent = c.label + (sort && sort.col === c.key ? (sort.dir < 0 ? ' ↓' : ' ↑') : '');
    if (sortKey) {
      th.addEventListener('click', () => {
        const s = state.sort[sortKey];
        state.sort[sortKey] = { col: c.key, dir: s.col === c.key ? -s.dir : -1 };
        render();
      });
    }
    tr.appendChild(th);
  }
  thead.appendChild(tr);
  table.appendChild(thead);

  const tbody = document.createElement('tbody');
  if (!rows.length) {
    const trE = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = cols.length;
    td.className = 'empty';
    td.textContent = '該当するデータがありません。';
    trE.appendChild(td);
    tbody.appendChild(trE);
  }
  for (const r of rows) {
    const trr = document.createElement('tr');
    for (const c of cols) {
      const td = document.createElement('td');
      if (c.num) td.className = 'num';
      c.render ? c.render(td, r) : (td.textContent = String(r[c.key] ?? ''));
      trr.appendChild(td);
    }
    tbody.appendChild(trr);
  }
  table.appendChild(tbody);
}

function renderEventTable(events) {
  const rows = countByEvent(events);
  const kindColor = k => `var(${(KINDS.find(x => x.key === k) || {}).color || '--text-muted'})`;
  renderTable($('table-events'), [
    {
      key: 'label', label: 'イベント',
      render: (td, r) => {
        const dot = document.createElement('span');
        dot.className = 'mark';
        dot.style.background = kindColor(r.kind);
        td.append(dot, document.createTextNode(r.label));
      },
    },
    {
      key: 'severity', label: '深刻度',
      render: (td, r) => {
        const b = document.createElement('span');
        b.className = `badge ${r.severity}`;
        b.textContent = SEV_LABEL[r.severity];
        td.appendChild(b);
      },
      sortVal: r => ['critical', 'error', 'warn', 'info'].indexOf(r.severity),
    },
    { key: 'count', label: '件数', num: true, render: (td, r) => td.textContent = r.count.toLocaleString('ja-JP') },
    { key: 'first', label: '最初', render: (td, r) => td.textContent = fmtDateTime(new Date(r.first)) },
    { key: 'last', label: '最後', render: (td, r) => td.textContent = fmtDateTime(new Date(r.last)) },
  ], rows, 'events');
}

function renderClientTable(events) {
  const rows = perClient(events);
  renderTable($('table-clients'), [
    {
      key: 'host', label: '端末名',
      render: (td, r) => td.textContent = r.host || '(名前なし)',
      sortVal: r => r.host || 'zzz',
    },
    {
      key: 'mac', label: 'MACアドレス',
      render: (td, r) => {
        const s = document.createElement('span');
        s.className = 'mono';
        s.textContent = r.mac;
        td.appendChild(s);
      },
    },
    { key: 'auth', label: 'Wi-Fi認証', num: true },
    { key: 'dhcpReq', label: 'IP要求', num: true },
    { key: 'dhcpAck', label: 'IP確定', num: true },
    { key: 'dhcpRelease', label: 'IP解放', num: true },
    { key: 'total', label: '合計', num: true, render: (td, r) => td.textContent = r.total.toLocaleString('ja-JP') },
    { key: 'last', label: '最終', render: (td, r) => td.textContent = fmtDateTime(new Date(r.last)) },
  ], rows, 'clients');
}

function renderAnomalyTable(anomalies, events) {
  const rows = anomalies.map(a => {
    const inBin = events.filter(e => e.t >= a.t && e.t < a.t + state.bucketMs);
    const top = countByEvent(inBin).slice(0, 3).map(c => `${c.label}×${c.count}`).join('、');
    return { ...a, top };
  });
  renderTable($('table-anomalies'), [
    { key: 't', label: '時間帯', render: (td, r) => td.textContent = fmtDateTime(new Date(r.t)) },
    { key: 'count', label: '件数', num: true, render: (td, r) => td.textContent = r.count.toLocaleString('ja-JP') },
    {
      key: 'ratio', label: '平常比', num: true,
      render: (td, r) => td.textContent = r.ratio >= 20 ? '大幅に多い' : `${r.ratio.toFixed(1)}倍`,
    },
    { key: 'top', label: '主なイベント' },
  ], rows, null);
}

/** 異常時間帯を候補に出し、選ぶとその前後の生ログを表示する。 */
function renderRawPicker(anomalies, events) {
  const sel = $('raw-anchor');
  sel.textContent = '';
  const opts = anomalies.slice(0, 40).map(a => ({
    t: a.t,
    label: `${fmtDateTime(new Date(a.t))}（${a.count}件${a.ratio >= 20 ? '・平常より大幅に多い' : `・平常の${a.ratio.toFixed(1)}倍`}）`,
  }));
  if (!opts.length && events.length) {
    opts.push({ t: events[events.length - 1].t, label: `${fmtDateTime(events[events.length - 1].ts)}（最新）` });
  }
  if (!opts.length) {
    $('rawlog').textContent = '表示できるログがありません。';
    return;
  }
  for (const o of opts) {
    const opt = document.createElement('option');
    opt.value = String(o.t);
    opt.textContent = o.label;
    sel.appendChild(opt);
  }
  const show = () => {
    const t = +sel.value;
    // 選んだ時間帯の生ログを、種別フィルタを外して時刻順に出す。
    const lines = state.dataset.events
      .filter(e => !e.preNtp && e.t >= t - 60_000 && e.t < t + state.bucketMs + 60_000)
      .filter(e => state.activeDevices.has(e.dev))
      .slice(0, 600)
      .map(e => {
        const d = e.ts;
        const p = n => String(n).padStart(2, '0');
        const dev = state.dataset.devices[e.dev].name;
        return `${d.getFullYear()}/${p(d.getMonth() + 1)}/${p(d.getDate())} `
          + `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}  [${dev}] ${e.cat}\t${e.message}`;
      });
    $('rawlog').textContent = lines.length ? lines.join('\n') : 'この時間帯のログはありません。';
  };
  sel.addEventListener('change', show);
  show();
}

// 画面幅が変わるとSVGの実寸が変わるため再描画する。
let resizeTimer;
addEventListener('resize', () => {
  if (!state.dataset) return;
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(render, 180);
});

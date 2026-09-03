// SVG グラフ描画。外部ライブラリを使わず、GitHub Pages で静的配信できるようにする。

const NS = 'http://www.w3.org/2000/svg';

function el(name, attrs = {}) {
  const n = document.createElementNS(NS, name);
  for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
  return n;
}

/** 目盛りが読みやすい丸い数字に切り上げる。 */
function niceMax(v) {
  if (v <= 5) return Math.max(v, 1);
  const mag = 10 ** Math.floor(Math.log10(v));
  for (const s of [1, 1.5, 2, 2.5, 3, 4, 5, 7.5, 10]) {
    if (v <= s * mag) return s * mag;
  }
  return 10 * mag;
}

function fmtTick(t, bucketMs) {
  const d = new Date(t);
  const p = n => String(n).padStart(2, '0');
  if (bucketMs >= 86400_000) return `${d.getMonth() + 1}/${d.getDate()}`;
  return `${d.getMonth() + 1}/${d.getDate()} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

function fmtFull(t, bucketMs) {
  const d = new Date(t);
  const p = n => String(n).padStart(2, '0');
  const base = `${d.getFullYear()}/${p(d.getMonth() + 1)}/${p(d.getDate())}`;
  if (bucketMs >= 86400_000) return `${base}（1日）`;
  const end = new Date(t + bucketMs);
  return `${base} ${p(d.getHours())}:${p(d.getMinutes())}〜${p(end.getHours())}:${p(end.getMinutes())}`;
}

/**
 * 積み上げ棒グラフ（時系列）。イベント種別の内訳を時間帯ごとに見せる。
 * 異常区間は背景に帯を敷いて示す。
 */
export function renderStackedBars(container, { bins, series, bucketMs, anomalies = [], height = 260 }) {
  container.textContent = '';
  if (!bins.length) {
    const p = document.createElement('div');
    p.className = 'empty';
    p.textContent = '該当するイベントがありません。フィルタを見直してください。';
    container.appendChild(p);
    return;
  }

  const pad = { t: 12, r: 14, b: 30, l: 46 };
  // ビンが多い場合は横スクロールさせ、1本あたり最低幅を確保する。
  // 幅に押し込めて棒が1px未満に潰れると、山がどこにあるか読めなくなる。
  const minBar = 6;
  const innerW = Math.max(bins.length * minBar, container.clientWidth - pad.l - pad.r - 2);
  const W = innerW + pad.l + pad.r;
  const H = height;
  const innerH = H - pad.t - pad.b;

  const svg = el('svg', { class: 'chart', viewBox: `0 0 ${W} ${H}`, width: W, height: H, role: 'img' });
  if (innerW > container.clientWidth) svg.setAttribute('preserveAspectRatio', 'xMinYMin meet');

  const maxTotal = niceMax(Math.max(...bins.map(b => series.reduce((s, k) => s + (b[k.key] || 0), 0)), 1));
  const x = i => pad.l + (i * innerW) / bins.length;
  const bw = Math.max(innerW / bins.length - 1.5, 1.5);
  const y = v => pad.t + innerH - (v / maxTotal) * innerH;

  // Y軸グリッドと目盛り
  const ticks = 4;
  for (let i = 0; i <= ticks; i++) {
    const v = (maxTotal / ticks) * i;
    const yy = y(v);
    svg.appendChild(el('line', { class: 'grid-line', x1: pad.l, x2: pad.l + innerW, y1: yy, y2: yy }));
    const tx = el('text', { x: pad.l - 7, y: yy + 3.5, 'text-anchor': 'end', class: 'y-label' });
    tx.textContent = Math.round(v).toLocaleString('ja-JP');
    svg.appendChild(tx);
  }

  // 異常区間の帯
  const anomSet = new Set(anomalies.map(a => a.t));
  bins.forEach((b, i) => {
    if (anomSet.has(b.t)) {
      svg.appendChild(el('rect', { class: 'anom-band', x: x(i) - 0.75, y: pad.t, width: bw + 1.5, height: innerH }));
    }
  });

  // 積み上げ棒。セグメント間は 2px のサーフェス色ギャップで分ける。
  bins.forEach((b, i) => {
    let acc = 0;
    const stack = series.filter(s => (b[s.key] || 0) > 0);
    stack.forEach((s, si) => {
      const v = b[s.key];
      const h = (v / maxTotal) * innerH;
      const gap = si < stack.length - 1 ? 2 : 0;
      const drawH = Math.max(h - gap, 0.8);
      const isTop = si === stack.length - 1;
      const yTop = pad.t + innerH - (acc + h);
      const r = Math.min(4, bw / 2, drawH);
      // 最上段のみ角丸。ベースライン側は角を立てる。
      const path = isTop
        ? `M${x(i)},${yTop + drawH} L${x(i)},${yTop + r} Q${x(i)},${yTop} ${x(i) + r},${yTop}`
          + ` L${x(i) + bw - r},${yTop} Q${x(i) + bw},${yTop} ${x(i) + bw},${yTop + r} L${x(i) + bw},${yTop + drawH} Z`
        : `M${x(i)},${yTop} h${bw} v${drawH} h${-bw} Z`;
      svg.appendChild(el('path', { d: path, fill: `var(${s.color})` }));
      acc += h;
    });
  });

  // X軸
  svg.appendChild(el('line', { class: 'axis-line', x1: pad.l, x2: pad.l + innerW, y1: pad.t + innerH, y2: pad.t + innerH }));

  // X軸ラベルは間引いて重なりを防ぐ
  const labelEvery = Math.max(1, Math.ceil(bins.length / Math.max(Math.floor(innerW / 78), 2)));
  bins.forEach((b, i) => {
    if (i % labelEvery) return;
    const tx = el('text', { x: x(i) + bw / 2, y: H - 10, 'text-anchor': 'middle' });
    tx.textContent = fmtTick(b.t, bucketMs);
    svg.appendChild(tx);
  });

  // ホバー層: 縦線 + ツールチップ。棒の細さに関わらず当たり判定を確保する。
  const hoverLine = el('line', { class: 'hover-line', y1: pad.t, y2: pad.t + innerH, x1: 0, x2: 0, opacity: 0 });
  svg.appendChild(hoverLine);

  const tip = document.createElement('div');
  tip.className = 'tooltip';
  container.appendChild(tip);

  const hit = el('rect', { x: pad.l, y: pad.t, width: innerW, height: innerH, fill: 'transparent', style: 'cursor:crosshair' });
  svg.appendChild(hit);

  const show = (i, clientX) => {
    const b = bins[i];
    const cx = x(i) + bw / 2;
    hoverLine.setAttribute('x1', cx);
    hoverLine.setAttribute('x2', cx);
    hoverLine.setAttribute('opacity', 1);

    tip.textContent = '';
    const head = document.createElement('div');
    head.className = 'tt-head';
    head.textContent = fmtFull(b.t, bucketMs);
    tip.appendChild(head);

    const rows = series.filter(s => (b[s.key] || 0) > 0);
    if (!rows.length) {
      const r = document.createElement('div');
      r.className = 'tt-row';
      r.innerHTML = '';
      const n = document.createElement('span');
      n.className = 'tt-name';
      n.textContent = 'イベントなし';
      r.appendChild(n);
      tip.appendChild(r);
    }
    for (const s of rows) {
      const row = document.createElement('div');
      row.className = 'tt-row';
      const key = document.createElement('span');
      key.className = 'tt-key';
      key.style.background = `var(${s.color})`;
      const name = document.createElement('span');
      name.className = 'tt-name';
      name.textContent = s.label;
      const val = document.createElement('span');
      val.className = 'tt-val';
      val.textContent = b[s.key].toLocaleString('ja-JP');
      row.append(key, name, val);
      tip.appendChild(row);
    }
    const total = series.reduce((sum, s) => sum + (b[s.key] || 0), 0);
    const tot = document.createElement('div');
    tot.className = 'tt-row';
    tot.style.marginTop = '5px';
    const tn = document.createElement('span');
    tn.className = 'tt-name';
    tn.textContent = '合計';
    const tv = document.createElement('span');
    tv.className = 'tt-val';
    tv.textContent = total.toLocaleString('ja-JP');
    tot.append(tn, tv);
    tip.appendChild(tot);

    tip.classList.add('on');
    const cRect = container.getBoundingClientRect();
    const px = clientX - cRect.left;
    const tw = tip.offsetWidth;
    tip.style.left = `${Math.min(Math.max(px + 14, 4), container.clientWidth - tw - 4)}px`;
    tip.style.top = `12px`;
  };

  const idxFromEvent = evt => {
    const rect = svg.getBoundingClientRect();
    const scale = W / rect.width;
    const sx = (evt.clientX - rect.left) * scale;
    return Math.min(bins.length - 1, Math.max(0, Math.floor(((sx - pad.l) / innerW) * bins.length)));
  };

  hit.addEventListener('pointermove', e => show(idxFromEvent(e), e.clientX));
  hit.addEventListener('pointerleave', () => {
    tip.classList.remove('on');
    hoverLine.setAttribute('opacity', 0);
  });

  container.appendChild(svg);
  container.appendChild(tip);
  // 当たり判定を最前面に保つ（後から追加した棒に隠れないようにする）
  svg.appendChild(hit);
  return svg;
}

/**
 * 折れ線グラフ。機器ごとの推移を同一時間軸で比較する。
 * 「AP機が暴れている時にルーター側は何を出していたか」を突き合わせるために使う。
 */
export function renderLines(container, { bins, series, bucketMs, height = 220 }) {
  container.textContent = '';
  if (!bins.length || !series.length) {
    const p = document.createElement('div');
    p.className = 'empty';
    p.textContent = '該当するイベントがありません。';
    container.appendChild(p);
    return;
  }

  const pad = { t: 12, r: 14, b: 30, l: 46 };
  const innerW = Math.max(bins.length * 6, container.clientWidth - pad.l - pad.r - 2);
  const W = innerW + pad.l + pad.r;
  const H = height;
  const innerH = H - pad.t - pad.b;

  const svg = el('svg', { class: 'chart', viewBox: `0 0 ${W} ${H}`, width: W, height: H, role: 'img' });
  const maxV = niceMax(Math.max(...bins.flatMap(b => series.map(s => b[s.key] || 0)), 1));
  const x = i => pad.l + (bins.length === 1 ? innerW / 2 : (i * innerW) / (bins.length - 1));
  const y = v => pad.t + innerH - (v / maxV) * innerH;

  const ticks = 4;
  for (let i = 0; i <= ticks; i++) {
    const v = (maxV / ticks) * i;
    const yy = y(v);
    svg.appendChild(el('line', { class: 'grid-line', x1: pad.l, x2: pad.l + innerW, y1: yy, y2: yy }));
    const tx = el('text', { x: pad.l - 7, y: yy + 3.5, 'text-anchor': 'end', class: 'y-label' });
    tx.textContent = Math.round(v).toLocaleString('ja-JP');
    svg.appendChild(tx);
  }

  for (const s of series) {
    const d = bins.map((b, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(b[s.key] || 0).toFixed(1)}`).join(' ');
    svg.appendChild(el('path', {
      d, fill: 'none', stroke: `var(${s.color})`, 'stroke-width': 2,
      'stroke-linejoin': 'round', 'stroke-linecap': 'round',
    }));
  }

  svg.appendChild(el('line', { class: 'axis-line', x1: pad.l, x2: pad.l + innerW, y1: pad.t + innerH, y2: pad.t + innerH }));

  const labelEvery = Math.max(1, Math.ceil(bins.length / Math.max(Math.floor(innerW / 78), 2)));
  bins.forEach((b, i) => {
    if (i % labelEvery) return;
    const tx = el('text', { x: x(i), y: H - 10, 'text-anchor': 'middle' });
    tx.textContent = fmtTick(b.t, bucketMs);
    svg.appendChild(tx);
  });

  const hoverLine = el('line', { class: 'hover-line', y1: pad.t, y2: pad.t + innerH, x1: 0, x2: 0, opacity: 0 });
  svg.appendChild(hoverLine);
  const dots = series.map(s => {
    const c = el('circle', { r: 4.5, fill: `var(${s.color})`, stroke: 'var(--surface-1)', 'stroke-width': 2, opacity: 0 });
    svg.appendChild(c);
    return c;
  });

  const tip = document.createElement('div');
  tip.className = 'tooltip';

  const hit = el('rect', { x: pad.l, y: pad.t, width: innerW, height: innerH, fill: 'transparent', style: 'cursor:crosshair' });
  svg.appendChild(hit);

  hit.addEventListener('pointermove', e => {
    const rect = svg.getBoundingClientRect();
    const scale = W / rect.width;
    const sx = (e.clientX - rect.left) * scale;
    const i = Math.min(bins.length - 1, Math.max(0,
      Math.round(((sx - pad.l) / innerW) * (bins.length - 1))));
    const b = bins[i];
    hoverLine.setAttribute('x1', x(i));
    hoverLine.setAttribute('x2', x(i));
    hoverLine.setAttribute('opacity', 1);
    series.forEach((s, si) => {
      dots[si].setAttribute('cx', x(i));
      dots[si].setAttribute('cy', y(b[s.key] || 0));
      dots[si].setAttribute('opacity', 1);
    });

    tip.textContent = '';
    const head = document.createElement('div');
    head.className = 'tt-head';
    head.textContent = fmtFull(b.t, bucketMs);
    tip.appendChild(head);
    for (const s of series) {
      const row = document.createElement('div');
      row.className = 'tt-row';
      const key = document.createElement('span');
      key.className = 'tt-key';
      key.style.background = `var(${s.color})`;
      const name = document.createElement('span');
      name.className = 'tt-name';
      name.textContent = s.label;
      const val = document.createElement('span');
      val.className = 'tt-val';
      val.textContent = (b[s.key] || 0).toLocaleString('ja-JP');
      row.append(key, name, val);
      tip.appendChild(row);
    }
    tip.classList.add('on');
    const cRect = container.getBoundingClientRect();
    const px = e.clientX - cRect.left;
    tip.style.left = `${Math.min(Math.max(px + 14, 4), container.clientWidth - tip.offsetWidth - 4)}px`;
    tip.style.top = '12px';
  });
  hit.addEventListener('pointerleave', () => {
    tip.classList.remove('on');
    hoverLine.setAttribute('opacity', 0);
    dots.forEach(d => d.setAttribute('opacity', 0));
  });

  container.appendChild(svg);
  container.appendChild(tip);
  svg.appendChild(hit);
}

/** 曜日 × 時刻のヒートマップ。「毎朝8時に落ちる」ような周期性を見つける。 */
export function renderHeatmap(container, { events, height = 200 }) {
  container.textContent = '';
  const DAYS = ['日', '月', '火', '水', '木', '金', '土'];
  const grid = Array.from({ length: 7 }, () => new Array(24).fill(0));
  for (const e of events) {
    grid[e.ts.getDay()][e.ts.getHours()]++;
  }
  const max = Math.max(...grid.flat(), 1);
  if (max === 1 && !events.length) {
    const p = document.createElement('div');
    p.className = 'empty';
    p.textContent = '該当するイベントがありません。';
    container.appendChild(p);
    return;
  }

  const pad = { t: 14, r: 10, b: 24, l: 30 };
  const cellW = 30, cellH = 20, gap = 2;
  const W = pad.l + 24 * cellW + pad.r;
  const H = pad.t + 7 * cellH + pad.b;
  const svg = el('svg', { class: 'chart', viewBox: `0 0 ${W} ${H}`, width: W, height: H, role: 'img' });

  // 単一色相の逐次スケール（薄い=少ない、濃い=多い）
  const RAMP = ['#cde2fb', '#9ec5f4', '#6da7ec', '#3987e5', '#256abf', '#184f95', '#0d366b'];
  const colorOf = v => {
    if (!v) return null;
    const idx = Math.min(RAMP.length - 1, Math.floor((v / max) * RAMP.length));
    return RAMP[idx];
  };

  const tip = document.createElement('div');
  tip.className = 'tooltip';

  for (let d = 0; d < 7; d++) {
    const ly = el('text', { x: pad.l - 7, y: pad.t + d * cellH + cellH / 2 + 3.5, 'text-anchor': 'end' });
    ly.textContent = DAYS[d];
    svg.appendChild(ly);
    for (let h = 0; h < 24; h++) {
      const v = grid[d][h];
      const fill = colorOf(v);
      const rect = el('rect', {
        x: pad.l + h * cellW + gap / 2, y: pad.t + d * cellH + gap / 2,
        width: cellW - gap, height: cellH - gap, rx: 3,
        fill: fill || 'var(--grid)', opacity: fill ? 1 : 0.35,
        style: 'cursor:pointer',
      });
      rect.addEventListener('pointerenter', e => {
        tip.textContent = '';
        const head = document.createElement('div');
        head.className = 'tt-head';
        head.textContent = `${DAYS[d]}曜 ${String(h).padStart(2, '0')}時台`;
        const row = document.createElement('div');
        row.className = 'tt-row';
        const name = document.createElement('span');
        name.className = 'tt-name';
        name.textContent = 'イベント';
        const val = document.createElement('span');
        val.className = 'tt-val';
        val.textContent = v.toLocaleString('ja-JP');
        row.append(name, val);
        tip.append(head, row);
        tip.classList.add('on');
        const cRect = container.getBoundingClientRect();
        tip.style.left = `${Math.min(e.clientX - cRect.left + 12, container.clientWidth - 160)}px`;
        tip.style.top = `${e.clientY - cRect.top + 12}px`;
      });
      rect.addEventListener('pointerleave', () => tip.classList.remove('on'));
      svg.appendChild(rect);
    }
  }
  for (let h = 0; h < 24; h += 3) {
    const tx = el('text', { x: pad.l + h * cellW + cellW / 2, y: H - 8, 'text-anchor': 'middle' });
    tx.textContent = `${h}時`;
    svg.appendChild(tx);
  }

  container.appendChild(svg);
  container.appendChild(tip);

  const scale = document.createElement('div');
  scale.className = 'legend';
  scale.style.marginTop = '10px';
  const lbl = document.createElement('span');
  lbl.textContent = '少ない';
  scale.appendChild(lbl);
  for (const c of RAMP) {
    const k = document.createElement('span');
    k.className = 'key';
    k.style.background = c;
    scale.appendChild(k);
  }
  const lbl2 = document.createElement('span');
  lbl2.textContent = `多い（最大 ${max.toLocaleString('ja-JP')}件）`;
  scale.appendChild(lbl2);
  container.appendChild(scale);
}

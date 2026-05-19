# 🎨 Evalsec — Shader Background untuk Vanilla HTML/Jinja2 Stack

> Adopt visual style dari 21st.dev shader reference (`bg.md`) ke evalsec dashboard, **tanpa npm/React/build step**. Pure vanilla CSS + SVG + JS, fully compatible dengan Jinja2 template + static deployment.

---

## 🎯 STACK CONFIRMED

- **Backend:** Python + Jinja2 (`dashboard.html.j2`), generate static HTML at build time
- **Frontend:** Vanilla HTML + inline CSS + inline JS (no bundler)
- **Charts:** Chart.js UMD via `<script src>` + custom plugins (`glowPlugin`, `copperEdgePlugin`)
- **Deploy:** Static file ke S3/CDN

**Konsekuensi:**
- ❌ `@paper-design/shaders-react` TIDAK BISA dipakai (React-only library)
- ❌ Tidak ada npm install, tidak ada framer-motion
- ✅ Pure CSS animations, SVG filters, dan (opsional) custom WebGL shader → **semua native, semua jalan tanpa build step**

---

## 🎨 PALETTE (Cyan + Orange dari 21st.dev reference)

Replace seluruh CSS variables Deep Plum + Copper yang existing dengan palette ini:

```css
:root {
  /* Background — transparent supaya shader keliatan */
  --bg-base:      #000000;
  --bg-elevated:  rgba(8, 12, 18, 0.65);   /* card glass */
  --bg-overlay:   rgba(15, 22, 32, 0.75);

  /* Primary — Cyan family */
  --accent-primary:      #06b6d4;
  --accent-primary-hi:   #22d3ee;
  --accent-primary-lo:   #0891b2;
  --accent-primary-deep: #164e63;

  /* Secondary — Orange family */
  --accent-secondary:    #f97316;
  --accent-secondary-hi: #fb923c;
  --accent-secondary-lo: #ea580c;

  /* Tertiary — White untuk highlights */
  --accent-tertiary: #f5f5f5;

  /* Text */
  --text-primary:   #ffffff;
  --text-secondary: rgba(255, 255, 255, 0.75);
  --text-tertiary:  rgba(255, 255, 255, 0.50);
  --text-disabled:  rgba(255, 255, 255, 0.30);

  /* Borders */
  --border-subtle:  rgba(255, 255, 255, 0.06);
  --border-default: rgba(255, 255, 255, 0.10);
  --border-strong:  rgba(255, 255, 255, 0.18);
  --border-accent:  rgba(6, 182, 212, 0.30);

  /* Semantic */
  --success: #10b981;
  --warning: #f97316;
  --danger:  #ef4444;
  --info:    #06b6d4;
}
```

**WAJIB:** Find & replace semua hex Plum/Copper di codebase:
- `#8B4A6B`, `#A8627F`, `#6B3852`, `#5C2F44` → ganti ke `--accent-primary` family
- `#C77D4A`, `#E09968`, `#9D5E33`, `#D4AF7A` → ganti ke `--accent-secondary` family
- Update juga di `glowPlugin` & `copperEdgePlugin` Chart.js custom plugins → rename jadi `cyanEdgePlugin` atau biarkan nama-nya tapi update warna hardcoded di dalamnya

---

## 🌊 SHADER BACKGROUND — 3 LAYER APPROACH

Karena tidak bisa pakai `@paper-design/shaders-react`, replika efek mesh gradient pakai **3 layer native** yang di-stack:

### Layer 1: SVG Filter Defs (paste di awal `<body>`)

```html
<svg class="defs-only" aria-hidden="true" width="0" height="0" style="position:absolute">
  <defs>
    <!-- Glass effect filter -->
    <filter id="glass-effect" x="-50%" y="-50%" width="200%" height="200%">
      <feTurbulence baseFrequency="0.005" numOctaves="1" result="noise" />
      <feDisplacementMap in="SourceGraphic" in2="noise" scale="0.3" />
      <feColorMatrix
        type="matrix"
        values="1 0 0 0 0.02
                0 1 0 0 0.02
                0 0 1 0 0.05
                0 0 0 0.9 0"
      />
    </filter>

    <!-- Text glow filter untuk hero logo -->
    <filter id="text-glow" x="-50%" y="-50%" width="200%" height="200%">
      <feGaussianBlur stdDeviation="2" result="coloredBlur" />
      <feMerge>
        <feMergeNode in="coloredBlur" />
        <feMergeNode in="SourceGraphic" />
      </feMerge>
    </filter>

    <!-- Animated noise filter — gerakan organik di background -->
    <filter id="bg-noise" x="0%" y="0%" width="100%" height="100%">
      <feTurbulence
        type="fractalNoise"
        baseFrequency="0.012"
        numOctaves="2"
        seed="2"
        result="turbulence"
      >
        <animate
          attributeName="baseFrequency"
          dur="40s"
          values="0.012;0.018;0.012"
          repeatCount="indefinite"
        />
      </feTurbulence>
      <feColorMatrix
        in="turbulence"
        type="matrix"
        values="0 0 0 0 0
                0 0 0 0 0
                0 0 0 0 0
                0 0 0 0.4 0"
      />
    </filter>

    <!-- Gradient untuk hero logo -->
    <linearGradient id="hero-gradient" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#ffffff" />
      <stop offset="30%" stop-color="#06b6d4" />
      <stop offset="70%" stop-color="#f97316" />
      <stop offset="100%" stop-color="#ffffff" />
    </linearGradient>
  </defs>
</svg>
```

### Layer 2: CSS Mesh Gradient (Background utama — animated)

Paste di `<body>` sebelum konten:

```html
<div class="shader-bg" aria-hidden="true">
  <div class="shader-mesh"></div>
  <div class="shader-mesh-2"></div>
  <div class="shader-noise"></div>
  <div class="shader-dim"></div>
</div>
```

CSS:

```css
/* Fixed di belakang konten, full viewport */
.shader-bg {
  position: fixed;
  inset: 0;
  z-index: -1;
  overflow: hidden;
  background: #000;
  pointer-events: none;
}

/* Mesh layer 1 — blob cyan dominant, slow drift */
.shader-mesh {
  position: absolute;
  inset: -20%;
  background:
    radial-gradient(circle at 20% 30%, #06b6d4 0%, transparent 35%),
    radial-gradient(circle at 80% 20%, #0891b2 0%, transparent 40%),
    radial-gradient(circle at 50% 80%, #164e63 0%, transparent 45%),
    radial-gradient(circle at 75% 65%, #f97316 0%, transparent 30%);
  filter: blur(60px) saturate(140%);
  opacity: 0.85;
  animation: meshDrift1 25s ease-in-out infinite;
  will-change: transform;
}

/* Mesh layer 2 — overlay orange/white untuk depth, slower */
.shader-mesh-2 {
  position: absolute;
  inset: -20%;
  background:
    radial-gradient(circle at 65% 40%, #f97316 0%, transparent 25%),
    radial-gradient(circle at 30% 70%, #ffffff 0%, transparent 20%),
    radial-gradient(circle at 90% 90%, #06b6d4 0%, transparent 30%);
  filter: blur(80px) saturate(130%);
  opacity: 0.45;
  mix-blend-mode: screen;
  animation: meshDrift2 35s ease-in-out infinite reverse;
  will-change: transform;
}

@keyframes meshDrift1 {
  0%, 100% { transform: translate(0%, 0%) rotate(0deg) scale(1); }
  25%      { transform: translate(3%, -2%) rotate(2deg) scale(1.05); }
  50%      { transform: translate(-2%, 3%) rotate(-1deg) scale(0.98); }
  75%      { transform: translate(2%, 2%) rotate(1deg) scale(1.02); }
}

@keyframes meshDrift2 {
  0%, 100% { transform: translate(0%, 0%) rotate(0deg) scale(1); }
  33%      { transform: translate(-4%, 3%) rotate(-2deg) scale(1.08); }
  66%      { transform: translate(3%, -3%) rotate(2deg) scale(0.95); }
}

/* Animated SVG noise overlay — gerakan organik */
.shader-noise {
  position: absolute;
  inset: 0;
  background-image: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='400' height='400'><filter id='n'><feTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='2' seed='5'/></filter><rect width='100%25' height='100%25' filter='url(%23n)' opacity='0.4'/></svg>");
  opacity: 0.05;
  mix-blend-mode: overlay;
}

/* CRITICAL: Dim overlay supaya konten readable */
.shader-dim {
  position: absolute;
  inset: 0;
  background:
    radial-gradient(ellipse at center top, rgba(0,0,0,0.3), rgba(0,0,0,0.65) 70%),
    rgba(0, 0, 0, 0.5);
  backdrop-filter: blur(2px);
}

/* Reduced motion fallback — static, no animation */
@media (prefers-reduced-motion: reduce) {
  .shader-mesh,
  .shader-mesh-2 {
    animation: none;
  }
}

/* Mobile — disable heavy filters, kurangi blur untuk performance */
@media (max-width: 768px) {
  .shader-mesh   { filter: blur(40px) saturate(120%); }
  .shader-mesh-2 { filter: blur(50px) saturate(120%); }
}
```

**Catatan kalibrasi `.shader-dim`:**
- Mulai dengan `rgba(0,0,0,0.5)` + radial overlay → check readability
- Kalau text susah dibaca → naikkan ke `0.6` atau `0.7`
- Kalau shader nyaris invisible → turunkan ke `0.4` atau `0.35`
- Sweet spot untuk dashboard content-heavy biasanya `0.50–0.65`

---

## 🎨 KOMPONEN SPECIFIC UPDATES

### Hero "evalsec." Logo

Existing logo text di `dashboard.html.j2` → tambahkan class & gradient:

```html
<h1 class="hero-logo">evalsec<span class="dot">.</span></h1>
```

```css
.hero-logo {
  font-family: 'Geist Sans', sans-serif;
  font-weight: 700;
  letter-spacing: -0.04em;
  font-size: clamp(3rem, 6vw, 5rem);
  background: linear-gradient(135deg,
    #ffffff 0%,
    #06b6d4 30%,
    #f97316 70%,
    #ffffff 100%
  );
  background-size: 200% auto;
  -webkit-background-clip: text;
  background-clip: text;
  -webkit-text-fill-color: transparent;
  filter: url(#text-glow);
  animation: heroShimmer 8s linear infinite;
}

@keyframes heroShimmer {
  0%   { background-position: 0% 50%; }
  50%  { background-position: 100% 50%; }
  100% { background-position: 0% 50%; }
}

.hero-logo .dot {
  color: #f97316;
  -webkit-text-fill-color: #f97316;
}
```

### Badge "BETA · V0.1.0" — Glass effect

```html
<div class="badge-glass">
  <span class="badge-line"></span>
  <span>BETA · V0.1.0</span>
</div>
```

```css
.badge-glass {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 6px 16px;
  border-radius: 999px;
  background: rgba(255, 255, 255, 0.05);
  backdrop-filter: blur(8px);
  border: 1px solid rgba(255, 255, 255, 0.10);
  position: relative;
  filter: url(#glass-effect);
  font-family: 'Geist Mono', monospace;
  font-size: 11px;
  letter-spacing: 0.12em;
  color: rgba(255, 255, 255, 0.9);
}

.badge-line {
  position: absolute;
  top: 0; left: 8px; right: 8px;
  height: 1px;
  background: linear-gradient(90deg,
    transparent,
    rgba(6, 182, 212, 0.5),
    transparent
  );
}
```

### Card Treatment — Glass with cyan accent

```css
.card-premium {
  background: rgba(8, 12, 18, 0.65);
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 16px;
  backdrop-filter: blur(16px) saturate(140%);
  -webkit-backdrop-filter: blur(16px) saturate(140%);
  position: relative;
  overflow: hidden;
  transition: border-color 200ms ease, background 200ms ease;
}

.card-premium:hover {
  border-color: rgba(6, 182, 212, 0.25);
  background: rgba(8, 12, 18, 0.75);
}

.card-featured::before {
  content: '';
  position: absolute;
  top: 0; left: 10%; right: 10%;
  height: 1px;
  background: linear-gradient(90deg,
    transparent,
    rgba(6, 182, 212, 0.6),
    rgba(249, 115, 22, 0.4),
    transparent
  );
}
```

### Chart.js — Update plugin colors

Cari custom plugins di inline `<script>`:

**`copperEdgePlugin` → rename jadi `cyanEdgePlugin`** (atau biarkan nama, ganti warnanya):
```javascript
// SEBELUM (copper)
ctx.strokeStyle = 'rgba(199, 125, 74, 0.5)';
// SESUDAH (cyan)
ctx.strokeStyle = 'rgba(6, 182, 212, 0.5)';
```

**`glowPlugin`** — update glow color:
```javascript
// SEBELUM (plum)
ctx.shadowColor = 'rgba(139, 74, 107, 0.3)';
// SESUDAH (cyan)
ctx.shadowColor = 'rgba(6, 182, 212, 0.25)';
```

### Composite Score Bar Chart (Chart.js config)

```javascript
{
  type: 'bar',
  data: {
    datasets: [{
      data: [...],
      backgroundColor: (ctx) => {
        const chart = ctx.chart;
        const {ctx: c, chartArea} = chart;
        if (!chartArea) return null;
        const gradient = c.createLinearGradient(
          chartArea.left, 0, chartArea.right, 0
        );
        gradient.addColorStop(0,    '#0891b2');
        gradient.addColorStop(0.6,  '#06b6d4');
        gradient.addColorStop(1,    'rgba(34, 211, 238, 0.7)');
        return gradient;
      },
      borderRadius: 2,
      borderSkipped: false,
    }]
  },
  options: { indexAxis: 'y', /* ... */ }
}
```

### Radar Chart — Per model colors

```javascript
const RADAR_COLORS = {
  deepseek_v4_pro:  { stroke: '#06b6d4', fill: 'rgba(6, 182, 212, 0.20)' },
  claude_sonnet_46: { stroke: '#f97316', fill: 'rgba(249, 115, 22, 0.15)' },
  kimi_k26:         { stroke: '#22d3ee', fill: 'rgba(34, 211, 238, 0.12)' },
  qwen_35:          { stroke: '#fb923c', fill: 'rgba(251, 146, 60, 0.10)' },
};
```

Grid lines:
```javascript
scales: {
  r: {
    grid: { color: 'rgba(255, 255, 255, 0.06)' },
    angleLines: { color: 'rgba(255, 255, 255, 0.08)' },
    pointLabels: {
      color: 'rgba(255, 255, 255, 0.5)',
      font: { family: 'Geist Mono', size: 10 }
    },
    ticks: { display: false, backdropColor: 'transparent' }
  }
}
```

### Baseline Bar Chart — Orange gradient

```javascript
backgroundColor: (ctx) => {
  const {ctx: c, chartArea} = ctx.chart;
  if (!chartArea) return null;
  const gradient = c.createLinearGradient(
    chartArea.left, 0, chartArea.right, 0
  );
  gradient.addColorStop(0,   '#ea580c');
  gradient.addColorStop(0.7, '#f97316');
  gradient.addColorStop(1,   'rgba(249, 115, 22, 0.6)');
  return gradient;
}
```

### Leaderboard rank #1 row highlight

```css
.rank-1 {
  background: linear-gradient(90deg,
    rgba(6, 182, 212, 0.10) 0%,
    rgba(6, 182, 212, 0.03) 50%,
    transparent 100%
  );
  border-left: 2px solid #06b6d4;
}
```

### Drill-down dimension bars

```css
.dimension-bar-llm {
  background: linear-gradient(90deg,
    rgba(6, 182, 212, 0.3),
    #06b6d4
  );
  height: 6px;
  border-radius: 1px;
}

.dimension-bar-baseline {
  background: linear-gradient(90deg,
    rgba(249, 115, 22, 0.3),
    #f97316
  );
  height: 6px;
  border-radius: 1px;
}
```

---

## ⚡ PERFORMANCE NOTES (penting untuk static hosting)

1. **CSS animations** pakai `transform` & `opacity` saja (GPU-accelerated) — sudah diaplikasikan via `will-change: transform`.

2. **SVG `<feTurbulence>` dengan `<animate>`** di-throttle Chrome ke ~30fps secara otomatis, jadi tidak akan kill CPU.

3. **Mobile fallback:** media query `(max-width: 768px)` mengurangi blur radius (60px → 40px) supaya tidak lag di low-end devices.

4. **Reduced motion:** `prefers-reduced-motion: reduce` mematikan semua animasi mesh — important untuk accessibility.

5. **Tidak ada WebGL** di solusi ini — jadi tidak ada concern crash di browser tanpa GPU acceleration. Pure CSS + SVG = jalan di mana saja.

6. **Tidak ada external assets** (kecuali Google Fonts yang sudah ada) → tetap 1 HTML file deploy ke S3, tidak ada additional network request.

---

## 🔧 EKSEKUSI ORDER di `dashboard.html.j2`

1. **Update CSS variables** di `<style>` — replace seluruh palette plum/copper ke cyan/orange
2. **Tambah SVG defs** (`<svg class="defs-only">`) tepat setelah `<body>` opening
3. **Tambah shader background div** (`<div class="shader-bg">`) setelah SVG defs, sebelum konten utama
4. **Update hero logo** dengan gradient text + filter
5. **Update badge styling** ke glass effect
6. **Update card styling** ke glass treatment
7. **Update Chart.js plugins & color configs** di inline `<script>`
8. **Test render** lalu kalibrasi `.shader-dim` opacity untuk readability

---

## ✅ ACCEPTANCE CRITERIA

- [ ] Tidak ada satupun npm package baru di dependency
- [ ] Output tetap **single static HTML file** yang bisa langsung deploy ke S3
- [ ] Background ada mesh gradient cyan-orange yang bergerak halus (~25s loop)
- [ ] Konten dashboard tetap readable (contrast min 4.5:1)
- [ ] Chart.js custom plugins (`glowPlugin`, `copperEdgePlugin`) sudah update warnanya
- [ ] Semua hex plum/copper sudah dihapus dari codebase
- [ ] Mobile: animation lebih ringan, tidak lag
- [ ] `prefers-reduced-motion` di-respect

---
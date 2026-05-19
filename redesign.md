# EvalSec Static Redesign Implementation Brief

Target: **static HTML/CSS/vanilla JS website deployable to AWS S3**  
Reference visual concept: `bg.md` infinite grid background, theme toggle, dark/light colors, typography, and button style.

---

## 1. Goal

Implement ulang website EvalSec supaya:

1. Background mengikuti konsep dari `bg.md`:
   - Infinite moving SVG grid.
   - Mouse hover spotlight / flashlight reveal effect.
   - Decorative blur spheres.
   - Full dark/light theme support.
2. Website tetap **static**, tidak perlu React, npm, shadcn, Tailwind, Framer Motion, atau lucide-react.
3. Deploy aman ke **AWS S3 static hosting**.
4. Ada **navbar maksimal 4 menu**.
5. Konten dipisahkan berdasarkan navbar/tab, bukan semua ditumpuk scroll panjang.
6. Warna, font style, theme toggle, dan button mengikuti rasa visual dari `bg.md`.

---

## 2. Important Constraint

Jangan pakai React implementation langsung dari `bg.md`. Itu memang component React/Tailwind/Framer Motion, tapi untuk website ini harus dikonversi ke:

```text
index.html
styles.css
script.js
```

Tidak perlu build step. Tidak perlu npm install. Tidak perlu bundler. Semua harus bisa dibuka langsung di browser dan diupload ke S3.

---

## 3. Navbar Requirement

Navbar maksimal **4 item**:

```text
Overview | Leaderboard | Models | Methodology
```

Jangan tambah menu lain seperti Baseline, Comparison, About, GitHub, Docs, dll di navbar utama. Kalau perlu GitHub/Docs, taruh sebagai button kecil di kanan navbar atau footer, bukan menu utama.

### Behavior

Navbar harus berfungsi sebagai **tab switcher**, bukan hanya anchor scroll.

Saat user klik:

- `Overview`: tampilkan hero, stats, dan quick comparison.
- `Leaderboard`: tampilkan leaderboard table dan chart ringkas.
- `Models`: tampilkan drill-down per model dengan filter/chip.
- `Methodology`: tampilkan cara kerja benchmark, scoring, dataset, limitations.

Konten section lain harus disembunyikan.

Jangan bikin user harus scroll panjang melewati semua informasi. Halaman boleh scroll di dalam tab kalau kontennya banyak, tapi bukan semua section ditampilkan sekaligus.

---

## 4. Recommended Page Structure

```html
<body>
  <div class="site-bg" aria-hidden="true">
    <svg class="grid grid-base"></svg>
    <svg class="grid grid-spotlight"></svg>
    <div class="orb orb-orange"></div>
    <div class="orb orb-primary"></div>
    <div class="orb orb-blue"></div>
  </div>

  <header class="navbar">
    <a class="brand" href="#">evalsec.</a>

    <nav class="nav-tabs" aria-label="Primary navigation">
      <button class="nav-tab is-active" data-tab="overview">Overview</button>
      <button class="nav-tab" data-tab="leaderboard">Leaderboard</button>
      <button class="nav-tab" data-tab="models">Models</button>
      <button class="nav-tab" data-tab="methodology">Methodology</button>
    </nav>

    <button class="theme-toggle" id="themeToggle" aria-label="Toggle theme">
      <span class="theme-icon theme-icon-moon">☾</span>
      <span class="theme-icon theme-icon-sun">☀</span>
    </button>
  </header>

  <main class="app-shell">
    <section id="overview" class="tab-panel is-active"></section>
    <section id="leaderboard" class="tab-panel"></section>
    <section id="models" class="tab-panel"></section>
    <section id="methodology" class="tab-panel"></section>
  </main>

  <footer class="footer"></footer>
</body>
```

---

## 5. Theme System From `bg.md`

`bg.md` uses semantic tokens like:

```text
bg-background
text-foreground
text-muted-foreground
bg-primary
text-primary-foreground
bg-secondary
text-secondary-foreground
border-border
```

Convert those into CSS variables.

### Light Mode Variables

Use light mode as default, like `bg.md` default state.

```css
:root {
  color-scheme: light;

  --background: #ffffff;
  --foreground: #0f172a;
  --muted-foreground: #64748b;
  --border: rgba(15, 23, 42, 0.12);

  --primary: #4f46e5;
  --primary-hover: #4338ca;
  --primary-border-hover: #6366f1;
  --primary-foreground: #ffffff;

  --secondary: #f1f5f9;
  --secondary-hover: #6d28d9;
  --secondary-border-hover: #8b5cf6;
  --secondary-foreground: #0f172a;

  --card: rgba(255, 255, 255, 0.72);
  --card-strong: rgba(255, 255, 255, 0.88);
  --grid: rgba(100, 116, 139, 0.75);

  --orb-orange: rgba(249, 115, 22, 0.40);
  --orb-primary: rgba(79, 70, 229, 0.30);
  --orb-blue: rgba(59, 130, 246, 0.40);

  --shadow-primary: rgba(67, 56, 202, 0.60);
  --shadow-secondary: rgba(109, 40, 217, 0.60);

  --font-sans: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  --font-mono: "JetBrains Mono", "SFMono-Regular", Consolas, monospace;
}
```

### Dark Mode Variables

```css
html.dark {
  color-scheme: dark;

  --background: #020617;
  --foreground: #f8fafc;
  --muted-foreground: #94a3b8;
  --border: rgba(248, 250, 252, 0.12);

  --primary: #6366f1;
  --primary-hover: #4338ca;
  --primary-border-hover: #6366f1;
  --primary-foreground: #ffffff;

  --secondary: rgba(148, 163, 184, 0.12);
  --secondary-hover: #6d28d9;
  --secondary-border-hover: #8b5cf6;
  --secondary-foreground: #f8fafc;

  --card: rgba(15, 23, 42, 0.68);
  --card-strong: rgba(15, 23, 42, 0.86);
  --grid: rgba(148, 163, 184, 0.70);

  --orb-orange: rgba(234, 88, 12, 0.20);
  --orb-primary: rgba(99, 102, 241, 0.24);
  --orb-blue: rgba(37, 99, 235, 0.20);

  --shadow-primary: rgba(67, 56, 202, 0.60);
  --shadow-secondary: rgba(109, 40, 217, 0.60);
}
```

Do not use the previous brown/sepia background. The only warm color allowed is the orange blur sphere from `bg.md`, and it must be decorative, not dominating the whole page.

---

## 6. Static Background Conversion

The original React version uses Framer Motion motion values and SVG pattern animation. Convert it into CSS/JS.

### CSS Background Layers

```css
body {
  margin: 0;
  min-height: 100vh;
  font-family: var(--font-sans);
  background: var(--background);
  color: var(--foreground);
  overflow-x: hidden;
}

.site-bg {
  position: fixed;
  inset: 0;
  z-index: -1;
  overflow: hidden;
  background: var(--background);
}

.grid {
  position: absolute;
  inset: 0;
  width: 100%;
  height: 100%;
  color: var(--grid);
  pointer-events: none;
}

.grid-base {
  opacity: 0.05;
}

.grid-spotlight {
  opacity: 0.40;
  mask-image: radial-gradient(300px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), black, transparent);
  -webkit-mask-image: radial-gradient(300px circle at var(--mouse-x, 50%) var(--mouse-y, 50%), black, transparent);
}

.orb {
  position: absolute;
  border-radius: 999px;
  pointer-events: none;
  filter: blur(120px);
}

.orb-orange {
  right: -20%;
  top: -20%;
  width: 40vw;
  height: 40vw;
  background: var(--orb-orange);
}

.orb-primary {
  right: 10%;
  top: -10%;
  width: 20vw;
  height: 20vw;
  background: var(--orb-primary);
  filter: blur(100px);
}

.orb-blue {
  left: -10%;
  bottom: -20%;
  width: 40vw;
  height: 40vw;
  background: var(--orb-blue);
}
```

### HTML SVG Pattern

Use two SVGs with identical pattern. JS will animate pattern `x` and `y`.

```html
<svg class="grid grid-base" aria-hidden="true">
  <defs>
    <pattern id="gridPatternBase" width="40" height="40" patternUnits="userSpaceOnUse" x="0" y="0">
      <path d="M 40 0 L 0 0 0 40" fill="none" stroke="currentColor" stroke-width="1"></path>
    </pattern>
  </defs>
  <rect width="100%" height="100%" fill="url(#gridPatternBase)"></rect>
</svg>

<svg class="grid grid-spotlight" aria-hidden="true">
  <defs>
    <pattern id="gridPatternSpotlight" width="40" height="40" patternUnits="userSpaceOnUse" x="0" y="0">
      <path d="M 40 0 L 0 0 0 40" fill="none" stroke="currentColor" stroke-width="1"></path>
    </pattern>
  </defs>
  <rect width="100%" height="100%" fill="url(#gridPatternSpotlight)"></rect>
</svg>
```

### JS Infinite Grid Animation

```js
const root = document.documentElement;
const basePattern = document.getElementById('gridPatternBase');
const spotlightPattern = document.getElementById('gridPatternSpotlight');

let gridSize = 40;
let offsetX = 0;
let offsetY = 0;
const speedX = 0.5;
const speedY = 0.5;

function animateGrid() {
  offsetX = (offsetX + speedX) % gridSize;
  offsetY = (offsetY + speedY) % gridSize;

  basePattern?.setAttribute('x', String(offsetX));
  basePattern?.setAttribute('y', String(offsetY));
  spotlightPattern?.setAttribute('x', String(offsetX));
  spotlightPattern?.setAttribute('y', String(offsetY));

  requestAnimationFrame(animateGrid);
}

animateGrid();

window.addEventListener('pointermove', (event) => {
  root.style.setProperty('--mouse-x', `${event.clientX}px`);
  root.style.setProperty('--mouse-y', `${event.clientY}px`);
});
```

Optional: do not include the grid density control panel. The EvalSec site does not need that control unless it is hidden behind a dev flag.

---

## 7. Theme Toggle Must Match `bg.md`

The theme toggle should be sticky/fixed at top right, circular, blurred, bordered, and animated.

### HTML

```html
<button class="theme-toggle" id="themeToggle" aria-label="Toggle theme">
  <span class="theme-icon moon-icon">☾</span>
  <span class="theme-icon sun-icon">☀</span>
</button>
```

### CSS

```css
.theme-toggle {
  position: fixed;
  top: 1rem;
  right: 1rem;
  z-index: 50;
  width: 48px;
  height: 48px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border-radius: 999px;
  border: 1px solid var(--border);
  background: color-mix(in srgb, var(--background) 50%, transparent);
  color: var(--foreground);
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.16);
  backdrop-filter: blur(12px);
  cursor: pointer;
  transition: transform 180ms ease, border-color 180ms ease, background 180ms ease;
}

.theme-toggle:hover {
  transform: scale(1.10);
}

.theme-toggle:active {
  transform: scale(0.95);
}

.theme-icon {
  position: absolute;
  font-size: 1.25rem;
  line-height: 1;
  transition: opacity 180ms ease, transform 180ms ease;
}

.moon-icon {
  color: #4f46e5;
  opacity: 1;
}

.sun-icon {
  color: #eab308;
  opacity: 0;
  transform: rotate(-45deg);
}

html.dark .moon-icon {
  opacity: 0;
  transform: rotate(12deg);
}

html.dark .sun-icon {
  opacity: 1;
  transform: rotate(0deg);
}

html.dark .theme-toggle:hover .sun-icon {
  transform: rotate(45deg);
}
```

### JS

```js
const themeToggle = document.getElementById('themeToggle');
const savedTheme = localStorage.getItem('theme');
const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;

if (savedTheme === 'dark' || (!savedTheme && prefersDark)) {
  document.documentElement.classList.add('dark');
}

function updateThemeMeta() {
  const meta = document.querySelector('meta[name="theme-color"]');
  const isDark = document.documentElement.classList.contains('dark');
  meta?.setAttribute('content', isDark ? '#020617' : '#ffffff');
}

updateThemeMeta();

themeToggle?.addEventListener('click', () => {
  const isDark = document.documentElement.classList.toggle('dark');
  localStorage.setItem('theme', isDark ? 'dark' : 'light');
  updateThemeMeta();
});
```

Add this in `<head>`:

```html
<meta name="theme-color" content="#ffffff">
```

---

## 8. Navbar Design

Navbar must feel integrated with the `bg.md` theme: translucent, blurred, rounded, and bordered.

```css
.navbar {
  position: sticky;
  top: 1rem;
  z-index: 40;
  width: min(1120px, calc(100% - 2rem));
  margin: 1rem auto 0;
  display: grid;
  grid-template-columns: auto 1fr auto;
  align-items: center;
  gap: 1rem;
  padding: 0.65rem 0.75rem;
  border: 1px solid var(--border);
  border-radius: 999px;
  background: color-mix(in srgb, var(--background) 64%, transparent);
  backdrop-filter: blur(16px);
  box-shadow: 0 20px 50px rgba(0,0,0,0.12);
}

.brand {
  padding-left: 0.75rem;
  color: var(--foreground);
  font-size: 1rem;
  font-weight: 700;
  letter-spacing: -0.04em;
  text-decoration: none;
}

.nav-tabs {
  display: flex;
  justify-content: center;
  gap: 0.25rem;
}

.nav-tab {
  border: 1px solid transparent;
  border-radius: 999px;
  padding: 0.55rem 0.9rem;
  background: transparent;
  color: var(--muted-foreground);
  font: 600 0.875rem/1 var(--font-sans);
  cursor: pointer;
  transition: color 160ms ease, background 160ms ease, border-color 160ms ease, transform 160ms ease;
}

.nav-tab:hover {
  color: var(--foreground);
  background: var(--secondary);
  transform: translateY(-1px);
}

.nav-tab.is-active {
  color: var(--primary-foreground);
  background: var(--primary);
  border-color: var(--primary-border-hover);
  box-shadow: 0 16px 36px -18px var(--shadow-primary);
}
```

On mobile, navbar should wrap gracefully:

```css
@media (max-width: 720px) {
  .navbar {
    position: sticky;
    top: 0.75rem;
    grid-template-columns: 1fr auto;
    border-radius: 24px;
  }

  .nav-tabs {
    grid-column: 1 / -1;
    justify-content: flex-start;
    overflow-x: auto;
    padding: 0.25rem;
  }

  .nav-tab {
    white-space: nowrap;
  }
}
```

---

## 9. Button Style Must Follow `bg.md`

Primary and secondary buttons should copy the interaction feeling from `bg.md`: scale up, move up, stronger shadow, and color shift.

```css
.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  min-height: 44px;
  padding: 0.75rem 1.35rem;
  border-radius: 0.5rem;
  border: 2px solid transparent;
  font-weight: 650;
  text-decoration: none;
  cursor: pointer;
  transition:
    transform 180ms cubic-bezier(.2,.8,.2,1),
    background 180ms ease,
    border-color 180ms ease,
    color 180ms ease,
    box-shadow 180ms ease;
}

.btn:hover {
  transform: translateY(-4px) scale(1.05);
}

.btn:active {
  transform: translateY(0) scale(0.98);
}

.btn-primary {
  background: var(--primary);
  color: var(--primary-foreground);
  box-shadow: 0 10px 24px rgba(0,0,0,0.14);
}

.btn-primary:hover {
  background: var(--primary-hover);
  border-color: var(--primary-border-hover);
  box-shadow: 0 25px 50px -12px var(--shadow-primary);
}

.btn-secondary {
  background: var(--secondary);
  color: var(--secondary-foreground);
}

.btn-secondary:hover {
  background: var(--secondary-hover);
  border-color: var(--secondary-border-hover);
  color: #ffffff;
  box-shadow: 0 25px 50px -12px var(--shadow-secondary);
}
```

---

## 10. Content Distribution Across 4 Tabs

### Tab 1: Overview

Show only high-level summary:

- Beta badge.
- Hero title: `EvalSec`.
- Subtitle: `DevSecOps LLM Benchmark`.
- One paragraph explaining what EvalSec measures.
- CTA buttons: `View Leaderboard`, `Read Methodology`.
- Metric cards: models tested, cases evaluated, top score, best value.
- Mini “leaderboard at a glance” with top 3 only.

Do not put full leaderboard here.

### Tab 2: Leaderboard

Show:

- Full leaderboard table.
- Sort controls.
- Compact chart: score by model.
- Optional notice: preliminary results / dataset size.

Move all baseline comparison details out of this tab unless they are summarized in one small card.

### Tab 3: Models

Show:

- Model selector chips.
- One active model detail card at a time.
- Metrics: score, reachability, prioritization, actionability, conciseness, cost.
- Strengths and weaknesses.

Do not render all model cards at once. The current long vertical stack is the problem.

Expected model UI:

```html
<div class="model-chips">
  <button class="chip is-active" data-model="deepseek">DeepSeek V4 Pro</button>
  <button class="chip" data-model="baseline-reachability">Baseline Reachability</button>
  <button class="chip" data-model="claude">Claude Sonnet 4.6</button>
</div>

<div class="model-panel is-active" data-model-panel="deepseek"></div>
<div class="model-panel" data-model-panel="baseline-reachability"></div>
<div class="model-panel" data-model-panel="claude"></div>
```

### Tab 4: Methodology

Show:

- How the benchmark works.
- What is tested.
- How score is calculated.
- Dataset information.
- Limitations.

Use accordion so it does not become a wall of text.

---

## 11. Tab Switching JS

```js
const navTabs = document.querySelectorAll('[data-tab]');
const panels = document.querySelectorAll('.tab-panel');

function activateTab(tabName) {
  navTabs.forEach((tab) => {
    tab.classList.toggle('is-active', tab.dataset.tab === tabName);
  });

  panels.forEach((panel) => {
    panel.classList.toggle('is-active', panel.id === tabName);
  });

  history.replaceState(null, '', `#${tabName}`);
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

navTabs.forEach((tab) => {
  tab.addEventListener('click', () => activateTab(tab.dataset.tab));
});

const initialTab = location.hash.replace('#', '') || 'overview';
if (document.getElementById(initialTab)) {
  activateTab(initialTab);
}
```

### CSS for Tab Panels

```css
.tab-panel {
  display: none;
  animation: panelIn 220ms ease both;
}

.tab-panel.is-active {
  display: block;
}

@keyframes panelIn {
  from {
    opacity: 0;
    transform: translateY(8px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}
```

---

## 12. Model Chip Switching JS

```js
const modelChips = document.querySelectorAll('[data-model]');
const modelPanels = document.querySelectorAll('[data-model-panel]');

modelChips.forEach((chip) => {
  chip.addEventListener('click', () => {
    const model = chip.dataset.model;

    modelChips.forEach((item) => {
      item.classList.toggle('is-active', item === chip);
    });

    modelPanels.forEach((panel) => {
      panel.classList.toggle('is-active', panel.dataset.modelPanel === model);
    });
  });
});
```

---

## 13. Card Styling

Keep card style aligned with `bg.md`: background/foreground variables, blurred surface, border, shadow.

```css
.card {
  border: 1px solid var(--border);
  border-radius: 1.25rem;
  background: var(--card);
  backdrop-filter: blur(16px);
  box-shadow: 0 24px 70px rgba(0,0,0,0.14);
}

.card-strong {
  background: var(--card-strong);
}

.metric-card {
  padding: 1.25rem;
}

.metric-value {
  font-size: clamp(2rem, 5vw, 3.75rem);
  font-weight: 650;
  letter-spacing: -0.06em;
  line-height: 1;
  font-variant-numeric: tabular-nums;
}

.metric-label {
  margin-top: 0.75rem;
  color: var(--muted-foreground);
  font-size: 0.75rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.12em;
}
```

---

## 14. Typography

Use the same clean, modern feeling as `bg.md`.

In HTML head:

```html
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
```

Recommended scale:

```css
.hero-title {
  font-size: clamp(3.5rem, 10vw, 7rem);
  font-weight: 700;
  letter-spacing: -0.075em;
  line-height: 0.92;
}

.section-title {
  font-size: clamp(2rem, 5vw, 3.5rem);
  font-weight: 650;
  letter-spacing: -0.055em;
}

.muted {
  color: var(--muted-foreground);
}

.mono {
  font-family: var(--font-mono);
}
```

---

## 15. Layout Width and Spacing

```css
.app-shell {
  width: min(1120px, calc(100% - 2rem));
  margin: 0 auto;
  padding: clamp(3rem, 8vw, 6rem) 0 4rem;
}

.hero {
  min-height: calc(100vh - 120px);
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  text-align: center;
}

.stack-lg {
  display: grid;
  gap: 1.5rem;
}

.metrics-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 1rem;
}

@media (max-width: 900px) {
  .metrics-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}

@media (max-width: 520px) {
  .metrics-grid {
    grid-template-columns: 1fr;
  }
}
```

---

## 16. S3 Static Deployment Notes

Because this is static:

1. Use only relative paths:

```html
<link rel="stylesheet" href="./styles.css">
<script src="./script.js" defer></script>
```

2. Avoid client-side routes like `/leaderboard`. Use hash tabs:

```text
/#overview
/#leaderboard
/#models
/#methodology
```

3. Make `index.html` both index document and error document in S3 static hosting.
4. No npm build output should be required.
5. Use `localStorage` for theme preference.
6. Use no server-side API unless existing JSON files are hosted as static assets.

Optional static data structure:

```text
/data/results.json
/data/models.json
```

Then fetch them using:

```js
fetch('./data/results.json')
```

---

## 17. Implementation Checklist for Claude VS Code

1. Open the current static website files.
2. Create or update:

```text
index.html
styles.css
script.js
```

3. Replace existing background with the static infinite grid implementation above.
4. Add semantic CSS variables for light and dark mode.
5. Add fixed circular theme toggle exactly like the `bg.md` concept.
6. Add sticky navbar with exactly 4 items:

```text
Overview | Leaderboard | Models | Methodology
```

7. Convert navbar into tab switching behavior.
8. Move existing content into the correct tab panels.
9. Hide inactive panels.
10. In `Models`, do not show all model cards at once. Use chips/selectors.
11. Use the button styles above for all primary/secondary actions.
12. Remove the current brown/sepia page-wide color treatment.
13. Test both themes.
14. Test direct hash links:

```text
/#overview
/#leaderboard
/#models
/#methodology
```

15. Confirm the page works by opening `index.html` directly without npm.

---

## 18. Expected Result

The final website should feel like:

- A premium interactive benchmark product.
- Technical and modern like the infinite grid demo.
- Clean in both dark and light mode.
- Not too long vertically.
- Easy to navigate using 4 tabs.
- Fully static and deployable to AWS S3.

The final site must not feel like:

- A long single-page dump of charts.
- A brown/sepia dashboard.
- A React-only component that requires npm.
- A website where every model card is visible at once.

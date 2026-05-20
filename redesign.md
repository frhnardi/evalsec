# 🔧 EvalSec — Patch v4: Calm Text + Chart Theming

> Soften text colors (GitHub Dark style), fix chart label visibility di dark mode, amber TRUNCATED badge. Patch atas v3.

---

## FIX 1: Replace Text Colors di `:root` dan `html.dark`

**Find di `:root` (light mode), replace 2 lines:**

```css
:root {
  /* ... */
  --foreground: #171717;
  --muted-foreground: rgba(23, 23, 23, 0.65);
  --subtle-foreground: rgba(23, 23, 23, 0.45);
  --disabled-foreground: rgba(23, 23, 23, 0.30);
  /* ... */
}
```

**Find di `html.dark`, replace 2 lines:**

```css
html.dark {
  /* ... */
  --foreground: #EDEDED;
  --muted-foreground: rgba(237, 237, 237, 0.65);
  --subtle-foreground: rgba(237, 237, 237, 0.45);
  --disabled-foreground: rgba(237, 237, 237, 0.30);
  /* ... */
}
```

**WAJIB hapus dari kedua block:**
```css
/* DELETE these lines if present: */
--foreground: #000000;
--foreground: #FFFFFF;
--muted-foreground: #6B7280;
--muted-foreground: #A1A1AA;
```

---

## FIX 2: Apply Opacity Tier Hierarchy

**Tambahkan di `styles.css`:**

```css
/* Text hierarchy tiers */
.text-primary    { color: var(--foreground); }
.text-muted      { color: var(--muted-foreground); }
.text-subtle     { color: var(--subtle-foreground); }
.text-disabled   { color: var(--disabled-foreground); }

/* Monospace IDs (deepseek_v4_pro, baseline_cvss, dll) — subtle tier */
.mono,
code,
.model-id,
[class*="font-mono"] {
  color: var(--subtle-foreground);
  font-family: var(--font-mono);
}

/* Section descriptions / captions — muted tier */
.section-subtitle,
.card-subtitle,
.caption {
  color: var(--muted-foreground);
}

/* Table headers (uppercase RANK, MODEL, SCORE) — muted tier */
th,
.table-header {
  color: var(--muted-foreground);
}

/* Metric labels (MODELS TESTED, TOP SCORE) — keep current uppercase + muted */
.metric-label,
[class*="metric-label"] {
  color: var(--muted-foreground);
}
```

---

## FIX 3: Chart.js Global Theme (CRITICAL — label invisible di dark mode)

**Find di `script.js`** — TEPAT SEBELUM chart pertama di-instantiate (`new Chart(...)`).

**Tambahkan helper function + global config:**

```js
// ============================================
// CHART.JS THEMING — sync dengan CSS variables
// ============================================
function getThemeColors() {
  const styles = getComputedStyle(document.documentElement);
  const isDark = document.documentElement.classList.contains('dark');
  return {
    text:       isDark ? '#EDEDED' : '#171717',
    textMuted:  isDark ? 'rgba(237, 237, 237, 0.65)' : 'rgba(23, 23, 23, 0.65)',
    textSubtle: isDark ? 'rgba(237, 237, 237, 0.45)' : 'rgba(23, 23, 23, 0.45)',
    grid:       isDark ? 'rgba(237, 237, 237, 0.08)' : 'rgba(23, 23, 23, 0.08)',
    axis:       isDark ? 'rgba(237, 237, 237, 0.20)' : 'rgba(23, 23, 23, 0.15)',
    barPrimary: isDark ? '#EDEDED' : '#171717',
    barMuted:   isDark ? 'rgba(237, 237, 237, 0.65)' : 'rgba(23, 23, 23, 0.65)',
  };
}

function applyChartDefaults() {
  const c = getThemeColors();
  Chart.defaults.color = c.textMuted;
  Chart.defaults.borderColor = c.grid;
  Chart.defaults.font.family = "'Inter', ui-sans-serif, system-ui, sans-serif";
  Chart.defaults.font.size = 11;
  Chart.defaults.plugins.legend.labels.color = c.text;
  Chart.defaults.plugins.tooltip.backgroundColor = c.barPrimary;
  Chart.defaults.plugins.tooltip.titleColor = isDarkMode() ? '#0A0A0A' : '#FAFAFA';
  Chart.defaults.plugins.tooltip.bodyColor = isDarkMode() ? '#0A0A0A' : '#FAFAFA';
}

function isDarkMode() {
  return document.documentElement.classList.contains('dark');
}

// Call BEFORE any chart instantiation
applyChartDefaults();
```

**WAJIB:** function `applyChartDefaults()` harus dipanggil **sebelum** `new Chart(...)` pertama.

---

## FIX 4: Per-Chart Color Configs

**Find Composite Bar Chart config, update scales & dataset colors:**

```js
// Composite Bar Chart
new Chart(compositeCtx, {
  type: 'bar',
  data: {
    labels: [...],
    datasets: [{
      data: [...],
      backgroundColor: function(ctx) {
        return getThemeColors().barPrimary;
      },
      borderRadius: 4,
      borderSkipped: false,
    }]
  },
  options: {
    indexAxis: 'y',
    scales: {
      x: {
        grid:   { color: getThemeColors().grid },
        ticks:  { color: getThemeColors().textMuted },
        border: { color: getThemeColors().axis },
      },
      y: {
        grid:   { display: false },
        ticks:  { color: getThemeColors().text, font: { size: 12, weight: '500' } },
        border: { color: getThemeColors().axis },
      },
    },
    plugins: { legend: { display: false } },
  }
});
```

**Find Radar Chart config:**

```js
// Radar Chart
new Chart(radarCtx, {
  type: 'radar',
  data: {
    labels: [...],  // FORMAT, COVERAGE, dll
    datasets: [
      {
        label: 'DeepSeek V4 Pro',
        data: [...],
        borderColor: getThemeColors().barPrimary,
        backgroundColor: isDarkMode() ? 'rgba(237, 237, 237, 0.15)' : 'rgba(23, 23, 23, 0.10)',
        borderWidth: 1.5,
        pointBackgroundColor: getThemeColors().barPrimary,
        pointRadius: 3,
      },
      {
        label: 'Claude Sonnet 4.6',
        data: [...],
        borderColor: getThemeColors().textMuted,
        backgroundColor: 'rgba(156, 163, 175, 0.10)',
        borderWidth: 1.5,
        pointRadius: 3,
      },
      // ... apply similar logic untuk Kimi & Qwen (gunakan textSubtle, textDisabled)
    ]
  },
  options: {
    scales: {
      r: {
        grid:        { color: getThemeColors().grid },
        angleLines:  { color: getThemeColors().grid },
        pointLabels: { color: getThemeColors().textMuted, font: { family: 'JetBrains Mono', size: 10 } },
        ticks: {
          color: getThemeColors().textSubtle,
          backdropColor: 'transparent',
          font: { size: 9 }
        },
      }
    },
    plugins: {
      legend: {
        labels: { color: getThemeColors().text, font: { size: 11 } }
      }
    }
  }
});
```

**Find Baseline Horizontal Bar Chart:**

```js
new Chart(baselineCtx, {
  type: 'bar',
  data: {
    labels: [...],  // Baseline: Reachability, dll
    datasets: [{
      data: [...],
      backgroundColor: getThemeColors().barMuted,
      borderRadius: 4,
    }]
  },
  options: {
    indexAxis: 'y',
    scales: {
      x: {
        grid:   { color: getThemeColors().grid },
        ticks:  { color: getThemeColors().textMuted },
        border: { color: getThemeColors().axis },
      },
      y: {
        grid:   { display: false },
        ticks:  { color: getThemeColors().text, font: { size: 12, weight: '500' } },
        border: { color: getThemeColors().axis },
      }
    },
    plugins: { legend: { display: false } }
  }
});
```

---

## FIX 5: Re-render Charts saat Theme Toggle

**Find theme toggle event handler (kemungkinan `themeToggle.addEventListener('click', ...)`), tambahkan logic re-render:**

```js
// Simpan reference ke semua chart instances
const chartInstances = []; // push setiap chart ke sini saat instantiate
// Contoh: const composite = new Chart(...); chartInstances.push(composite);

themeToggle.addEventListener('click', () => {
  document.documentElement.classList.toggle('dark');
  localStorage.setItem('theme', isDarkMode() ? 'dark' : 'light');

  // Re-apply Chart.js defaults dengan colors baru
  applyChartDefaults();

  // Update setiap chart manually karena Chart.js cache di canvas
  chartInstances.forEach(chart => {
    const c = getThemeColors();

    // Update datasets
    chart.data.datasets.forEach((ds, idx) => {
      if (chart.config.type === 'bar') {
        ds.backgroundColor = idx === 0 ? c.barPrimary : c.barMuted;
      } else if (chart.config.type === 'radar') {
        // Map ulang colors per dataset index
        const colors = [c.barPrimary, c.textMuted, c.textSubtle, 'rgba(156, 163, 175, 0.6)'];
        ds.borderColor = colors[idx] || c.textSubtle;
        ds.pointBackgroundColor = colors[idx] || c.textSubtle;
      }
    });

    // Update scales
    if (chart.options.scales) {
      Object.values(chart.options.scales).forEach(scale => {
        if (scale.grid)       scale.grid.color = c.grid;
        if (scale.ticks)      scale.ticks.color = scale === chart.options.scales.y ? c.text : c.textMuted;
        if (scale.border)     scale.border.color = c.axis;
        if (scale.angleLines) scale.angleLines.color = c.grid;
        if (scale.pointLabels) scale.pointLabels.color = c.textMuted;
      });
    }

    // Update legend
    if (chart.options.plugins?.legend?.labels) {
      chart.options.plugins.legend.labels.color = c.text;
    }

    chart.update('none');  // 'none' = no animation, instant swap
  });
});
```

**CRITICAL:** Pastikan setiap chart di-push ke `chartInstances` array saat dibuat:
```js
const compositeChart = new Chart(compositeCtx, {...});
chartInstances.push(compositeChart);
```

---

## FIX 6: TRUNCATED Badge — Amber Soft Warning

**Find CSS untuk badge truncated (kemungkinan `.badge-truncated`, `.truncated`, atau inline style):**

```css
.badge-truncated,
.truncated,
[data-status="truncated"] {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 3px 10px;
  border-radius: 999px;
  font-size: 10px;
  font-weight: 600;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  font-family: var(--font-mono);

  /* Amber soft — warm warning, not harsh */
  background: rgba(251, 191, 36, 0.10);
  border: 1px solid rgba(251, 191, 36, 0.30);
  color: #D97706;
}

html.dark .badge-truncated,
html.dark .truncated,
html.dark [data-status="truncated"] {
  background: rgba(251, 191, 36, 0.08);
  border: 1px solid rgba(251, 191, 36, 0.25);
  color: #FBBF24;  /* lighter amber untuk dark bg */
}

/* Dot indicator di depan badge */
.badge-truncated::before,
.truncated::before {
  content: '';
  width: 5px;
  height: 5px;
  border-radius: 50%;
  background: currentColor;
  display: inline-block;
}
```

**Also update warning text di baris bawah** ("Response exceeded max_tokens — JSON truncated..."):

```css
.truncated-message,
.warning-message {
  color: rgba(217, 119, 6, 0.85);
  font-size: 11px;
  line-height: 1.4;
}

html.dark .truncated-message,
html.dark .warning-message {
  color: rgba(251, 191, 36, 0.75);
}
```

---

## VERIFICATION

**Dark mode check:**
- [ ] Composite bar chart: label model **terbaca jelas** (DeepSeek V4 Pro, dst)
- [ ] Radar chart: FORMAT/COVERAGE/PRIORITY ORDER/dll **terbaca jelas**
- [ ] Radar tick numbers (25, 50, 75, 100) **terbaca**
- [ ] Baseline bar: label kiri & axis numbers **terbaca**
- [ ] Legend bawah radar **terbaca**
- [ ] Text "DeepSeek V4 Pro" di leaderboard table tidak harsh white

**Light mode check:**
- [ ] Composite bar chart: bar **terlihat** (sebelumnya bar invisible/abu sangat tipis)
- [ ] Semua text dark, tidak pure black harsh

**TRUNCATED badge:**
- [ ] Light mode: amber soft `#D97706` text, background tipis
- [ ] Dark mode: amber lebih terang `#FBBF24`, tetap soft

**Theme toggle:**
- [ ] Switch theme → chart **langsung update warnanya**, tidak butuh reload
- [ ] Tidak ada flicker saat switch

**Hierarchy:**
- [ ] Headings & metric numbers paling terang (100% foreground)
- [ ] Body text sedikit muted (65%)
- [ ] Model IDs monospace (deepseek_v4_pro) lebih subtle (45%)
- [ ] Disabled/empty values paling samar (30%)

---

## GREP AUDIT

```bash
grep -ic "#FFFFFF\|#000000" styles.css
# expected: minimal (mostly diganti var)

grep -c "getThemeColors\|applyChartDefaults" script.js
# expected: >= 5

grep -c "chartInstances" script.js
# expected: >= 2 (declare + push + iterate)

grep -c "EDEDED\|171717" styles.css
# expected: >= 4
```

---

**Jangan ubah struktur layout, hanya text colors + chart configs + truncated badge. Test theme toggle di kedua mode setelah selesai.**

/**
 * Arithmetic contrast measurer for the surfaces axe declines to compute.
 *
 * axe-core files "background color could not be determined due to a background
 * gradient / pseudo element" under `incomplete`, which never reaches an
 * assertion on `results.violations` — so real AA failures hide there. On this
 * page 199 of axe's nodes land in exactly that bucket, because the hero sits in
 * a radial teal glow and several panels carry gradient rules.
 *
 * This measures the ratio the way a reader experiences it, from rendered pixels:
 *
 *   1. screenshot the page as it paints (A);
 *   2. screenshot it again with every glyph made transparent (B);
 *   3. pixels that differ between A and B are exactly the glyph coverage, and at
 *      those coordinates B is the surface the text was drawn on.
 *
 * Because B comes from the renderer, gradients, pseudo-element overlays and
 * translucent panels arrive already composited — no colour parsing or manual
 * alpha blending of the background is involved. The foreground is taken from
 * computed style rather than from pixels: at 10px even the most-covered glyph
 * pixel is partly antialiased and reads ~0.5:1 lighter than the real colour,
 * which manufactures failures. Element `opacity` is applied analytically on top.
 *
 * Used two ways: `measure()` is the gate in e2e/contrast.spec.ts, and running
 * this file directly gives the same numbers interactively.
 *
 *   node contrast/measure.mjs [url] [--theme=light|dark] [--width=N] [--height=N]
 */

/** Relative luminance, WCAG 2.x definition. */
export function luminance([r, g, b]) {
  const ch = [r, g, b].map((c) => {
    const v = c / 255;
    return v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * ch[0] + 0.7152 * ch[1] + 0.0722 * ch[2];
}

/** Contrast ratio between two opaque colours. */
export function ratio(a, b) {
  const l1 = luminance(a);
  const l2 = luminance(b);
  return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
}

/** Translucent text over an opaque surface: what the eye actually receives. */
function composite(fg, alpha, bg) {
  return [0, 1, 2].map((i) => fg[i] * alpha + bg[i] * (1 - alpha));
}

/**
 * Wait until nothing is animating and stays that way. A single empty batch is
 * not enough — one wave of transitions finishing can start the next — so
 * require quiescence to hold across several consecutive frames.
 */
export async function settle(page, timeout = 15_000) {
  await page.waitForFunction(
    () => {
      const w = window;
      const running = document.getAnimations().filter((a) => a.playState === 'running').length;
      w.__quietFrames = running === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 5;
    },
    undefined,
    { timeout, polling: 'raf' },
  );
}

/**
 * Measure every text node on the page as it currently stands. The caller owns
 * navigation, theme and state; this only reads, and restores what it touches.
 */
export async function measure(page) {
  // Sample from a known scroll offset. Range rects are document coordinates,
  // but a sticky header paints wherever the viewport currently sits, so
  // measuring mid-scroll charges body text for pixels the header covers.
  await page.evaluate(() => window.scrollTo(0, 0));
  await settle(page);

  // One entry per text node, located by its own Range rects so a parent is
  // never charged for a child's glyphs.
  const targets = await page.evaluate(() => {
    /** Normalise any CSS colour syntax Chrome may report to [r,g,b,a] 0-255. */
    const parseColor = (value) => {
      const nums = value.match(/-?[\d.]+(?:e-?\d+)?/g)?.map(Number) ?? [];
      if (nums.length < 3) return [0, 0, 0, 1];
      // color(srgb 0.49 0.9 0.83) reports channels in 0-1, rgb() in 0-255.
      const scale = /^color\(/i.test(value.trim()) ? 255 : 1;
      return [nums[0] * scale, nums[1] * scale, nums[2] * scale, nums[3] ?? 1];
    };
    const out = [];
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    for (let node = walker.nextNode(); node; node = walker.nextNode()) {
      const text = (node.textContent ?? '').trim();
      if (!text) continue;
      const el = node.parentElement;
      if (!el || el.closest('script,style,noscript')) continue;
      // WCAG 1.4.3 exempts text in an inactive user-interface component, and
      // axe skips those too; measuring them only manufactures failures.
      if (el.closest('[disabled]') || el.closest('[aria-disabled="true"]')) continue;
      const cs = getComputedStyle(el);
      if (cs.visibility === 'hidden' || cs.display === 'none' || Number(cs.opacity) === 0) continue;

      const range = document.createRange();
      range.selectNodeContents(node);
      // Clip each line box to every scrolling/overflow-hidden ancestor. Range
      // rects are geometric, so a row scrolled out of an `overflow: auto` list
      // still reports a position, and sampling there reads whatever else
      // happens to paint at those page coordinates.
      const clips = [];
      for (let a = el; a && a !== document.documentElement; a = a.parentElement) {
        const ac = getComputedStyle(a);
        if (ac.overflowX !== 'visible' || ac.overflowY !== 'visible')
          clips.push(a.getBoundingClientRect());
      }
      const clip = (r) => {
        let { left, top, right, bottom } = r;
        for (const c of clips) {
          left = Math.max(left, c.left);
          top = Math.max(top, c.top);
          right = Math.min(right, c.right);
          bottom = Math.min(bottom, c.bottom);
        }
        return { x: left, y: top, width: right - left, height: bottom - top };
      };
      const rects = [...range.getClientRects()]
        .map(clip)
        .filter((r) => r.width >= 1 && r.height >= 1);
      if (!rects.length) continue;

      const rgba = parseColor(cs.color);
      // Element opacity applies to the whole subtree it paints, so it dims the
      // glyph against whatever is already composited behind it.
      let alpha = rgba[3];
      for (let a = el; a && a !== document.documentElement; a = a.parentElement) {
        const o = Number(getComputedStyle(a).opacity);
        if (!Number.isNaN(o) && o < 1) alpha *= o;
      }
      const fontSize = Number.parseFloat(cs.fontSize);
      const weight = Number(cs.fontWeight) || 400;
      // WCAG large text: >= 24px, or >= 18.66px when bold.
      const large = fontSize >= 24 || (fontSize >= 18.66 && weight >= 700);
      let path = el.tagName.toLowerCase();
      if (el.id) path += `#${el.id}`;
      const cls = el.getAttribute('class');
      if (cls) path += `.${cls.trim().split(/\s+/).join('.')}`;
      out.push({
        path,
        text: text.slice(0, 44),
        fg: [rgba[0], rgba[1], rgba[2]],
        alpha,
        large,
        rects: rects.map((r) => ({
          x: r.x + window.scrollX,
          y: r.y + window.scrollY,
          w: r.width,
          h: r.height,
        })),
      });
    }
    return out;
  });

  const shotA = (await page.screenshot({ fullPage: true })).toString('base64');
  const hider = await page.addStyleTag({
    content: `*, *::before, *::after {
      color: transparent !important;
      -webkit-text-fill-color: transparent !important;
      text-shadow: none !important;
      caret-color: transparent !important;
    }`,
  });
  const shotB = (await page.screenshot({ fullPage: true })).toString('base64');
  // Leave the page as it was found; callers may keep scanning it.
  await hider.evaluate((node) => node.remove());

  const report = await page.evaluate(
    async ({ shotA, shotB, targets }) => {
      const load = async (b64) => {
        const img = new Image();
        img.src = `data:image/png;base64,${b64}`;
        await img.decode();
        const c = document.createElement('canvas');
        c.width = img.naturalWidth;
        c.height = img.naturalHeight;
        const ctx = c.getContext('2d', { willReadFrequently: true });
        ctx.drawImage(img, 0, 0);
        return { ctx, w: c.width, h: c.height };
      };
      const A = await load(shotA);
      const B = await load(shotB);
      const scale = A.w / document.documentElement.scrollWidth;

      return targets.map((t) => {
        // Glyph pixels are those that changed when the text went transparent.
        const px = [];
        for (const r of t.rects) {
          const x = Math.max(0, Math.round(r.x * scale));
          const y = Math.max(0, Math.round(r.y * scale));
          const w = Math.min(A.w - x, Math.max(1, Math.round(r.w * scale)));
          const h = Math.min(A.h - y, Math.max(1, Math.round(r.h * scale)));
          if (w <= 0 || h <= 0) continue;
          const da = A.ctx.getImageData(x, y, w, h).data;
          const db = B.ctx.getImageData(x, y, w, h).data;
          for (let i = 0; i < da.length; i += 4) {
            const delta =
              Math.abs(da[i] - db[i]) +
              Math.abs(da[i + 1] - db[i + 1]) +
              Math.abs(da[i + 2] - db[i + 2]);
            if (delta > 12) px.push({ delta, b: [db[i], db[i + 1], db[i + 2]] });
          }
        }
        if (!px.length) return { ...t, backgrounds: [] };
        // Core glyphs: near-full coverage, not the antialiased rim.
        const maxDelta = px.reduce((m, p) => Math.max(m, p.delta), 0);
        const tally = new Map();
        for (const p of px) {
          if (p.delta < maxDelta * 0.9) continue;
          const key = p.b.join(',');
          const hit = tally.get(key) ?? { bg: p.b, count: 0 };
          hit.count += 1;
          tally.set(key, hit);
        }
        const backgrounds = [...tally.values()].sort((x, y) => y.count - x.count);
        return { ...t, backgrounds: backgrounds.slice(0, 24) };
      });
    },
    { shotA, shotB, targets },
  );

  const rows = [];
  for (const r of report) {
    if (!r.backgrounds?.length) continue;
    // Ignore single stray pixels; a real surface backs several core glyphs.
    const solid = r.backgrounds.filter((p) => p.count >= 3);
    if (!solid.length) continue;
    let worst = Infinity;
    let worstBg = null;
    let worstFg = null;
    for (const p of solid) {
      const fg = composite(r.fg, r.alpha, p.bg);
      const c = ratio(fg, p.bg);
      if (c < worst) {
        worst = c;
        worstBg = p.bg;
        worstFg = fg.map(Math.round);
      }
    }
    const need = r.large ? 3 : 4.5;
    rows.push({
      path: r.path,
      text: r.text,
      fg: worstFg,
      bg: worstBg,
      worst: Number(worst.toFixed(2)),
      need,
      pass: worst >= need,
    });
  }
  rows.sort((a, b) => a.worst - b.worst);
  return rows;
}

/** One line per failure, shared by the CLI and the gate's failure message. */
export function formatFailures(rows) {
  return rows
    .filter((r) => !r.pass)
    .map(
      (r) =>
        `${r.worst.toFixed(2)}:1 (need ${r.need}) ${r.path} — ` +
        `rgb(${r.fg.join(',')}) on rgb(${r.bg.join(',')}) "${r.text}"`,
    );
}

/* ── CLI ─────────────────────────────────────────────────────────────────── */

if (process.argv[1]?.endsWith('measure.mjs')) {
  const { chromium } = await import('playwright');
  const args = process.argv.slice(2);
  const flag = (name, fallback) => {
    const hit = args.find((a) => a.startsWith(`--${name}=`));
    return hit ? hit.slice(name.length + 3) : fallback;
  };
  const url =
    args.find((a) => !a.startsWith('--')) ?? 'http://localhost:4636/crypto-lab-envelope-kms/';
  const theme = flag('theme', 'dark');
  const width = Number(flag('width', '1280'));
  const height = Number(flag('height', '900'));

  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width, height }, colorScheme: 'dark' });
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto(url, { waitUntil: 'load' });
  await page.evaluate(() => {
    for (const d of document.querySelectorAll('details')) d.open = true;
  });
  const rows = await measure(page);
  await browser.close();

  const fails = formatFailures(rows);
  console.info(`theme=${theme} width=${width} measured=${rows.length} failing=${fails.length}`);
  for (const line of fails) console.info(`  ${line}`);
  if (!fails.length && rows.length) {
    console.info(`  lowest passing: ${rows[0].worst.toFixed(2)}:1 ${rows[0].path}`);
  }
  process.exit(fails.length ? 1 : 0);
}

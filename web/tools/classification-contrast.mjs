#!/usr/bin/env node
/**
 * What mix of the classification colour can carry the badge's own label.
 *
 * The five classification colours are **locked** (`docs/09 §16a`): a tenant
 * cannot recolour `Restricted`, and neither can this file. What is *not* locked
 * is the reference's badge recipe — `color: color-mix(in srgb, var(--cc) 82%,
 * var(--fg))` over an 11% tint of the same colour — and axe measured that recipe
 * at 3.68:1 for `Public` and 4.28:1 for `Confidential` in the light theme,
 * against `docs/09 §15`'s 4.5:1.
 *
 * So this searches for the largest mix ratio that clears 4.5:1 for all five
 * levels in both themes, keeping the hue as close to the reference as the
 * contrast rule allows. The dot beside the label stays at pure `--cc` and is
 * untouched, which is where the locked colour actually does its work.
 *
 * Run it when a token changes. It prints a table; it does not write CSS.
 */

const LEVELS = {
  public: '#8A97A6',
  internal: '#2F6FDB',
  confidential: '#B7791F',
  highlyConfidential: '#D2591C',
  restricted: '#C2273A',
};

const THEMES = {
  light: { sheet: '#FFFFFF', fg: '#141412' },
  dark: { sheet: '#161615', fg: '#F2F2EF' },
};

const parse = (hex) => [1, 3, 5].map((i) => Number.parseInt(hex.slice(i, i + 2), 16));
const mix = (a, b, ratio) => a.map((channel, i) => channel * ratio + b[i] * (1 - ratio));

function luminance([r, g, b]) {
  const channel = (value) => {
    const v = value / 255;
    return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
}

function contrast(a, b) {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

const BACKGROUND_TINT = 0.11; // the reference's `color-mix(… 11%, transparent)`

function worstAt(ratio) {
  let worst = Infinity;
  for (const [theme, { sheet, fg }] of Object.entries(THEMES)) {
    for (const [level, hex] of Object.entries(LEVELS)) {
      const cc = parse(hex);
      const background = mix(cc, parse(sheet), BACKGROUND_TINT);
      const text = mix(cc, parse(fg), ratio);
      const value = contrast(text, background);
      if (value < worst) worst = value;
      if (process.env['VERBOSE'] !== undefined) {
        console.log(`  ${theme.padEnd(6)} ${level.padEnd(20)} ${value.toFixed(2)}`);
      }
    }
  }
  return worst;
}

let best = 0;
for (let ratio = 0.9; ratio >= 0.2; ratio -= 0.01) {
  if (worstAt(ratio) >= 4.5) {
    best = ratio;
    break;
  }
}

console.log(`reference recipe (82%):   worst ${worstAt(0.82).toFixed(2)}:1`);
console.log(`largest ratio at AA:      ${(best * 100).toFixed(0)}%  worst ${worstAt(best).toFixed(2)}:1`);
console.log('\nper level, at the chosen ratio:');
for (const [theme, { sheet, fg }] of Object.entries(THEMES)) {
  for (const [level, hex] of Object.entries(LEVELS)) {
    const cc = parse(hex);
    const value = contrast(mix(cc, parse(fg), best), mix(cc, parse(sheet), BACKGROUND_TINT));
    console.log(`  ${theme.padEnd(6)} ${level.padEnd(20)} ${value.toFixed(2)}:1`);
  }
}

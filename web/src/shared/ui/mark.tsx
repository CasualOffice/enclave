import { useT } from '../i18n/index.tsx';

/* The Enclave mark — Strata.
 *
 * An abstract E built from three policy layers, the middle one held back like a
 * redaction: the letterform of the product and the policy chain in one shape.
 *
 * **Three optical cuts, and the right one is chosen rather than scaled.** The
 * bars thicken and widen as the mark shrinks, so `logo-lg` at 16 px is thin and
 * `logo-sm` at 64 px is clumsy. `web/public/BRAND.md` sets the boundaries:
 * `lg` at 48 px and above, the base cut around 20 px, `sm` at 16 px and below.
 * They are inlined rather than fetched from `/logo.svg` so the mark cannot be
 * missing during first paint and cannot be a second request on a cold load.
 *
 * `currentColor` throughout: the mark takes whatever accent the brand sets, so
 * the customization is the mark's own rather than a variant per tenant.
 */

type Cut = 'lg' | 'md' | 'sm';

/** The three cuts, as `[x, y, width, height, radius]` per layer. */
const CUTS: Record<Cut, { inset: number; bars: readonly [number, number, number][]; r: number }> = {
  // logo-lg.svg — x 8, w 32/21, h 8.5, r 4.25
  lg: {
    inset: 8,
    bars: [
      [9, 32, 8.5],
      [19.75, 21, 8.5],
      [30.5, 32, 8.5],
    ],
    r: 4.25,
  },
  // logo.svg — x 7, w 34/22, h 9.5, r 4.75
  md: {
    inset: 7,
    bars: [
      [8, 34, 9.5],
      [19.25, 22, 9.5],
      [30.5, 34, 9.5],
    ],
    r: 4.75,
  },
  // logo-sm.svg — x 6, w 36/23, h 10, r 5
  sm: {
    inset: 6,
    bars: [
      [7, 36, 10],
      [19, 23, 10],
      [31, 36, 10],
    ],
    r: 5,
  },
};

function cutFor(size: number): Cut {
  if (size >= 48) return 'lg';
  if (size <= 16) return 'sm';
  return 'md';
}

export interface MarkProps {
  readonly size?: number;
  /**
   * `settling` plays once — a route resolving. `loading` repeats — a wait of
   * unknown length, which in this product means the policy chain deciding.
   * Never use the loop for something that finishes quickly (`logo-loader.css`).
   */
  readonly motion?: 'still' | 'settling' | 'loading';
  readonly className?: string;
}

export function Mark({ size = 20, motion = 'still', className }: MarkProps) {
  const cut = CUTS[cutFor(size)];
  const motionClass =
    motion === 'still'
      ? ''
      : motion === 'loading'
        ? 'enclave-mark--loading'
        : 'enclave-mark--settling';

  return (
    <svg
      className={`enclave-mark ${motionClass} ${className ?? ''}`.trim()}
      viewBox="0 0 48 48"
      width={size}
      height={size}
      aria-hidden="true"
      focusable="false"
      style={{ flex: 'none' }}
    >
      {cut.bars.map(([y, width, height], index) => (
        <rect
          key={y}
          x={cut.inset}
          y={y}
          width={width}
          height={height}
          rx={cut.r}
          fill="currentColor"
          // The middle layer is the redaction. Never recoloured separately.
          opacity={index === 1 ? 0.55 : 1}
        />
      ))}
    </svg>
  );
}

/**
 * The mark, explaining what the chain is doing.
 *
 * Paired with *"Checking your access…"* rather than with a generic spinner,
 * because that is what is actually happening: tenant isolation, auth,
 * conditional access, authorization, barriers, classification, DLP, retention.
 * A spinner says *wait*; this says *why*, and `docs/09 §14` prefers the second.
 */
export function AccessLoader({ size = 48 }: { size?: number }) {
  const t = useT();
  return (
    <div
      role="status"
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        gap: '14px',
        flex: 1,
        color: 'var(--accent)',
      }}
    >
      <Mark size={size} motion="loading" />
      <span style={{ color: 'var(--fg2)', fontSize: '12.5px' }}>{t('app.checkingAccess')}</span>
    </div>
  );
}

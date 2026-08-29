import { useIntl } from 'react-intl';

/* Every date, number and size in the interface goes through here.
 *
 * `docs/14 §6`: all formatting through `Intl`, nothing hand-rolled. The v2
 * design reference hand-builds both — `₹ 4.8 Cr` is manual number formatting
 * and `2 h ago` / `Yesterday` / `Fri` are hand-built relative times (D35.6).
 * Those are defects in the reference, so this module exists before the first
 * component does and the component never gets the chance to copy them.
 *
 * `Intl.NumberFormat` also gets Indian digit grouping right (`12,34,567`),
 * which is the specific thing naive formatters get wrong and the specific
 * reason `docs/14 §6` calls it out.
 */

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
const WEEK = 7 * DAY;
const MONTH = 30 * DAY;
const YEAR = 365 * DAY;

/** Byte units `Intl.NumberFormat` accepts, ascending, with the threshold each takes over at. */
const DECIMAL_UNITS = [
  { unit: 'byte', scale: 1 },
  { unit: 'kilobyte', scale: 1e3 },
  { unit: 'megabyte', scale: 1e6 },
  { unit: 'gigabyte', scale: 1e9 },
  { unit: 'terabyte', scale: 1e12 },
] as const;

export interface Formatters {
  /** An absolute date, medium form. For anything a user might quote back to support. */
  date(value: Date): string;
  /** An absolute date and time, for tooltips behind a relative time. */
  dateTime(value: Date): string;
  /**
   * "2 hours ago". Always paired with an absolute value in a `title`
   * (`docs/14 §6`) — a relative time alone is unquotable and ages badly in a
   * screenshot.
   */
  relative(value: Date, now?: Date): string;
  /** A plain count, locale-grouped. */
  count(value: number): string;
  /** A file size, locale-aware unit and all. Decimal units; binary is a tenant preference M5 does not carry yet. */
  bytes(value: number): string;
}

function pickUnit(bytes: number): { unit: (typeof DECIMAL_UNITS)[number]['unit']; scale: number } {
  let chosen: (typeof DECIMAL_UNITS)[number] = DECIMAL_UNITS[0];
  for (const candidate of DECIMAL_UNITS) {
    if (Math.abs(bytes) >= candidate.scale) chosen = candidate;
  }
  return chosen;
}

/** The relative-time unit that reads most naturally for a given distance. */
function pickRelativeUnit(deltaMs: number): { unit: Intl.RelativeTimeFormatUnit; scale: number } {
  const magnitude = Math.abs(deltaMs);
  if (magnitude < HOUR) return { unit: 'minute', scale: MINUTE };
  if (magnitude < DAY) return { unit: 'hour', scale: HOUR };
  if (magnitude < WEEK) return { unit: 'day', scale: DAY };
  if (magnitude < MONTH) return { unit: 'week', scale: WEEK };
  if (magnitude < YEAR) return { unit: 'month', scale: MONTH };
  return { unit: 'year', scale: YEAR };
}

export function useFormatters(): Formatters {
  const intl = useIntl();

  return {
    date: (value) => intl.formatDate(value, { dateStyle: 'medium' }),
    dateTime: (value) => intl.formatDate(value, { dateStyle: 'medium', timeStyle: 'short' }),
    relative: (value, now = new Date()) => {
      const delta = value.getTime() - now.getTime();
      const { unit, scale } = pickRelativeUnit(delta);
      // Round towards zero so "in 59 minutes" never reads as "in 1 hour".
      return intl.formatRelativeTime(Math.trunc(delta / scale), unit, { numeric: 'auto' });
    },
    count: (value) => intl.formatNumber(value),
    bytes: (value) => {
      const { unit, scale } = pickUnit(value);
      return intl.formatNumber(value / scale, {
        style: 'unit',
        unit,
        /* `long` for raw bytes and `short` for everything above them, which is
         * not a style choice: `short` renders the `byte` unit **unpluralised**,
         * so a 45-byte file read "45 byte" on every listing (`ENC-937`). `long`
         * gives "45 bytes" and is only ever reached below 1 kB, where the unit
         * name is short enough to spell out.
         *
         * The scaled units must stay `short` — `long` renders them
         * "1.5 kilobytes" and "4.2 megabytes", which is the opposite problem in
         * the column where almost every real file lands. */
        unitDisplay: scale === 1 ? 'long' : 'short',
        maximumFractionDigits: scale === 1 ? 0 : 1,
      });
    },
  };
}

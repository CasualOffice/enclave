import type { GroupSpec } from '../features/libraries/list/geometry.ts';
import type { FileKind, FileRow } from '../entities/file/model.ts';
import type { ClassificationLevel } from '../entities/classification/model.ts';

/* A deterministic library, for the benchmark and for the tests.
 *
 * Deterministic because a performance number measured against different data
 * each run is not a number, and because `docs/12 §6` fails a build on a 20%
 * regression — which needs the same input on both sides of the comparison.
 *
 * The shape is drawn from a contracts library rather than from `file-1.pdf`:
 * long names that actually reach the ellipsis, a classification mix weighted
 * the way a real tenant's is (most things internal, few things restricted), and
 * group sizes that vary by two orders of magnitude, because a list where every
 * group holds exactly 250 rows would hide every off-by-one this file exists to
 * expose.
 */

/** A 32-bit LCG. Small, seedable, and the sequence is stable across engines. */
function lcg(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state / 0x1_0000_0000;
  };
}

const COUNTERPARTIES = [
  'Helios Logistics',
  'Orion Analytics',
  'Brightwater Utilities',
  'Kestrel Manufacturing',
  'Nordvik Shipping',
  'Aldergrove Health',
  'Tamarind Foods',
  'Cobalt Peak Mining',
  'Saltmarsh Insurance',
  'Verrazano Capital',
  'Ironbark Timber',
  'Quiller Media',
  'Lanthorn Energy',
  'Meridian Rail',
  'Ferngate Chemicals',
  'Ostara Biotech',
] as const;

const MATTERS = [
  'Master services',
  'Statements of work',
  'Amendments',
  'Data processing',
  'Non-disclosure',
  'Renewals',
  'Pricing schedules',
  'Termination notices',
  'Templates and notes',
  'Correspondence',
] as const;

const DOCUMENTS = [
  'Vendor master agreement',
  'Statement of work',
  'Amendment',
  'Data processing addendum',
  'Mutual non-disclosure agreement',
  'Rate card',
  'Board pack',
  'Supplier code of conduct',
  'Negotiation notes',
  'Service level schedule',
  'Change request',
  'Termination notice',
  'Insurance certificate',
  'Security questionnaire response',
] as const;

const EXTENSIONS: readonly (readonly [string, FileKind])[] = [
  ['.pdf', 'pdf'],
  ['.docx', 'doc'],
  ['.xlsx', 'xls'],
  ['.pptx', 'ppt'],
  ['.md', 'other'],
];

/* Weighted towards the middle of the scale, which is where a real tenant sits.
 * A fixture that is 20% `restricted` makes the badge column look busy and hides
 * how the restrained case actually reads. */
const CLASSIFICATIONS: readonly (readonly [ClassificationLevel, number])[] = [
  ['internal', 46],
  ['confidential', 27],
  ['public', 11],
  ['highlyConfidential', 8],
  ['restricted', 5],
  ['unclassified', 3],
];

const TONES = ['a', 'b', 'c', 'd'] as const;
const INITIALS = ['PN', 'AK', 'RS', 'LB', 'MO', 'JD', 'TH', 'CV', 'EW', 'SG'] as const;

export interface Library {
  readonly groups: readonly GroupSpec[];
  readonly rows: readonly FileRow[];
}

/**
 * Build a library of approximately `targetRows` rows.
 *
 * `now` is an explicit parameter rather than `Date.now()` so a test asserting a
 * rendered relative time is not a test that fails at midnight.
 */
export function buildLibrary(targetRows: number, seed = 0x5e_ed_10_23, now = Date.UTC(2026, 7, 25)): Library {
  const random = lcg(seed);
  const groups: GroupSpec[] = [];
  const rows: FileRow[] = [];

  const classificationTotal = CLASSIFICATIONS.reduce((sum, [, weight]) => sum + weight, 0);
  const pickClassification = (): ClassificationLevel => {
    let ticket = random() * classificationTotal;
    for (const [level, weight] of CLASSIFICATIONS) {
      ticket -= weight;
      if (ticket <= 0) return level;
    }
    return 'internal';
  };

  let produced = 0;
  let groupIndex = 0;

  while (produced < targetRows) {
    const counterparty = COUNTERPARTIES[groupIndex % COUNTERPARTIES.length]!;
    const matter = MATTERS[Math.floor(groupIndex / COUNTERPARTIES.length) % MATTERS.length]!;
    const cycle = 2019 + (groupIndex % 8);

    /* Sizes spread over two orders of magnitude: a fifth of groups are tiny,
     * most are mid-sized, and one in twelve is very large. */
    const roll = random();
    const size =
      roll < 0.2
        ? 1 + Math.floor(random() * 9)
        : roll < 0.92
          ? 40 + Math.floor(random() * 420)
          : 900 + Math.floor(random() * 2600);
    const count = Math.min(size, targetRows - produced);

    groups.push({
      id: `g${groupIndex}`,
      name: `${counterparty} — ${matter} ${cycle}`,
      count,
    });

    for (let i = 0; i < count; i += 1) {
      const [extension, kind] = EXTENSIONS[Math.floor(random() * EXTENSIONS.length)]!;
      const document = DOCUMENTS[Math.floor(random() * DOCUMENTS.length)]!;
      // Ages spread from minutes to four years, so the relative-time formatter
      // is exercised across every unit it can choose.
      const ageMs = Math.floor(random() ** 3 * 4 * 365 * 24 * 60 * 60 * 1000);
      rows.push({
        id: `f${produced + i}`,
        name: `${document} ${cycle}-${String(100 + ((produced + i) % 900))} — ${counterparty}`,
        extension,
        kind,
        classification: pickClassification(),
        modifiedAt: now - ageMs,
        modifiedByInitials: INITIALS[Math.floor(random() * INITIALS.length)]!,
        modifiedByTone: TONES[Math.floor(random() * TONES.length)]!,
        // Log-uniform between about 8 KB and 40 MB. Not round numbers.
        sizeBytes: Math.round(8_000 * Math.pow(5_000, random())),
      });
    }

    produced += count;
    groupIndex += 1;
  }

  /* The design's collapsed `Archive 96`, kept as the last group so the
   * collapsed-group affordance has somewhere real to live. */
  groups.push({ id: 'archive', name: 'Archive', count: 96 });
  for (let i = 0; i < 96; i += 1) {
    rows.push({
      id: `arch${i}`,
      name: `Superseded agreement ${2011 + (i % 9)}-${String(100 + i)}`,
      extension: '.pdf',
      kind: 'pdf',
      classification: 'internal',
      modifiedAt: now - (1200 + i) * 24 * 60 * 60 * 1000,
      modifiedByInitials: INITIALS[i % INITIALS.length]!,
      modifiedByTone: TONES[i % TONES.length]!,
      sizeBytes: 240_000 + i * 3_137,
    });
  }

  return { groups, rows };
}

import type { ReactNode } from 'react';
import { useT } from '../../../shared/i18n/index.tsx';
import { useFormatters } from '../../../shared/i18n/format.ts';
import type { MessageKey } from '../../../shared/i18n/catalog.ts';
import { Eyebrow } from '../../../shared/ui/layout.tsx';
import { LaterChip, Pill } from '../../../shared/ui/primitives.tsx';
import { CLASSIFICATION_KEY } from '../../../entities/classification/model.ts';
import { useListFormat } from '../rich-text.tsx';
import {
  ACTION_KEY,
  CATEGORY_KEY,
  SCOPE_KEY,
  categoriesOf,
  classificationOf,
  type DlpRule,
} from './model.ts';

/* Diff before save (`docs/09 §21`).
 *
 * "Security-sensitive changes show a field-level diff and require confirmation."
 * Field-level is the load-bearing word: a summary that says *the policy changed*
 * is the thing administrators click past. Every field is listed, changed or not,
 * because a diff that only shows what moved gives no way to tell "priority is
 * unchanged" from "priority was not considered".
 *
 * A rule's scope, conditions, action and priority are **not editable at all** on
 * the server — `docs/05 §14.2` has no `PATCH`, and changing what a rule refuses
 * is a withdrawal plus a new rule, so the text of what was in force during any
 * period stays readable. So this diff is not a patch preview: it is *what the
 * tenant enforces before* against *what it would enforce after*, which is the
 * question an approver actually has.
 */

interface Row {
  readonly field: MessageKey;
  readonly before: ReactNode;
  readonly after: ReactNode;
  readonly changed: boolean;
}

export function PolicyDiff({
  baseline,
  draft,
  confirmed,
  onConfirm,
  readOnly,
}: {
  /** The rule in force. `undefined` when this policy has never been written. */
  baseline: DlpRule | undefined;
  draft: DlpRule;
  confirmed: boolean;
  onConfirm: (next: boolean) => void;
  readOnly: boolean;
}) {
  const t = useT();
  const format = useFormatters();
  const and = useListFormat('conjunction');

  const unset = <span className="adm-muted">{t('admin.dlp.diff.unset')}</span>;
  /* Keys rather than translated strings, so the term is a `Pill` — the shared
   * 20px sunken chip this file had written out by hand. A component that takes
   * a `MessageKey` cannot be handed a literal (`CLAUDE.md` rule 12), which is
   * the reason the mapping happens here rather than at the call sites. */
  const terms = (keys: readonly MessageKey[]) =>
    keys.length === 0
      ? unset
      : and(keys.map((key) => <Pill key={key} label={key} />));

  const scopeTerms = (rule: DlpRule) => terms(rule.scope.map((scope) => SCOPE_KEY[scope]));
  const categoryTerms = (rule: DlpRule) =>
    terms(categoriesOf(rule).map((category) => CATEGORY_KEY[category]));
  const levelTerm = (rule: DlpRule) => {
    const level = classificationOf(rule);
    /* `entities/classification`'s map, not a fifth private copy of it. It is
     * total over the six levels, so there is no "key not found" branch left. */
    return level === undefined ? unset : <Pill label={CLASSIFICATION_KEY[level]} />;
  };

  const rows: readonly Row[] = [
    {
      field: 'admin.dlp.field.name',
      before: baseline === undefined ? unset : baseline.name,
      after: draft.name,
      changed: baseline === undefined || baseline.name !== draft.name,
    },
    {
      field: 'admin.dlp.field.priority',
      before: baseline === undefined ? unset : format.count(baseline.priority),
      after: format.count(draft.priority),
      changed: baseline === undefined || baseline.priority !== draft.priority,
    },
    {
      field: 'admin.dlp.field.scope',
      before: baseline === undefined ? unset : scopeTerms(baseline),
      after: scopeTerms(draft),
      changed: baseline === undefined || baseline.scope.join() !== draft.scope.join(),
    },
    {
      field: 'admin.dlp.field.classification',
      before: baseline === undefined ? unset : levelTerm(baseline),
      after: levelTerm(draft),
      changed: baseline === undefined || classificationOf(baseline) !== classificationOf(draft),
    },
    {
      field: 'admin.dlp.field.categories',
      before: baseline === undefined ? unset : categoryTerms(baseline),
      after: categoryTerms(draft),
      changed:
        baseline === undefined ||
        categoriesOf(baseline).join() !== categoriesOf(draft).join(),
    },
    {
      field: 'admin.dlp.field.action',
      before: baseline === undefined ? unset : t(ACTION_KEY[baseline.action]),
      after: t(ACTION_KEY[draft.action]),
      changed: baseline === undefined || baseline.action !== draft.action,
    },
  ];

  const changedCount = rows.filter((row) => row.changed).length;

  return (
    <section className="ui-card adm-panel" data-padded="" aria-label={t('admin.dlp.diff.title')}>
      <Eyebrow label="admin.dlp.diff.title" />
      <p className="adm-muted">
        {baseline === undefined
          ? t('admin.dlp.diff.newPolicy')
          : t('admin.dlp.diff.changedCount', { count: changedCount })}
      </p>

      <table className="adm-diff">
        <thead>
          {/* The uppercase is `.ui-eyebrow-text`'s, behind its `:lang()`
            * allowlist — a `<th>` cannot hold the `Eyebrow` heading, but it can
            * hold the span that carries the transform, and the catalog stays
            * sentence case either way (`docs/14`). */}
          <tr>
            <th scope="col">
              <span className="ui-eyebrow-text">{t('admin.dlp.diff.field')}</span>
            </th>
            <th scope="col">
              <span className="ui-eyebrow-text">{t('admin.dlp.diff.before')}</span>
            </th>
            <th scope="col">
              <span className="ui-eyebrow-text">{t('admin.dlp.diff.after')}</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.field} data-changed={row.changed ? 'true' : undefined}>
              <th scope="row">{t(row.field)}</th>
              <td>{row.before}</td>
              <td>{row.after}</td>
            </tr>
          ))}
        </tbody>
      </table>

      {/* `docs/06 §22`: maker/checker is optional for critical configuration and
       * needs a pending `config_version` plus a second administrator. Neither
       * exists yet, so the line says so in the neutral treatment — future tense,
       * about the product, no remedy — rather than being left off the screen. */}
      <p className="adm-clause" data-unbuilt="true">
        <span aria-disabled="true" className="adm-clause-unbuilt">
          {t('admin.dlp.diff.makerCheckerUnbuilt')}
        </span>
        <LaterChip note="later.chip" />
      </p>

      {!readOnly && (
        <label className="adm-confirm">
          <input
            type="checkbox"
            checked={confirmed}
            onChange={(event) => onConfirm(event.target.checked)}
          />
          {t('admin.dlp.diff.confirm')}
        </label>
      )}
    </section>
  );
}

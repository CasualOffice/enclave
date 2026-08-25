import type { ReactNode } from 'react';
import { useT } from '../../../shared/i18n/index.tsx';
import { useFormatters } from '../../../shared/i18n/format.ts';
import type { MessageKey } from '../../../shared/i18n/catalog.ts';
import { LaterChip } from '../../../shared/ui/primitives.tsx';
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

const CLASSIFICATION_KEY_RANKED: Record<string, MessageKey> = {
  public: 'classification.public',
  internal: 'classification.internal',
  confidential: 'classification.confidential',
  highlyConfidential: 'classification.highlyConfidential',
  restricted: 'classification.restricted',
};

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
  const terms = (items: readonly string[]) =>
    items.length === 0
      ? unset
      : and(
          items.map((item) => (
            <span className="adm-chip adm-chip-sm" key={item}>
              {item}
            </span>
          )),
        );

  const scopeTerms = (rule: DlpRule) => terms(rule.scope.map((scope) => t(SCOPE_KEY[scope])));
  const categoryTerms = (rule: DlpRule) =>
    terms(categoriesOf(rule).map((category) => t(CATEGORY_KEY[category])));
  const levelTerm = (rule: DlpRule) => {
    const level = classificationOf(rule);
    if (level === undefined) return unset;
    const key = CLASSIFICATION_KEY_RANKED[level];
    return key === undefined ? unset : <span className="adm-chip adm-chip-sm">{t(key)}</span>;
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
    <section className="adm-panel" aria-labelledby="adm-diff-title">
      <h3 className="adm-panel-title" id="adm-diff-title">
        {t('admin.dlp.diff.title')}
      </h3>
      <p className="adm-muted">
        {baseline === undefined
          ? t('admin.dlp.diff.newPolicy')
          : t('admin.dlp.diff.changedCount', { count: changedCount })}
      </p>

      <table className="adm-diff">
        <thead>
          <tr>
            <th scope="col">{t('admin.dlp.diff.field')}</th>
            <th scope="col">{t('admin.dlp.diff.before')}</th>
            <th scope="col">{t('admin.dlp.diff.after')}</th>
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

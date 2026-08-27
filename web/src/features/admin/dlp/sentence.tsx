import type { ReactNode } from 'react';
import { useT } from '../../../shared/i18n/index.tsx';
import type { MessageKey } from '../../../shared/i18n/catalog.ts';
import { Icon } from '../../../shared/ui/icon-sprite.tsx';
import { Card, Eyebrow, Field } from '../../../shared/ui/layout.tsx';
import { LaterChip } from '../../../shared/ui/primitives.tsx';
import { ClassificationChip } from '../../../entities/classification/chip.tsx';
import { CLASSIFICATION_KEY } from '../../../entities/classification/model.ts';
import { useListFormat, useRichT } from '../rich-text.tsx';
import {
  ACTION_KEY,
  CATEGORY_KEY,
  SCOPE_KEY,
  DlpAction,
  DlpCategory,
  DlpClassification,
  DlpScope,
  categoriesOf,
  classificationOf,
  denialFor,
  type DlpRule,
} from './model.ts';

/* The policy, as a sentence.
 *
 * `docs/09 §21`: **rule builders, not JSON.** Normal policy creation is a
 * form-based condition/effect builder, and a JSON view exists beside it for
 * power users and for copying between tenants. Both render from the same `rule`
 * object, so "the two stay in sync" is a property of the data flow rather than a
 * thing to remember.
 *
 * The i18n shape is the interesting part, and `rich-text.tsx` explains it: every
 * clause is **one** ICU message with the controls as placeholders, never a
 * sequence of fragments glued around them. Clauses are list items under a band
 * header that already says "all of these are true", so there is no conjunction
 * to invent between them either.
 *
 * Three of the prototype's chips are drawn as `unbuilt` instead of as controls,
 * because `docs/05 §14.2` has no field for what they would edit. See the header
 * of `model.ts`. Drawing them as working controls would be the "screen is a
 * promise" failure this milestone is built around; drawing them with the denial
 * treatment would be worse, because it would teach an administrator that dimmed
 * means refused when here it means unwritten (`docs/17 §6`).
 */

function Chevron() {
  return <Icon name="chev" size={12} className="adm-chip-chev" />;
}

function SelectChip<T extends string>({
  label,
  value,
  options,
  optionKey,
  onChange,
  readOnly,
  className,
}: {
  label: MessageKey;
  value: T;
  options: readonly T[];
  optionKey: Record<T, MessageKey>;
  onChange: (next: T) => void;
  readOnly: boolean;
  className?: string | undefined;
}) {
  const t = useT();
  if (readOnly) {
    return <span className={className ?? 'adm-chip'}>{t(optionKey[value])}</span>;
  }
  return (
    <span className={`${className ?? 'adm-chip'} adm-chip-control`}>
      <select
        className="adm-select"
        aria-label={t(label)}
        value={value}
        onChange={(event) => onChange(event.target.value as T)}
      >
        {options.map((option) => (
          <option key={option} value={option}>
            {t(optionKey[option])}
          </option>
        ))}
      </select>
      <Chevron />
    </span>
  );
}

function AddChip<T extends string>({
  label,
  options,
  optionKey,
  onAdd,
}: {
  label: MessageKey;
  options: readonly T[];
  optionKey: Record<T, MessageKey>;
  onAdd: (next: T) => void;
}) {
  const t = useT();
  if (options.length === 0) return null;
  return (
    <span className="adm-chip adm-chip-add">
      <Icon name="plus" size={12} />
      <select
        className="adm-select"
        aria-label={t(label)}
        value=""
        onChange={(event) => {
          if (event.target.value !== '') onAdd(event.target.value as T);
        }}
      >
        <option value="">{t(label)}</option>
        {options.map((option) => (
          <option key={option} value={option}>
            {t(optionKey[option])}
          </option>
        ))}
      </select>
    </span>
  );
}

function TermChip({
  term,
  removeLabel,
  onRemove,
}: {
  term: string;
  removeLabel: string | undefined;
  onRemove: (() => void) | undefined;
}) {
  return (
    <span className="adm-chip">
      {term}
      {onRemove !== undefined && removeLabel !== undefined && (
        <button type="button" className="adm-chip-x" aria-label={removeLabel} onClick={onRemove}>
          <Icon name="x" size={11} />
        </button>
      )}
    </span>
  );
}

/**
 * The classification threshold, wearing the locked palette.
 *
 * **One badge, and this is not a second one.** `entities/classification/chip`
 * is the only implementation (`docs/09 §16a` locks the palette; four
 * hand-maintained copies lock nothing, and they had already drifted to four
 * heights, four dot sizes and three type sizes). Admin's copy was one of the
 * four: 22px, no `unclassified` branch, and its own five `--c-*` bindings.
 *
 * Read-only is the chip itself. Editable reuses the chip's *class*, because the
 * shared component takes no children and a threshold is a badge with a `select`
 * in it — the alternative is a second set of `--c-*` bindings, which is the
 * thing being deleted. `size="md"` is the 22px form admin already used.
 *
 * The option labels come from `CLASSIFICATION_KEY`. The list of options does
 * not: `DlpClassification.options` is the five ranked levels, and
 * `unclassified` is an absence rather than a sixth level, so it can never be a
 * threshold.
 */
function ClassificationThreshold({
  value,
  onChange,
  readOnly,
}: {
  value: DlpClassification;
  onChange: (next: DlpClassification) => void;
  readOnly: boolean;
}) {
  const t = useT();
  if (readOnly) return <ClassificationChip level={value} size="md" />;

  return (
    <span className="ui-classification" data-level={value} data-size="md">
      <select
        className="adm-select"
        aria-label={t('admin.dlp.chip.classificationLabel')}
        value={value}
        onChange={(event) => onChange(event.target.value as DlpClassification)}
      >
        {DlpClassification.options.map((option) => (
          <option key={option} value={option}>
            {t(CLASSIFICATION_KEY[option])}
          </option>
        ))}
      </select>
      <Chevron />
    </span>
  );
}

function Band({
  heading,
  hint,
  children,
}: {
  /* Named `heading` rather than `title`: `title=` is a user-facing attribute to
   * the i18n gate, and a prop that trips a rule is a prop somebody silences it for. */
  heading: MessageKey;
  hint?: MessageKey;
  children: ReactNode;
}) {
  const t = useT();
  return (
    <>
      {/* `Eyebrow` owns the uppercase, behind a `:lang()` allowlist — it is
        * wrong in Turkish, strips accents in Greek and means nothing in a
        * caseless script (`docs/14`), and a catalog holding "WHEN" in capitals
        * would be untranslatable. The band was one of three places in this file
        * that wrote `text-transform: uppercase` out by hand. */}
      <div className="adm-band">
        <Eyebrow label={heading}>
          {hint !== undefined && <span className="adm-band-hint">{t(hint)}</span>}
        </Eyebrow>
      </div>
      <ul className="adm-clauses">{children}</ul>
    </>
  );
}

/** A clause the contract cannot express. Neutral, not focusable, no remedy. */
function UnbuiltClause({ note }: { note: MessageKey }) {
  const t = useT();
  return (
    <li className="adm-clause" data-unbuilt="true">
      {/* `aria-disabled` with a description, and nothing focusable inside: there
       * is nothing to find out and nothing to do (`docs/17 §6`). Future tense,
       * about the product, and never the denial colour. */}
      <span aria-disabled="true" className="adm-clause-unbuilt">
        {t(note)}
      </span>
      <LaterChip note="later.chip" />
    </li>
  );
}

export interface SentenceProps {
  readonly rule: DlpRule;
  readonly onChange: (next: DlpRule) => void;
  /** Auditor mode renders the same sentence with no control in it (`docs/09 §21`). */
  readonly readOnly: boolean;
}

export function PolicySentence({ rule, onChange, readOnly }: SentenceProps) {
  const t = useT();
  const rich = useRichT();
  const anyOf = useListFormat('disjunction');

  const level = classificationOf(rule);
  const categories = categoriesOf(rule);
  const unusedCategories = DlpCategory.options.filter((option) => !categories.includes(option));
  const unusedScopes = DlpScope.options.filter((option) => !rule.scope.includes(option));
  const denial = denialFor(rule.action);

  const setClassification = (next: DlpClassification) => {
    onChange({
      ...rule,
      conditions: rule.conditions.map((condition) =>
        'classification_at_least' in condition
          ? { classification_at_least: { classification: next } }
          : condition,
      ),
    });
  };

  const addCategory = (next: DlpCategory) => {
    onChange({
      ...rule,
      conditions: [...rule.conditions, { category_at_least: { category: next, count: 1 } }],
    });
  };

  const removeCategory = (target: DlpCategory) => {
    onChange({
      ...rule,
      conditions: rule.conditions.filter(
        (condition) =>
          !('category_at_least' in condition) || condition.category_at_least.category !== target,
      ),
    });
  };

  return (
    /* `.adm-builder` is kept as the class name because the accessibility and
     * screenshot runs wait on it; the raised surface under it is `Card`'s. */
    <Card className="adm-builder" padded={false}>
      <Band heading="admin.dlp.band.identity">
        <li className="adm-clause">
          {rich('admin.dlp.clause.name', {
            name: readOnly ? (
              <span className="adm-chip">{rule.name}</span>
            ) : (
              /* The width is the content's, in `ch`, so the field reads as a
               * word in the sentence rather than as a form control that
               * happens to sit in one. `size=` cannot do it here: `Field` owns
               * that prop for its own three heights. */
              <Field
                label="admin.dlp.chip.nameLabel"
                value={rule.name}
                style={{ inlineSize: `${Math.max(rule.name.length, 12)}ch` }}
                onChange={(event) => onChange({ ...rule, name: event.target.value })}
              />
            ),
          })}
        </li>
        <li className="adm-clause">
          {rich('admin.dlp.clause.priority', {
            priority: readOnly ? (
              <span className="adm-chip">{rule.priority}</span>
            ) : (
              <Field
                label="admin.dlp.chip.priorityLabel"
                type="number"
                min={0}
                value={rule.priority}
                style={{ inlineSize: '9ch' }}
                onChange={(event) =>
                  onChange({ ...rule, priority: Math.max(0, event.target.valueAsNumber || 0) })
                }
              />
            ),
          })}
        </li>
      </Band>

      <Band heading="admin.dlp.band.when" hint="admin.dlp.band.whenHint">
        {level !== undefined && (
          <li className="adm-clause">
            {rich('admin.dlp.clause.classification', {
              level: (
                <ClassificationThreshold
                  value={level}
                  onChange={setClassification}
                  readOnly={readOnly}
                />
              ),
            })}
          </li>
        )}
        <li className="adm-clause">
          {rich('admin.dlp.clause.categories', {
            categories: anyOf(
              categories.map((category) => (
                <TermChip
                  key={category}
                  term={t(CATEGORY_KEY[category])}
                  removeLabel={
                    readOnly || categories.length < 2
                      ? undefined
                      : t('admin.dlp.chip.removeCategory', { category: t(CATEGORY_KEY[category]) })
                  }
                  onRemove={
                    readOnly || categories.length < 2
                      ? undefined
                      : () => removeCategory(category)
                  }
                />
              )),
            ),
          })}
          {!readOnly && (
            <AddChip
              label="admin.dlp.chip.addCategory"
              options={unusedCategories}
              optionKey={CATEGORY_KEY}
              onAdd={addCategory}
            />
          )}
        </li>
        <li className="adm-clause">
          {rich('admin.dlp.clause.scope', {
            actions: anyOf(
              rule.scope.map((scope) => (
                <TermChip
                  key={scope}
                  term={t(SCOPE_KEY[scope])}
                  /* `docs/05 §14.2`: **`scope` may not be empty.** An empty scope
                   * governs nothing, which is the permissive reading that turns a
                   * mis-migrated row into a tenant-wide surprise — so the last one
                   * has no remove control at all rather than a control that errors. */
                  removeLabel={
                    readOnly || rule.scope.length < 2
                      ? undefined
                      : t('admin.dlp.chip.removeScope', { action: t(SCOPE_KEY[scope]) })
                  }
                  onRemove={
                    readOnly || rule.scope.length < 2
                      ? undefined
                      : () =>
                          onChange({
                            ...rule,
                            scope: rule.scope.filter((entry) => entry !== scope),
                          })
                  }
                />
              )),
            ),
          })}
          {!readOnly && (
            <AddChip
              label="admin.dlp.chip.addScope"
              options={unusedScopes}
              optionKey={SCOPE_KEY}
              onAdd={(next) => onChange({ ...rule, scope: [...rule.scope, next] })}
            />
          )}
        </li>
      </Band>

      <Band heading="admin.dlp.band.then">
        <li className="adm-clause">
          {rich('admin.dlp.clause.effect', {
            effect: (
              <SelectChip
                label="admin.dlp.chip.effectLabel"
                value={rule.action}
                options={DlpAction.options}
                optionKey={ACTION_KEY}
                onChange={(next) => onChange({ ...rule, action: next })}
                readOnly={readOnly}
                className="adm-chip adm-chip-effect"
              />
            ),
          })}
        </li>
        <li className="adm-clause">
          {denial === undefined
            ? t('admin.dlp.clause.noRefusal')
            : rich('admin.dlp.clause.reason', {
                code: <code className="adm-code">{denial.code}</code>,
              })}
        </li>
        <UnbuiltClause note="admin.dlp.clause.messageUnbuilt" />
        <UnbuiltClause note="admin.dlp.clause.obligationsUnbuilt" />
      </Band>

      <Band heading="admin.dlp.band.where">
        <UnbuiltClause note="admin.dlp.clause.whereUnbuilt" />
      </Band>
    </Card>
  );
}

/**
 * What a refused person is shown — and, just as load-bearing, what they are not.
 *
 * `docs/06 §24` and `CLAUDE.md` rule 10: a stable reason code, a user-safe
 * sentence, a remediation, and **never** which policy matched, its conditions or
 * its thresholds. That is a rule about what this screen *renders*, not only
 * about what the server logs, so the preview is built from `denialFor(action)`
 * alone — it is given the effect and nothing else, and cannot name the rule even
 * by accident.
 */
export function DenialPreview({ rule }: { rule: DlpRule }) {
  const t = useT();
  const denial = denialFor(rule.action);

  return (
    /* Still a `<section>` with an accessible name, so it stays a landmark; the
     * raised surface is `.ui-card`'s, which `Card` also renders — the component
     * would have made it a `<div>`. */
    <section className="ui-card adm-panel" data-padded="" aria-label={t('admin.dlp.preview.title')}>
      <Eyebrow label="admin.dlp.preview.title" />
      {denial === undefined ? (
        <p className="adm-muted">{t('admin.dlp.preview.none')}</p>
      ) : (
        <div className="adm-denial">
          <p className="adm-denial-message">{t(denial.message)}</p>
          <p className="adm-denial-remedy">{t(denial.remediation)}</p>
          <p className="adm-denial-code">
            <span>{t('admin.dlp.preview.codeLabel')}</span>
            <code className="adm-code">{denial.code}</code>
          </p>
        </div>
      )}
      <p className="adm-muted">{t('admin.dlp.preview.note')}</p>
    </section>
  );
}

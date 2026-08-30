import { useT } from '../../shared/i18n/index.tsx';
import type { MessageKey } from '../../shared/i18n/catalog.ts';
import { Field, Push, Row, Truncate } from '../../shared/ui/layout.tsx';
import { IconButton, LaterChip } from '../../shared/ui/primitives.tsx';
import type { DlpRule } from './dlp/model.ts';

/* The admin section rail, and the list of policies inside it.
 *
 * `docs/09 §21`: **everything is searchable and linkable — every admin object
 * has a stable URL.** So each policy is a real `<a href>` carrying its id, not a
 * click handler on a `<div>`: a link can be copied into a ticket, opened in a
 * new tab, and found by the browser's own history. The search box narrows the
 * list and lives in the URL beside the selection, so a filtered rail is
 * shareable too (`docs/17 §4`).
 *
 * `docs/09 §21`'s navigation list is much longer than this. The sections that
 * exist as screens are links; the rest carry the neutral `Later` chip and sit
 * outside the tab order — future tense, about the product, never the denial
 * treatment (`docs/17 §6`). Half the rail meaning "not written yet" is exactly
 * how a user learns to stop reading dimmed, so it must not look refused.
 *
 * ## Why two of these three rows are `.ui-row` and one is `<Row>`
 *
 * `Row` renders a `<button>`, and a policy must be an `<a href>`: `docs/09 §21`
 * requires a stable URL per admin object, and a button cannot be copied into a
 * ticket, opened in a new tab or found in browser history. So the anchor wears
 * the shared class while the unbuilt sections use the component — which is the
 * half that matters, because the component is what renders unbuilt as a
 * non-focusable `<span>` with no opacity change and no danger tint. This rail's
 * own copy had drifted an `opacity: .5` onto that variant while the two others
 * deliberately had none; `docs/17 §6` forbids exactly that, and one
 * implementation is the only way it stays forbidden.
 */

interface Section {
  readonly label: MessageKey;
  readonly items: readonly {
    readonly label: MessageKey;
    /** The `?section=` value, for entries that lead somewhere. */
    readonly section?: string;
  }[];
}

/* An entry with a `section` is built and navigates; one without is `unbuilt`
 * and is not focusable, because there is nowhere to go (`docs/17 §6`).
 *
 * Until `ENC-945` every entry but DLP was in the second class and the rail had
 * no notion of navigation at all — `current: true` was a literal on one row.
 * Retention is the second built surface, so the distinction has to be a
 * property rather than a hard-coded row. */
const SECTIONS: readonly Section[] = [
  {
    label: 'admin.nav.security',
    items: [
      { label: 'admin.nav.dlp', section: 'dlp' },
      { label: 'admin.nav.retention', section: 'retention' },
      { label: 'admin.nav.conditionalAccess' },
      { label: 'admin.nav.classification' },
      { label: 'admin.nav.barriers' },
      { label: 'admin.nav.incidents' },
    ],
  },
  {
    label: 'admin.nav.detectors',
    items: [{ label: 'admin.nav.detectorsBuiltIn' }, { label: 'admin.nav.detectorsCustom' }],
  },
];

export function AdminNav({
  section,
  onSection,
  rules,
  selectedId,
  query,
  onQuery,
  hrefFor,
  onSelect,
  onCreate,
  readOnly,
}: {
  section: string;
  onSection: (next: string) => void;
  rules: readonly DlpRule[];
  selectedId: string | undefined;
  query: string;
  onQuery: (next: string) => void;
  hrefFor: (ruleId: string) => string;
  onSelect: (ruleId: string) => void;
  onCreate: () => void;
  readOnly: boolean;
}) {
  const t = useT();

  return (
    <nav className="adm-nav" aria-label={t('admin.nav.label')}>
      {SECTIONS.map((group) => (
        <div key={group.label}>
          <div className="adm-nav-group">{t(group.label)}</div>
          {group.items.map((item) =>
            item.section !== undefined ? (
              /* A real control: the built surfaces are reachable from each
               * other, which is what makes the rail a rail rather than a
               * heading with one live row. */
              <button
                type="button"
                className="ui-row adm-nav-link"
                key={item.label}
                aria-current={item.section === section ? 'page' : undefined}
                onClick={() => onSection(item.section as string)}
              >
                {t(item.label)}
              </button>
            ) : (
              /* Not an anchor and not focusable: there is nowhere to go and
               * nothing to find out (`docs/17 §6`). */
              <Row key={item.label} unbuilt>
                {t(item.label)}
                <Push />
                <LaterChip note="later.chip" />
              </Row>
            ),
          )}
        </div>
      ))}

      {/* Everything below is the DLP surface's own index — its rule search and
        * rule list — and belongs to that section rather than to the rail. Left
        * visible on the retention section it would offer a search over rules
        * the pane beside it is not showing (`ENC-945`). */}
      {section === 'dlp' && (
        <>
      <div className="adm-nav-group">
        {t('admin.dlp.rules.title')}
        {!readOnly && (
          <IconButton name="plus" label="admin.state.empty.action" onClick={onCreate} />
        )}
      </div>

      {/* One field, one focus ring. The rail's own recipe was an `outline` at
        * +2px offset, one of three in the tree for five inputs (`docs/09 §15`
        * wants one visible indicator, not one per screen). */}
      <Field
        label="admin.dlp.rules.searchLabel"
        icon="s"
        type="search"
        value={query}
        placeholder={t('admin.dlp.rules.searchLabel')}
        onChange={(event) => onQuery(event.target.value)}
      />

      <ul className="adm-nav-rules">
        {rules.map((rule) => (
          <li key={rule.id}>
            <a
              className="ui-row"
              href={hrefFor(rule.id)}
              aria-current={rule.id === selectedId ? 'page' : undefined}
              onClick={(event) => {
                event.preventDefault();
                onSelect(rule.id);
              }}
            >
              <Truncate>{rule.name}</Truncate>
              {/* `docs/05 §14.2`: a stored rule that no longer decodes fails
               * every request in the tenant, and this list is where an
               * administrator would find out which one to withdraw. */}
              {!rule.decodes && (
                <>
                  <Push />
                  <span className="adm-nav-broken">{t('admin.dlp.rules.decodeError')}</span>
                </>
              )}
            </a>
          </li>
        ))}
      </ul>
        </>
      )}
    </nav>
  );
}

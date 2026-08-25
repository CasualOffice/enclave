import { useT } from '../../shared/i18n/index.tsx';
import type { MessageKey } from '../../shared/i18n/catalog.ts';
import { Icon } from '../../shared/ui/icon-sprite.tsx';
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
 */

interface Section {
  readonly label: MessageKey;
  readonly items: readonly { readonly label: MessageKey; readonly current?: boolean }[];
}

const SECTIONS: readonly Section[] = [
  {
    label: 'admin.nav.security',
    items: [
      { label: 'admin.nav.dlp', current: true },
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
  rules,
  selectedId,
  query,
  onQuery,
  hrefFor,
  onSelect,
  onCreate,
  readOnly,
}: {
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
      {SECTIONS.map((section) => (
        <div key={section.label}>
          <div className="adm-nav-group">{t(section.label)}</div>
          {section.items.map((item) =>
            item.current === true ? (
              <span className="adm-nav-link" key={item.label} aria-current="page">
                {t(item.label)}
              </span>
            ) : (
              /* Not an anchor and not focusable: there is nowhere to go and
               * nothing to find out (`docs/17 §6`). */
              <span className="adm-nav-link" key={item.label} data-unbuilt="true" aria-disabled="true">
                {t(item.label)}
                <LaterChip note="later.chip" />
              </span>
            ),
          )}
        </div>
      ))}

      <div className="adm-nav-group">
        {t('admin.dlp.rules.title')}
        {!readOnly && (
          <IconButton name="plus" label="admin.state.empty.action" onClick={onCreate} />
        )}
      </div>

      <div className="adm-nav-search">
        <Icon name="s" size={12} />
        <input
          type="search"
          value={query}
          aria-label={t('admin.dlp.rules.searchLabel')}
          placeholder={t('admin.dlp.rules.searchLabel')}
          onChange={(event) => onQuery(event.target.value)}
        />
      </div>

      <ul className="adm-nav-rules">
        {rules.map((rule) => (
          <li key={rule.id}>
            <a
              className="adm-nav-link"
              href={hrefFor(rule.id)}
              aria-current={rule.id === selectedId ? 'page' : undefined}
              onClick={(event) => {
                event.preventDefault();
                onSelect(rule.id);
              }}
            >
              {rule.name}
              {/* `docs/05 §14.2`: a stored rule that no longer decodes fails
               * every request in the tenant, and this list is where an
               * administrator would find out which one to withdraw. */}
              {!rule.decodes && <span className="adm-nav-broken">{t('admin.dlp.rules.decodeError')}</span>}
            </a>
          </li>
        ))}
      </ul>
    </nav>
  );
}

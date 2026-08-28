import { useEffect, useRef, useState } from 'react';
import { useT } from '../../shared/i18n/index.tsx';
import { Icon } from '../../shared/ui/icon-sprite.tsx';
import { Popover, Row } from '../../shared/ui/layout.tsx';
import type { MessageKey } from '../../shared/i18n/catalog.ts';
import { ANY, type FilterDef, type FilterId, type FilterOption, type FilterState } from './filters.ts';

/* Filter chips.
 *
 * `docs/09 §10`: *"Filters are chips that compose and are individually
 * removable; the active filter set is reflected in the URL so a search is
 * shareable and restorable."* Three requirements, and each has a visible
 * consequence here:
 *
 * - **Compose.** Every chip is always present, at its default or not. A chip
 *   that appears only once chosen hides the axes a user could narrow along, and
 *   the prototype's row — Type / Classification / Modified, each reading `Any` —
 *   already makes that call. It is right and it is kept.
 * - **Individually removable.** An active chip grows a second control with its
 *   own accessible name ("Remove the Classification filter"), rather than
 *   overloading the chip itself: a single control that opens a menu on click and
 *   clears on some other gesture is not reachable from a keyboard.
 * - **Reflected in the URL.** Every change goes out through the screen's
 *   `onChange`, which writes the *whole* parameter set via `replaceParams`. The
 *   chip never touches the URL itself — one writer, so a cleared chip cannot
 *   drop the others.
 *
 * The value half of a chip is either a catalog key or server-owned data (a
 * workspace name), which is why `FilterOption` has two shapes. Data is rendered
 * with `dir="auto"` inside `<bdi>` and never translated (`docs/14 §6`).
 */

/** A chip's value half: a catalog key when the product owns the word, data when the server does. */
function optionText(option: FilterOption, t: (key: MessageKey) => string): string {
  return 'label' in option ? t(option.label) : option.text;
}

function FilterChip({
  def,
  value,
  onChange,
}: {
  def: FilterDef;
  value: string;
  onChange: (id: FilterId, value: string) => void;
}) {
  const t = useT();
  const [open, setOpen] = useState(false);
  const chipRef = useRef<HTMLDivElement | null>(null);
  const triggerRef = useRef<HTMLButtonElement | null>(null);

  const active = value !== ANY;
  const selected = def.options.find((option) => option.value === value) ?? def.options[0]!;
  const keyText = t(def.label);
  const valueText = optionText(selected, t);

  /* Escape closes and returns focus to the trigger; a pointer outside closes
   * without moving focus. `docs/09 §6`: "focus returns to the triggering element
   * when a dialog closes", and a menu is the same promise at a smaller scale. */
  useEffect(() => {
    if (!open) return undefined;

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;
      event.stopPropagation();
      setOpen(false);
      triggerRef.current?.focus();
    };
    const onPointerDown = (event: PointerEvent) => {
      const node = chipRef.current;
      if (node !== null && event.target instanceof Node && !node.contains(event.target)) {
        setOpen(false);
      }
    };

    document.addEventListener('keydown', onKeyDown, true);
    document.addEventListener('pointerdown', onPointerDown, true);
    return () => {
      document.removeEventListener('keydown', onKeyDown, true);
      document.removeEventListener('pointerdown', onPointerDown, true);
    };
  }, [open]);

  return (
    <div className="esr-chip-holder" ref={chipRef}>
      <span className="esr-chip" data-active={active || undefined}>
        <button
          type="button"
          ref={triggerRef}
          className="esr-chip-open"
          aria-haspopup="menu"
          aria-expanded={open}
          aria-label={t('search.filter.change', { filter: keyText, value: valueText })}
          onClick={() => setOpen((current) => !current)}
        >
          <span className="esr-chip-key">{keyText}</span>
          <bdi className="esr-chip-value" dir="auto">
            {valueText}
          </bdi>
        </button>
        {active && (
          <button
            type="button"
            className="esr-chip-clear"
            aria-label={t('search.filter.remove', { filter: keyText })}
            onClick={() => onChange(def.id, ANY)}
          >
            <Icon name="x" size={10} />
          </button>
        )}
      </span>

      {/* `Popover` owns the elevation, the radius, the padding, the entrance and
        * the layer — `--z-popover`, from the ladder in `styles/scale.css`. This
        * menu and the upload tray had independently arrived at `z-index: 20`
        * because the ladder was prose in a comment neither author could read.
        * Only the anchoring is `.esr-chip-menu`'s, because a popover's anchor is
        * the caller's business. `Row` is the item, for the same reason: four
        * implementations agreed on eleven declarations and differed on the
        * twelfth. */}
      {open && (
        <Popover label={def.label} role="menu" className="esr-chip-menu">
          {def.options.map((option) => (
            <Row
              key={option.value}
              role="menuitemradio"
              aria-checked={option.value === value}
              onClick={() => {
                onChange(def.id, option.value);
                setOpen(false);
                triggerRef.current?.focus();
              }}
            >
              <span className="esr-chip-tick">
                {option.value === value && <Icon name="check" size={10} />}
              </span>
              <bdi dir="auto">{optionText(option, t)}</bdi>
            </Row>
          ))}
        </Popover>
      )}
    </div>
  );
}

export function FilterChips({
  defs,
  filters,
  onChange,
}: {
  defs: readonly FilterDef[];
  filters: FilterState;
  onChange: (id: FilterId, value: string) => void;
}) {
  return (
    <>
      {defs.map((def) => (
        <FilterChip key={def.id} def={def} value={filters[def.id]} onChange={onChange} />
      ))}
    </>
  );
}

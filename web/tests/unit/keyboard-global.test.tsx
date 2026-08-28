import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { I18nProvider } from '../../src/shared/i18n/index.tsx';
import { BINDINGS, BUILT } from '../../src/shared/keyboard/bindings.ts';
import { matchesSpec, useKeyBindings } from '../../src/shared/keyboard/use-key-bindings.ts';
import { isTypingTarget } from '../../src/shared/keyboard/keys.ts';
import {
  onFocusRequest,
  requestFocus,
  resetFocusBus,
} from '../../src/shared/keyboard/focus-bus.ts';
import { ShortcutSheet } from '../../src/shared/keyboard/shortcut-sheet.tsx';
import { CommandPalette, type Command } from '../../src/shared/keyboard/command-palette.tsx';

afterEach(cleanup);
beforeEach(resetFocusBus);

/* The global half of `docs/09 §6`.
 *
 * The one rule these mostly exist for is the typing guard. Every single-letter
 * binding in §6 is a character somebody types into the search field within a
 * minute of the product loading, and a handler without the guard makes those
 * characters untypeable — a defect that is trivially reachable and completely
 * invisible in any test that only presses keys at the document body.
 */

describe('matching a key spec', () => {
  /* The modifier flags default to `false` because a real `KeyboardEvent` always
   * carries them. Leaving them `undefined` is not a smaller fixture, it is a
   * different type — and it is how the first draft of this suite reported that
   * `i` did not match `I`. */
  const event = (init: Partial<KeyboardEvent>): KeyboardEvent =>
    ({ metaKey: false, ctrlKey: false, altKey: false, shiftKey: false, ...init }) as KeyboardEvent;

  it('requires the modifier when the spec asks for one, and refuses it when it does not', () => {
    expect(matchesSpec('mod+k', event({ key: 'k', metaKey: true }))).toBe(true);
    expect(matchesSpec('mod+k', event({ key: 'k', ctrlKey: true }))).toBe(true);
    /* Both, rather than sniffing the platform: `docs/09 §5` writes the binding
     * as "⌘K / Ctrl+K", and a `navigator.platform` test gets a Mac with a PC
     * keyboard wrong. */
    expect(matchesSpec('mod+k', event({ key: 'k' }))).toBe(false);
    expect(matchesSpec('/', event({ key: '/', metaKey: true }))).toBe(false);
  });

  it('compares letters case-insensitively and punctuation exactly', () => {
    /* Caps lock reports the upper-case character, and a user with caps lock on
     * has not asked for a different command. `?` and `/` are different
     * bindings on the same physical key, so those compare exactly. */
    expect(matchesSpec('i', event({ key: 'I' }))).toBe(true);
    expect(matchesSpec('?', event({ key: '/' }))).toBe(false);
    expect(matchesSpec('/', event({ key: '?' }))).toBe(false);
  });

  it('never fires with Alt held', () => {
    expect(matchesSpec('mod+k', event({ key: 'k', metaKey: true, altKey: true }))).toBe(false);
  });
});

describe('the typing guard', () => {
  it('recognises every field a user composes in', () => {
    /* The hosts are removed at the end. A stray `<select>` left in the document
     * has the role `combobox`, which made four command-palette tests four
     * describes later fail with "found multiple elements" — a test polluting a
     * global document is a test that breaks other tests. */
    const hosts: HTMLElement[] = [];
    const make = (html: string) => {
      const host = document.createElement('div');
      host.innerHTML = html;
      document.body.append(host);
      hosts.push(host);
      return host.firstElementChild!;
    };
    expect(isTypingTarget(make('<input />'))).toBe(true);
    expect(isTypingTarget(make('<textarea></textarea>'))).toBe(true);
    expect(isTypingTarget(make('<select></select>'))).toBe(true);
    expect(isTypingTarget(make('<div role="textbox"></div>'))).toBe(true);
    /* The positive control: something that is *not* a field, so the assertions
     * above are about the predicate and not about it returning `true` for
     * everything. */
    expect(isTypingTarget(make('<div></div>'))).toBe(false);
    expect(isTypingTarget(null)).toBe(false);
    for (const host of hosts) host.remove();
  });

  function Harness({ log }: { log: string[] }) {
    useKeyBindings({
      '/': () => log.push('slash'),
      i: () => log.push('i'),
      Escape: () => log.push('escape'),
      'mod+k': () => log.push('palette'),
    });
    return <input aria-label="field" />;
  }

  it('holds every unmodified binding while the caret is in a field', () => {
    const log: string[] = [];
    render(<Harness log={log} />);
    const field = screen.getByLabelText('field');

    /* Positive control first: the same keys *do* fire from outside a field, so
     * an empty log below means the guard held rather than that the listener
     * was never installed. */
    fireEvent.keyDown(document.body, { key: '/' });
    fireEvent.keyDown(document.body, { key: 'i' });
    expect(log).toEqual(['slash', 'i']);

    log.length = 0;
    fireEvent.keyDown(field, { key: '/' });
    fireEvent.keyDown(field, { key: 'i' });
    expect(log, '/ and I fired while the user was typing them into a field').toEqual([]);
  });

  it('lets Escape and ⌘K through from inside a field, deliberately', () => {
    const log: string[] = [];
    render(<Harness log={log} />);
    const field = screen.getByLabelText('field');
    fireEvent.keyDown(field, { key: 'Escape' });
    fireEvent.keyDown(field, { key: 'k', metaKey: true });
    expect(log).toEqual(['escape', 'palette']);
  });

  it('leaves an event alone once something nearer has claimed it', () => {
    /* A dialog's own Escape handler calls `preventDefault`; the global one must
     * not then also close the panel behind it. */
    const log: string[] = [];
    render(<Harness log={log} />);
    const event = new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true });
    event.preventDefault();
    act(() => {
      document.body.dispatchEvent(event);
    });
    expect(log).toEqual([]);
  });
});

describe('the focus bus', () => {
  it('reports whether anything was listening, which is how / knows to navigate', () => {
    /* The return value is the whole point. A silent no-op would make `/` work
     * on the search screen and do nothing on the other five. */
    const listener = vi.fn();
    const off = onFocusRequest('search', listener);
    expect(requestFocus('search')).toBe(true);
    expect(listener).toHaveBeenCalledTimes(1);

    off();
    expect(requestFocus('search'), 'a request was answered by a field that had unmounted').toBe(
      false,
    );
    expect(listener).toHaveBeenCalledTimes(1);
  });

  it('holds a request until a field mounts to take it', () => {
    /* `/` on the library screen navigates to a `lazy()` chunk that mounts some
     * frames later. Without this the binding would land the user on the right
     * screen with the caret nowhere — half a shortcut, and the annoying half. */
    expect(requestFocus('search')).toBe(false);
    const listener = vi.fn();
    onFocusRequest('search', listener);
    expect(listener).toHaveBeenCalledTimes(1);
  });

  it('delivers a held request exactly once', () => {
    requestFocus('search');
    const first = vi.fn();
    const second = vi.fn();
    onFocusRequest('search', first);
    onFocusRequest('search', second);
    expect(first).toHaveBeenCalledTimes(1);
    expect(second, 'the held request was delivered twice').not.toHaveBeenCalled();
  });
});

describe('the shortcut sheet', () => {
  it('lists every binding docs/09 §6 declares, in its order', () => {
    render(
      <I18nProvider>
        <ShortcutSheet onClose={vi.fn()} />
      </I18nProvider>,
    );
    const rows = [...document.querySelectorAll('[data-binding]')].map(
      (node) => (node as HTMLElement).dataset.binding,
    );
    expect(rows).toEqual(BINDINGS.map((binding) => binding.id));
    /* The sheet's one structural guarantee, so "it cannot be empty" is checked
     * rather than asserted in a comment. */
    expect(rows.length).toBeGreaterThan(0);
  });

  it('marks a deferred binding Later, with the blocker named', () => {
    render(
      <I18nProvider>
        <ShortcutSheet onClose={vi.fn()} />
      </I18nProvider>,
    );
    const trash = document.querySelector('[data-binding="trash"]') as HTMLElement;
    expect(trash.dataset.state).toBe('later');
    expect(trash.textContent).toContain('The trash, and the undo that goes with it');

    /* The positive control: a *built* binding carries none of that treatment,
     * so the assertion above is about the deferred ones and not about every
     * row looking the same. */
    const palette = document.querySelector('[data-binding="palette"]') as HTMLElement;
    expect(palette.dataset.state).toBe('built');
    expect(palette.querySelector('.ui-later')).toBeNull();
  });

  it('agrees with the table about which bindings dispatch', () => {
    /* One source, two consumers. This is the assertion that keeps them one. */
    for (const binding of BINDINGS) {
      expect(BUILT.has(binding.id)).toBe(binding.state === 'built');
    }
  });

  it('takes focus on open and closes on Escape', () => {
    const onClose = vi.fn();
    render(
      <I18nProvider>
        <ShortcutSheet onClose={onClose} />
      </I18nProvider>,
    );
    const dialog = screen.getByRole('dialog');
    expect(dialog.contains(document.activeElement), 'the dialog opened without focus').toBe(true);
    fireEvent.keyDown(dialog, { key: 'Escape' });
    expect(onClose).toHaveBeenCalled();
  });
});

describe('the command palette', () => {
  const COMMANDS: readonly Command[] = [
    { id: 'files', label: 'nav.files', icon: 'folder', run: vi.fn() },
    { id: 'home', label: 'nav.home', icon: 'home', run: vi.fn() },
    { id: 'trash', label: 'kbd.action.trash', icon: 'trash', shortcut: 'key.delete', note: 'kbd.note.trash' },
  ];

  function open(onSearch = vi.fn()) {
    render(
      <I18nProvider>
        <CommandPalette commands={COMMANDS} onClose={vi.fn()} onSearch={onSearch} />
      </I18nProvider>,
    );
    return { input: screen.getByRole('combobox'), onSearch };
  }

  it('filters on what the user can see, not on the catalog key', () => {
    /* `nav.files` renders as "Files". Filtering on the key would match "nav"
     * and would not match the translated word — a palette searchable only in
     * English, by people who had read the source. */
    const { input } = open();
    fireEvent.change(input, { target: { value: 'nav' } });
    expect(screen.queryAllByRole('option')).toHaveLength(0);
    fireEvent.change(input, { target: { value: 'file' } });
    expect(screen.getAllByRole('option').map((node) => node.textContent)).toEqual([
      expect.stringContaining('Files'),
    ]);
  });

  it('moves a virtual cursor with the arrows, leaving focus in the field', () => {
    const { input } = open();
    expect(document.activeElement).toBe(input); // positive control
    expect(screen.getAllByRole('option')[0]?.getAttribute('aria-selected')).toBe('true');

    fireEvent.keyDown(input, { key: 'ArrowDown' });
    expect(screen.getAllByRole('option')[1]?.getAttribute('aria-selected')).toBe('true');
    expect(
      document.activeElement,
      'focus left the field, so the next keystroke would not reach it',
    ).toBe(input);
    expect(input.getAttribute('aria-activedescendant')).toBe('palette-home');
  });

  it('shows an unbuilt command with its shortcut rather than hiding it', () => {
    /* `docs/09 §5`: the palette is how users learn the shortcuts. A command
     * that appears only once it works teaches nobody. */
    open();
    const trash = screen.getByRole('option', { name: /Move to trash/ });
    expect(trash.dataset.state).toBe('later');
    expect(trash.getAttribute('aria-disabled')).toBe('true');
    expect(trash.textContent).toContain('Del');
  });

  it('offers the typed text to search when nothing matches', () => {
    const { input, onSearch } = open();
    fireEvent.change(input, { target: { value: 'zzzz' } });
    expect(screen.queryAllByRole('option')).toHaveLength(0);
    const fallback = screen.getByRole('button', { name: 'Search files instead' });
    fireEvent.click(fallback);
    expect(onSearch).toHaveBeenCalledWith('zzzz');
  });
});

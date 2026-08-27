/* Two icons, inline.
 *
 * `design-taste-frontend` §9.E says not to hand-roll SVG icons and to pull a
 * set instead. Overruled here, deliberately and narrowly: the list needs
 * exactly two glyphs, both are already defined in
 * `web/design-system/design-system-v2.html` (`#chev`, `#file`) which is
 * authoritative for appearance, and an icon package would add a dependency and
 * bytes to a bundle that `docs/09 §2` caps at 250 KB gzipped. When the shell
 * needs the other thirty, a package earns its place; two is not thirty.
 *
 * Both are decorative. Neither carries meaning the row does not also carry in
 * text, so both are `aria-hidden` and neither has a `<title>` — a `<title>` is
 * a user-facing string and those live in the catalog (`CLAUDE.md` rule 12,
 * echoed by `web/public/BRAND.md`).
 */

export function ChevronIcon({ className }: { className?: string }) {
  return (
    <svg
      className={className}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      <path d="m6 9 6 6 6-6" />
    </svg>
  );
}

export function FileIcon({ className, kind }: { className?: string; kind: string }) {
  return (
    <svg
      className={className}
      data-kind={kind}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.8}
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {/* A folder is a different shape, not a differently tinted page.
       *
       * The list is mostly scanned rather than read, and the glyph is the first
       * thing that says "this opens into more rows" — a folder wearing the page
       * outline made every row look alike until the name was read. `#folder` in
       * `design-system-v2.html` is the source of this path. */}
      {kind === 'folder' ? (
        <path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />
      ) : (
        <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8zM14 3v5h5" />
      )}
    </svg>
  );
}

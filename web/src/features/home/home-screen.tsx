/* Home — placeholder.
 *
 * Owned by the `features/home` session and replaced wholesale. It exists so
 * the router's lazy import resolves and the build stays green while the screens
 * land in parallel.
 *
 * It renders an empty region and claims nothing, which is deliberate: this
 * milestone's whole discipline is that a screen is a promise, and a stub that
 * drew a convincing-looking layout would be making one.
 */
export default function Screen() {
  return <div style={{ flex: 1, minBlockSize: 0 }} />;
}

/* The client's half of the integrity check.
 *
 * `POST /uploads/{id}/complete` takes a lowercase-hex SHA-256 that the client
 * computed over the bytes it sent, and the server refuses a malformed one
 * outright — verified against the running binary, which answers
 * `400 VALIDATION_FAILED` with `details: [{code: "INVALID_FORMAT", field:
 * "sha256"}]` for an uppercase digest. So the casing below is a contract, not a
 * style choice.
 *
 * ## What the server does and does not verify, on this stack
 *
 * Worth stating precisely, because it is easy to assume more protection than
 * there is. `crates/uploads/src/content.rs` compares three numbers:
 *
 *   * the size **declared** at `POST /uploads` against the size **reported** at
 *     `complete` — a mismatch is `400 INCONSISTENT`;
 *   * the reported size against the size the **store observed** — also refused;
 *   * the reported digest against a digest **the store observed**, *if the
 *     store supplies one*. MinIO does not return `ChecksumSHA256` for an
 *     ordinary presigned `PUT`, so that branch falls to
 *     `ChecksumEvidence::ClientDeclared` and the digest is recorded unverified.
 *
 * Confirmed by hand: completing with `sha256` of all zeroes over a real object
 * answers `202` and persists `checksumSha256: "0000…"` on the version.
 *
 * That is an argument for computing this **correctly**, not for skipping it.
 * The value is what the version carries forever and what a later integrity
 * check compares against, so a client that sent a placeholder would be writing
 * a lie into the record that nothing downstream could detect.
 */

/**
 * SHA-256 of a file's bytes, as lowercase hex.
 *
 * Reads the file in chunks rather than calling `file.arrayBuffer()` on the
 * whole thing: a 2 GB upload would otherwise be held in memory twice, once as
 * the `ArrayBuffer` and once inside `crypto.subtle.digest`, and the tab would
 * be killed before it ever reached the network.
 *
 * `crypto.subtle` has no streaming digest — there is no `update`/`final` pair
 * in the Web Crypto API — so the chunking here buys the *read*, not the digest.
 * The whole buffer still reaches `digest` once. That is the honest limit of the
 * platform, and it is recorded rather than papered over: `ENC-823` is the row
 * for a worker-thread incremental digest if upload sizes make it necessary.
 *
 * `onProgress` reports the fraction read so the row can show that hashing is
 * happening. A large file spends real time here *before* a byte is sent, and a
 * progress bar that sits at zero through it reads as a hang.
 */
export async function sha256Hex(
  file: Blob,
  onProgress?: (fraction: number) => void,
): Promise<string> {
  const buffer = await readAll(file, onProgress);
  const digest = await crypto.subtle.digest('SHA-256', buffer);
  return hex(new Uint8Array(digest));
}

/** 8 MiB. Large enough that the loop is not the cost, small enough to stay responsive. */
const CHUNK = 8 * 1024 * 1024;

async function readAll(file: Blob, onProgress?: (fraction: number) => void): Promise<ArrayBuffer> {
  if (file.size <= CHUNK) {
    onProgress?.(1);
    return file.arrayBuffer();
  }

  const out = new Uint8Array(file.size);
  let offset = 0;
  while (offset < file.size) {
    const slice = file.slice(offset, Math.min(offset + CHUNK, file.size));
    const chunk = new Uint8Array(await slice.arrayBuffer());
    out.set(chunk, offset);
    offset += chunk.byteLength;
    onProgress?.(offset / file.size);
    /* Yield to the event loop between chunks. Without it a multi-gigabyte read
     * blocks paint for its whole duration and `docs/09 §2`'s one-frame
     * keystroke budget is missed across the entire application, not just here. */
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  return out.buffer;
}

/**
 * Lowercase hex, built from a lookup table.
 *
 * `toString(16)` per byte needs a `padStart` and allocates two strings a byte;
 * over a 32-byte digest that is irrelevant, and the table is here because the
 * padding is the part people forget — a digest with a `0a` byte written as `a`
 * is 63 characters and the server rejects it as malformed, which is a bug that
 * only appears for one input in sixteen.
 */
const HEX = Array.from({ length: 256 }, (_, index) => index.toString(16).padStart(2, '0'));

function hex(bytes: Uint8Array): string {
  let out = '';
  for (const byte of bytes) out += HEX[byte];
  return out;
}

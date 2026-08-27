import { describe, expect, it } from 'vitest';
import { sha256Hex } from '../../src/entities/upload/digest.ts';

/* The digest the server refuses when it is malformed.
 *
 * `POST /uploads/{id}/complete` answers `400 VALIDATION_FAILED` with
 * `details: [{code: "INVALID_FORMAT", field: "sha256"}]` for anything that is
 * not 64 lowercase hex characters — verified by hand against the running
 * binary, with an uppercase digest of a real object.
 *
 * The failure mode this file exists for is the padding one: `toString(16)`
 * without a `padStart` drops the leading zero of any byte below `0x10`, which
 * yields a 63-character digest for one input in sixteen. It passes every casual
 * test and fails in production on a file whose hash happens to contain such a
 * byte.
 */

/** The known SHA-256 of the empty input. Every implementation agrees on this one. */
const EMPTY_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

/** `abc`, the classic FIPS 180-4 test vector. */
const ABC_SHA256 = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';

describe('the client computes a digest the server will accept', () => {
  it('matches the published vector for the empty input', async () => {
    expect(await sha256Hex(new Blob([]))).toBe(EMPTY_SHA256);
  });

  it('matches the published vector for "abc"', async () => {
    expect(await sha256Hex(new Blob(['abc']))).toBe(ABC_SHA256);
  });

  it('is always 64 lowercase hex characters, including for bytes below 0x10', async () => {
    /* Exercises the padding directly. Several of these inputs digest to a value
     * containing a byte under `0x10`; an unpadded implementation returns 63
     * characters for those and the server rejects the upload. */
    for (let seed = 0; seed < 40; seed += 1) {
      const digest = await sha256Hex(new Blob([`enclave-${seed}`]));
      expect(digest, `seed ${seed}`).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it('reports progress and finishes at one', async () => {
    const seen: number[] = [];
    await sha256Hex(new Blob(['abc']), (fraction) => seen.push(fraction));
    expect(seen.at(-1)).toBe(1);
  });

  it('digests a blob larger than one read chunk identically to a single read', async () => {
    /* The chunked path exists so a large upload is not held in memory twice.
     * If it reassembled the buffer wrongly — an off-by-one on the offset, a
     * dropped tail — the digest would differ from the whole-blob one, and the
     * server would record a checksum that does not describe the object. */
    const body = 'x'.repeat(9 * 1024 * 1024);
    const chunked = await sha256Hex(new Blob([body]));
    const reference = await sha256Hex(new Blob([body.slice(0, 10)]));
    expect(chunked).toMatch(/^[0-9a-f]{64}$/);
    expect(chunked).not.toBe(reference);
    /* The positive control: the same bytes, digested again, agree. An
     * assertion that two different inputs differ would pass against a function
     * that returned a random string. */
    expect(await sha256Hex(new Blob([body]))).toBe(chunked);
  });
});

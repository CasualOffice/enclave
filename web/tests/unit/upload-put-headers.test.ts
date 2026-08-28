import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { putBytes, TransferError } from '../../src/entities/upload/api.ts';

/* `ENC-820` / `ENC-832`: the browser's `PUT` carries the headers the API signed.
 *
 * `POST /uploads` signs the client's declared SHA-256 into the pre-signed `PUT`
 * as `x-amz-checksum-sha256` and returns every header that `PUT` must carry, at
 * the exact value that was signed, in `requiredHeaders` (`docs/05 §8.1`). The
 * header **names** appear in `X-Amz-SignedHeaders`, so this is not advisory: a
 * `PUT` that omits one fails the provider's signature check with
 * `403 SignatureDoesNotMatch`, and one that sends a different value fails the
 * same way. The moment the server half merges, every browser upload fails until
 * the client sends them.
 *
 * ## Why this test runs a real HTTP server
 *
 * **A mocked `PUT` accepts any headers.** It would pass against a client that
 * sent none, which is precisely the state this test exists to catch, and it is
 * the "green while the product is broken" shape this milestone keeps finding
 * (`ENC-543`, `ENC-677`). So the transfer below goes over a real socket to a
 * real server, through the same `XMLHttpRequest` the browser uses, and the
 * server refuses the way S3 and MinIO refuse.
 *
 * The server is a *stand-in for the provider*, not for `putBytes`: it knows the
 * signed header set and the declared digest and it enforces both, so the
 * assertions are about what arrived on the wire rather than about what the code
 * was asked to do. Its two refusals mirror the two the real store makes —
 * `403 SignatureDoesNotMatch` for a missing or altered signed header,
 * `400 BadDigest` for the right checksum over the wrong bytes.
 *
 * The server-side proof already exists against real MinIO
 * (`a_lying_client_cannot_store_an_object_under_a_digest_it_declared`); this is
 * the browser half of the same claim.
 */

/** The body every case below sends, and the digest the API would have signed for it. */
const BODY = 'board pack, october';
const SHA256_BASE64 = createHash('sha256').update(BODY).digest('base64');

/**
 * What `POST /uploads` would have returned for that body.
 *
 * Lower-case names and the provider's own value format, because that is what
 * `IssuedUploadView::required_headers` puts on the wire — a `BTreeMap<String,
 * String>` copied from the store, not a shape this client gets to normalise.
 */
const REQUIRED_HEADERS: Readonly<Record<string, string>> = {
  'content-type': 'application/pdf',
  'x-amz-checksum-sha256': SHA256_BASE64,
};

interface Seen {
  readonly headers: Record<string, string>;
  readonly body: string;
}

let server: Server;
let origin: string;
let lastSeen: Seen | undefined;

/** The provider, as far as this test is concerned. Refuses exactly as S3 does. */
function handle(request: IncomingMessage, response: ServerResponse): void {
  /* jsdom sends a CORS preflight for the custom `x-amz-*` header, exactly as a
   * browser does — and a real bucket has to be configured to answer it too, so
   * this is part of the path rather than a test artefact. */
  if (request.method === 'OPTIONS') {
    response.writeHead(204, {
      'access-control-allow-origin': '*',
      'access-control-allow-methods': 'PUT',
      'access-control-allow-headers': request.headers['access-control-request-headers'] ?? '*',
    });
    response.end();
    return;
  }

  const chunks: Buffer[] = [];
  request.on('data', (chunk: Buffer) => chunks.push(chunk));
  request.on('end', () => {
    const body = Buffer.concat(chunks).toString('utf8');
    lastSeen = {
      headers: Object.fromEntries(
        Object.entries(request.headers).map(([name, value]) => [
          name,
          Array.isArray(value) ? value.join(',') : (value ?? ''),
        ]),
      ),
      body,
    };

    const cors = { 'access-control-allow-origin': '*' };

    /* The signature check. Every name in `X-Amz-SignedHeaders` must be present
     * with the value that was signed; anything else is `SignatureDoesNotMatch`,
     * which the store answers with a `403`. */
    for (const [name, value] of Object.entries(REQUIRED_HEADERS)) {
      if (lastSeen.headers[name] !== value) {
        response.writeHead(403, cors);
        response.end('SignatureDoesNotMatch');
        return;
      }
    }

    /* The digest check, which is the whole of `ENC-820`: the store computes the
     * hash of the body it received and refuses the object if it disagrees with
     * the one the URL was signed for. */
    if (createHash('sha256').update(body).digest('base64') !== REQUIRED_HEADERS['x-amz-checksum-sha256']) {
      response.writeHead(400, cors);
      response.end('BadDigest');
      return;
    }

    response.writeHead(200, cors);
    response.end();
  });
}

beforeAll(async () => {
  server = createServer(handle);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (address === null || typeof address === 'string') throw new Error('no port');
  origin = `http://127.0.0.1:${address.port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

function put(headers: Readonly<Record<string, string>>, body = BODY): Promise<void> {
  lastSeen = undefined;
  return putBytes(
    `${origin}/tenant/versions/object`,
    new Blob([body]),
    headers,
    () => undefined,
    new AbortController().signal,
  );
}

describe('the browser PUT carries the headers the API signed', () => {
  it('sends every required header, at the value the server gave it', async () => {
    await expect(put(REQUIRED_HEADERS)).resolves.toBeUndefined();

    /* Read off the wire, not off the call. The point of the exercise is what
     * arrived at the provider. */
    expect(lastSeen?.headers['content-type']).toBe('application/pdf');
    expect(lastSeen?.headers['x-amz-checksum-sha256']).toBe(SHA256_BASE64);
  });

  it('fails the signature check when the checksum header is dropped', async () => {
    /* The regression this exists for: a client that filters `requiredHeaders`
     * down to the names it recognises, or that never reads the field at all.
     * `403 SignatureDoesNotMatch` is what the real store answers, and it reads
     * as a permission problem rather than a header problem — which is why the
     * fix has to be asserted rather than remembered (`ENC-821`). */
    await expect(put({ 'content-type': 'application/pdf' })).rejects.toThrow(TransferError);
    expect(lastSeen?.headers['x-amz-checksum-sha256']).toBeUndefined();
  });

  it('fails the signature check when the content type is reconstructed rather than passed through', async () => {
    /* A value computed locally is a different string from the one that was
     * signed even when it is the "right" media type — here, the browser's own
     * default for a `Blob`. The signature does not care which is right. */
    await expect(
      put({ ...REQUIRED_HEADERS, 'content-type': 'application/octet-stream' }),
    ).rejects.toThrow(TransferError);
  });

  it('is refused on the digest when the bytes are not the ones that were declared', async () => {
    /* `ENC-820`'s actual purpose: the provider verifies, so a client that
     * declares one digest and sends other bytes stores nothing and `complete`
     * never sees an object. */
    await expect(put(REQUIRED_HEADERS, 'different bytes entirely')).rejects.toThrow(TransferError);
  });

  it('reports the store’s status on the rejection, so the row can classify it', async () => {
    /* `store.ts` turns a `TransferError` into a retryable `upload_transfer`
     * failure rather than into a denial. It needs the status to keep being
     * carried, or a `403` from the store would be indistinguishable from a
     * network drop. */
    await expect(put({ 'content-type': 'application/pdf' })).rejects.toMatchObject({ status: 403 });
    await expect(put(REQUIRED_HEADERS, 'different bytes entirely')).rejects.toMatchObject({
      status: 400,
    });
  });
});

import { z } from 'zod';
import { request } from '../../shared/api/client.ts';
import { VersionPage } from '../file/api-model.ts';

/* The upload path: **three requests, and the middle one does not come here.**
 *
 *   1. `POST /api/v1/uploads`            — decides, and issues a signed URL
 *   2. `PUT <that URL>`                  — the bytes, straight to object storage
 *   3. `POST /api/v1/uploads/{id}/complete` — size + client-computed SHA-256
 *
 * Step 2 is the one worth being explicit about: the bytes **never pass through
 * the API**. That is why `putBytes` below uses a bare `XMLHttpRequest` rather
 * than `shared/api/client.ts` — the client attaches a bearer token, an
 * idempotency key and `credentials: 'same-origin'`, and sending any of those to
 * a third-party object store would leak the session credential to a host that
 * has no business seeing it. A presigned URL carries its own authority in the
 * query string; adding ours to it is strictly a disclosure.
 *
 * ## Two things learned by driving this against MinIO
 *
 * **The signed headers come from the server, not from here.** The issued URL is
 * signed over a set of headers named in `X-Amz-SignedHeaders`, and a `PUT` that
 * omits one, or sends a different value for one, fails the provider's signature
 * check with `403 SignatureDoesNotMatch` — which reads as a permission problem
 * rather than a header problem and cost the first client written against this
 * API two attempts to diagnose (`ENC-821`).
 *
 * That was `content-type`, threaded by hand from the value this client had
 * declared. `ENC-820` adds a second — `x-amz-checksum-sha256`, which is what
 * makes the store itself verify the digest — and, with it,
 * `requiredHeaders` on the `201`: **every header the `PUT` must carry, with the
 * exact value that was signed** (`docs/05 §8.1`). The hand-threaded
 * `Content-Type` is gone rather than left beside it, because two sources for one
 * header is how they drift, and the drift would present as a `403`.
 *
 * The map is sent **verbatim**: not filtered to the names this client happens to
 * recognise, not re-cased, not reordered, and nothing recomputed locally. A
 * value computed here is a different string from the one that was signed even
 * when it looks identical, and the signature does not care which of the two is
 * "right".
 *
 * **`GET /uploads/{id}`'s own `state` is not the readiness signal** — and that
 * is still true, deliberately. The session reports `CREATED` before `complete`
 * and `SCANNING` after it, and it stays `SCANNING`: handing the staged object
 * to antivirus is the last transition the *session* makes, and everything after
 * it happens to the version. A tray that waited for `state` to become "ready"
 * waits forever, and did (`ENC-826`).
 *
 * What has changed is the rest of that response. `ENC-826` added the committed
 * `version` — `status`, `avStatus`, `isReadable` — and `fileId` beside the
 * session's `state`, so `GET /uploads/{id}` *can* now answer readiness; read the
 * version's state beside the session's, never instead of it (`docs/05 §8.1`).
 * The `fileId` is no longer only in the `complete` response either.
 *
 * The store still polls `GET /files/{id}/versions`, which also answers, and
 * moving it is `ENC-848` — see the poll's own comment in `store.ts` for why
 * that is left to a session that can drive a real upload.
 */

/** What `POST /uploads` answers. `uploadUrl` and `urls` are mutually exclusive; `method` says which. */
const IssuedUpload = z.object({
  uploadId: z.string(),
  method: z.enum(['SINGLE', 'MULTIPART']),
  uploadUrl: z.string().optional(),
  /**
   * Every header the pre-signed `PUT` must carry, verbatim.
   *
   * **Required, not optional** (`docs/05 §8.1`). Optional would make the one
   * failure mode this field exists to prevent — a `PUT` sent without the signed
   * headers — a silent `403` from a third-party host at the end of a transfer,
   * rather than a parse error before it starts. `ENC-821` is that debugging
   * session; once was enough.
   *
   * The server omits it only on a `MULTIPART` response, which it documents as
   * unreachable: `UploadService::create` always declares a digest, and a store
   * that cannot have the provider confirm one for an upload that size refuses
   * before a URL exists (`403 QUOTA_EXCEEDED`, `ENC-829`). This client refuses
   * `MULTIPART` anyway, so requiring the field costs a clearer message on a
   * response that should not occur, and buys a loud failure on the one that
   * would otherwise cost bytes.
   *
   * `z.record` rather than a named shape on purpose: the set of signed headers
   * is the *store's*, and a client that enumerated the two it knows about today
   * would silently drop a third.
   */
  requiredHeaders: z.record(z.string(), z.string()),
  urls: z
    .array(
      z.object({
        partNumber: z.number(),
        offset: z.number(),
        length: z.number(),
        url: z.string(),
      }),
    )
    .optional(),
  partSize: z.number().optional(),
  urlsExpireAt: z.string(),
  expiresAt: z.string(),
});

export type IssuedUpload = z.infer<typeof IssuedUpload>;

/** What `POST /uploads/{id}/complete` answers. `202`, and `state` is always `SCANNING`. */
const HandedOff = z.object({
  uploadId: z.string(),
  fileId: z.string(),
  versionId: z.string(),
  state: z.string(),
});

export type HandedOff = z.infer<typeof HandedOff>;

export interface CreateUploadInput {
  readonly libraryId: string;
  readonly parentId?: string | undefined;
  readonly name: string;
  readonly sizeBytes: number;
  readonly mimeType: string;
  readonly sha256: string;
}

/**
 * Step 1 — ask permission and get somewhere to put it.
 *
 * This is also the **pre-flight** `docs/09 §8` asks for: *"surface a rejected
 * file type or size before bytes are sent"*. No endpoint publishes the
 * per-library ceiling or the extension allow-list, so the client cannot check
 * them itself — and inventing a limit would be re-deriving a policy decision.
 * What it can do is ask first, which is exactly what this call is: it answers
 * `400` for a refused name or size, and `403` for a refused *user*, before a
 * single byte has left the machine. The distinction between those two is
 * preserved all the way to the row (`docs/17 §7`).
 *
 * The declared `sha256` is sent up front so a store that supports it can refuse
 * a corrupted transfer at the edge. MinIO does not, which is recorded in
 * `digest.ts` rather than treated as a reason to omit it.
 */
export function createUpload(input: CreateUploadInput): Promise<IssuedUpload> {
  return request('/uploads', IssuedUpload, {
    method: 'POST',
    body: {
      libraryId: input.libraryId,
      ...(input.parentId === undefined ? {} : { parentId: input.parentId }),
      name: input.name,
      sizeBytes: input.sizeBytes,
      mimeType: input.mimeType,
      sha256: input.sha256,
    },
  });
}

/** How a `PUT` to the object store ended. Not an `ApiError`: no `/api/v1` handler was involved. */
export class TransferError extends Error {
  readonly status: number;
  constructor(status: number) {
    super(`upload_transfer_${status}`);
    this.name = 'TransferError';
    this.status = status;
  }
}

/**
 * Step 2 — the bytes, to the store, with real progress.
 *
 * `XMLHttpRequest` rather than `fetch` for one reason: **`fetch` cannot report
 * upload progress.** `ReadableStream` request bodies are the standard answer and
 * are not available cross-browser without HTTP/2 and duplex support, and a
 * progress bar is not decoration here — `docs/09 §8` requires per-file progress,
 * and a 2 GB transfer showing nothing until it finishes is indistinguishable
 * from a hang.
 *
 * Note what is *absent*: no `Authorization`, no `idempotency-key`, no cookies.
 * `withCredentials` stays `false`. See the header of this file.
 *
 * `headers` is `requiredHeaders` from the `201`, passed through untouched. This
 * function deliberately knows nothing about which headers those are: it does not
 * default a `Content-Type`, does not add one the map omits, and does not drop
 * one it does not recognise. Every value in it was signed into the URL, and the
 * provider verifies the set rather than the intent.
 */
export function putBytes(
  url: string,
  file: Blob,
  headers: Readonly<Record<string, string>>,
  onProgress: (sentBytes: number) => void,
  signal: AbortSignal,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('PUT', url, true);
    /* Verbatim, and all of them. `x-amz-checksum-sha256` is what makes the store
     * compute the digest of the body it receives and refuse the object if it
     * disagrees with what was declared (`ENC-820`) — so a client cannot decline
     * to be checked without also failing to upload. Reconstructing any of these
     * locally would produce a different string from the one that was signed. */
    for (const [name, value] of Object.entries(headers)) {
      xhr.setRequestHeader(name, value);
    }
    xhr.withCredentials = false;

    xhr.upload.addEventListener('progress', (event) => {
      if (event.lengthComputable) onProgress(event.loaded);
    });

    xhr.addEventListener('load', () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        onProgress(file.size);
        resolve();
      } else {
        reject(new TransferError(xhr.status));
      }
    });
    /* Status 0 is the network's answer for "did not happen": DNS, TLS, a
     * refused connection, or CORS. Distinguished from a real status so the row
     * can say *retryable* honestly. */
    xhr.addEventListener('error', () => reject(new TransferError(0)));
    xhr.addEventListener('timeout', () => reject(new TransferError(0)));
    xhr.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));

    signal.addEventListener('abort', () => xhr.abort(), { once: true });
    if (signal.aborted) {
      xhr.abort();
      return;
    }

    xhr.send(file);
  });
}

/**
 * Step 3 — hand off, and be told the content is not ready.
 *
 * `202` with `state: "SCANNING"`, always. `docs/05 §8` specifies it and
 * `CLAUDE.md` rule 9 is why: the bytes exist, nothing has inspected them, and
 * no read path may serve them yet. A client that treated this `202` as *done*
 * would be reporting a file ready at the exact moment the product guarantees it
 * is not.
 *
 * The size is verified against both the declaration and the store, so a
 * mismatch answers `400` — see `digest.ts` for what the checksum does and does
 * not buy on this stack.
 */
export function completeUpload(
  uploadId: string,
  sizeBytes: number,
  sha256: string,
): Promise<HandedOff> {
  return request(`/uploads/${encodeURIComponent(uploadId)}/complete`, HandedOff, {
    method: 'POST',
    body: { sizeBytes, sha256 },
  });
}

/** `DELETE /api/v1/uploads/{id}` — release a session the user cancelled. */
export function abortUpload(uploadId: string): Promise<unknown> {
  return request(`/uploads/${encodeURIComponent(uploadId)}`, z.unknown(), { method: 'DELETE' });
}

/**
 * The readiness poll: `GET /files/{id}/versions`.
 *
 * The only endpoint that publishes `isReadable`, which is the only field that
 * answers "may these bytes be served". See `model.ts` for why `status` alone
 * cannot be read as *Ready*.
 */
export function readVersions(fileId: string, signal?: AbortSignal): Promise<VersionPage> {
  return request(
    `/files/${encodeURIComponent(fileId)}/versions`,
    VersionPage,
    signal === undefined ? {} : { signal },
  );
}

import { create } from 'zustand';
import type { Failure } from '../../shared/api/failure.ts';
import { failureOf } from '../../shared/api/failure.ts';
import { ApiError } from '../../shared/api/client.ts';
import type { MessageKey } from '../../shared/i18n/catalog.ts';
import { sha256Hex } from './digest.ts';
import { abortUpload, completeUpload, createUpload, putBytes, readVersions } from './api.ts';
import { isActive, phaseFromVersion, unreadableNote, type UploadPhase } from './model.ts';

/* The upload queue, and why it is a module-level store rather than state in the
 * component that started it.
 *
 * `docs/09 §8`: *"keep uploads running across navigation within the app"*. A
 * transfer owned by the library screen dies the moment the user clicks Search,
 * and the file is silently gone. So the queue lives outside the React tree, the
 * tray subscribes to it, and navigating unmounts the view and not the work.
 *
 * This is the one place in the client where a Zustand store holds something
 * derived from the server — the phase of each row after `complete` — and it is
 * deliberate: an upload is a *process the client is running*, not a resource
 * TanStack Query is caching. What the store never holds is a permission. The
 * `refused` phase carries the server's own `Failure` and the row renders that
 * verbatim (`docs/17 §1`).
 */

export interface UploadRow {
  /** Client-side identity. The server's `uploadId` arrives only after step 1. */
  readonly id: string;
  readonly name: string;
  readonly sizeBytes: number;
  readonly mimeType: string;
  readonly libraryId: string;
  readonly parentId: string | undefined;
  readonly phase: UploadPhase;
  /** 0–1. During `hashing` it is the read fraction; during `uploading`, bytes sent. */
  readonly progress: number;
  readonly uploadId: string | undefined;
  readonly fileId: string | undefined;
  /**
   * Why it stopped, when it stopped badly.
   *
   * A `Failure`, not a string: `denied` and `failed` are different outcomes and
   * the row draws them differently — one gets a reason and no retry, the other
   * gets retry and a request id (`docs/17 §7`).
   */
  readonly failure: Failure | undefined;
  /** An extra sentence for a published-but-unreadable version. A catalog key. */
  readonly note: MessageKey | undefined;
}

interface UploadState {
  readonly rows: readonly UploadRow[];
  /** Whether the user has dismissed the tray. Re-opens when a new upload starts. */
  readonly trayOpen: boolean;
  enqueue: (files: readonly File[], libraryId: string, parentId: string | undefined) => void;
  cancel: (id: string) => void;
  retry: (id: string) => void;
  dismiss: (id: string) => void;
  clearSettled: () => void;
  setTrayOpen: (open: boolean) => void;
}

/** The `AbortController` per row, kept outside the store: it is not renderable state. */
const controllers = new Map<string, AbortController>();
/** The `File` handle per row. Not in the store — it is a large object and never rendered. */
const handles = new Map<string, File>();
/** The poll timer per row, so a cancelled row stops asking. */
const timers = new Map<string, ReturnType<typeof setTimeout>>();

function patch(id: string, changes: Partial<UploadRow>): void {
  useUploadStore.setState((state) => ({
    rows: state.rows.map((row) => (row.id === id ? { ...row, ...changes } : row)),
  }));
}

function forget(id: string): void {
  controllers.delete(id);
  handles.delete(id);
  const timer = timers.get(id);
  if (timer !== undefined) clearTimeout(timer);
  timers.delete(id);
}

export const useUploadStore = create<UploadState>((set, get) => ({
  rows: [],
  trayOpen: false,

  enqueue: (files, libraryId, parentId) => {
    const rows = files.map((file) => {
      const id = crypto.randomUUID();
      handles.set(id, file);
      return {
        id,
        name: file.name,
        sizeBytes: file.size,
        /* The browser's guess, or a safe default. This exact string is signed
         * into the presigned URL and must be replayed on the `PUT`, so it is
         * captured once here and never recomputed. */
        mimeType: file.type.length > 0 ? file.type : 'application/octet-stream',
        libraryId,
        parentId,
        phase: 'queued' as UploadPhase,
        progress: 0,
        uploadId: undefined,
        fileId: undefined,
        failure: undefined,
        note: undefined,
      };
    });

    set((state) => ({ rows: [...rows, ...state.rows], trayOpen: true }));
    for (const row of rows) void run(row.id);
  },

  cancel: (id) => {
    controllers.get(id)?.abort();
    const row = get().rows.find((candidate) => candidate.id === id);
    /* Release the server's staged bytes as well as stopping the transfer. A
     * session left dangling holds its object until it expires. */
    if (row?.uploadId !== undefined) void abortUpload(row.uploadId).catch(() => undefined);
    patch(id, { phase: 'aborted', failure: undefined });
    forget(id);
  },

  retry: (id) => {
    const file = handles.get(id);
    if (file === undefined) return;
    patch(id, { phase: 'queued', progress: 0, failure: undefined, uploadId: undefined });
    void run(id);
  },

  dismiss: (id) => {
    forget(id);
    set((state) => ({ rows: state.rows.filter((row) => row.id !== id) }));
  },

  clearSettled: () => {
    const keep = get().rows.filter((row) => isActive(row.phase));
    for (const row of get().rows) if (!isActive(row.phase)) forget(row.id);
    set({ rows: keep });
  },

  setTrayOpen: (open) => set({ trayOpen: open }),
}));

/**
 * One file, end to end.
 *
 * Ordered so that the two things that can be refused happen before any bytes
 * move: the digest is computed locally, then `POST /uploads` asks the policy
 * chain. A `403` there costs the user nothing but the hash.
 */
async function run(id: string): Promise<void> {
  const file = handles.get(id);
  if (file === undefined) return;

  const controller = new AbortController();
  controllers.set(id, controller);

  const row = useUploadStore.getState().rows.find((candidate) => candidate.id === id);
  if (row === undefined) return;

  try {
    patch(id, { phase: 'hashing', progress: 0 });
    const sha256 = await sha256Hex(file, (fraction) => patch(id, { progress: fraction }));
    if (controller.signal.aborted) return;

    /* Step 1. Also the pre-flight: a refused type or size answers here, before
     * a byte is sent (`docs/09 §8`). */
    const issued = await createUpload({
      libraryId: row.libraryId,
      parentId: row.parentId,
      name: row.name,
      sizeBytes: row.sizeBytes,
      mimeType: row.mimeType,
      sha256,
    });
    patch(id, { uploadId: issued.uploadId, phase: 'uploading', progress: 0 });

    /* `MULTIPART` is issued for large files and this client does not implement
     * the per-part `PUT` and ETag report yet (`ENC-827`). Saying so is better
     * than sending the whole body to the first part's URL, which would store a
     * corrupt object and pass `complete`'s size check only by accident. */
    if (issued.method !== 'SINGLE' || issued.uploadUrl === undefined) {
      patch(id, {
        phase: 'failed',
        failure: { kind: 'failed', code: 'upload_multipart_unsupported', retryable: false, requestId: '' },
      });
      return;
    }

    /* Step 2 — the bytes, straight to the store. Never through the API. */
    await putBytes(
      issued.uploadUrl,
      file,
      row.mimeType,
      (sent) => patch(id, { progress: row.sizeBytes === 0 ? 1 : sent / row.sizeBytes }),
      controller.signal,
    );
    if (controller.signal.aborted) return;

    /* Step 3. `202 SCANNING` — and that is exactly what the row now says. It
     * does **not** say Ready (`CLAUDE.md` rule 9). */
    const handed = await completeUpload(issued.uploadId, row.sizeBytes, sha256);
    patch(id, { fileId: handed.fileId, phase: 'scanning', progress: 1 });
    poll(id, handed.fileId);
  } catch (error) {
    if (controller.signal.aborted || (error instanceof DOMException && error.name === 'AbortError')) {
      patch(id, { phase: 'aborted' });
      return;
    }
    patch(id, classify(error));
  }
}

/**
 * Turn a thrown thing into the row's terminal state.
 *
 * The `denied` branch is the reason this is a function rather than a `catch`
 * that sets `failed`. A policy refusal is not a failure (`docs/17 §7`): it gets
 * the server's reason, it is drawn neutral, and it offers no retry. Collapsing
 * the two would teach a user that "you may not upload here" means "try again".
 */
function classify(error: unknown): Partial<UploadRow> {
  const failure = failureOf(error);
  if (failure.kind === 'denied' || failure.kind === 'stepUp') {
    return { phase: 'refused', failure };
  }
  /* A `TransferError` is not an `ApiError`, so `failureOf` reports it as a
   * non-retryable `unexpected`. It is neither: the store answered, and a `5xx`
   * or a network drop there is worth another attempt. */
  if (!(error instanceof ApiError)) {
    return {
      phase: 'failed',
      failure: { kind: 'failed', code: 'upload_transfer', retryable: true, requestId: '' },
    };
  }
  return { phase: 'failed', failure };
}

/** How often the readiness poll asks, and for how long before it gives up. */
const POLL_MS = 2_000;
const POLL_LIMIT = 90;

/**
 * Watch a handed-off upload until the server says its bytes may be served.
 *
 * Polls `GET /files/{id}/versions` — **not** `GET /uploads/{id}`, which reports
 * `SCANNING` and never changes (`ENC-826`), and **not** `GET /files/{id}`,
 * whose `currentVersion` carries no `isReadable` (`ENC-825`).
 *
 * There is no push channel for this; `docs/05` registers no events endpoint the
 * client can subscribe to, so a poll is the honest implementation rather than a
 * placeholder for one.
 */
function poll(id: string, fileId: string, attempt = 0): void {
  if (attempt >= POLL_LIMIT) {
    patch(id, {
      phase: 'failed',
      failure: { kind: 'failed', code: 'upload_scan_timeout', retryable: false, requestId: '' },
    });
    return;
  }

  const timer = setTimeout(() => {
    void readVersions(fileId)
      .then((page) => {
        const version = page.items[0];
        if (version === undefined) {
          poll(id, fileId, attempt + 1);
          return;
        }
        const phase = phaseFromVersion(version);
        patch(id, { phase, note: unreadableNote(version) });
        /* Still moving. `scanning` on a published-but-unscanned version is a
         * resting state on this stack rather than a transient one, so the poll
         * keeps asking until the limit and then stops — it does not promise a
         * transition that no configured engine will ever make. */
        if (isActive(phase)) poll(id, fileId, attempt + 1);
        else forget(id);
      })
      .catch((error: unknown) => {
        patch(id, classify(error));
      });
  }, POLL_MS);

  timers.set(id, timer);
}

/**
 * Warn before a tab close that would abort transfers (`docs/09 §8`).
 *
 * Registered once at module scope rather than from a component, for the same
 * reason the queue is: the warning has to hold on every route, including ones
 * that never render the tray. Modern browsers ignore the string and show their
 * own, so nothing user-facing is composed here and the i18n rule is untouched.
 */
if (typeof window !== 'undefined') {
  window.addEventListener('beforeunload', (event) => {
    const busy = useUploadStore.getState().rows.some((row) => isActive(row.phase));
    if (!busy) return;
    event.preventDefault();
    /* Legacy browsers require a truthy `returnValue` to raise the prompt. */
    event.returnValue = '';
  });
}

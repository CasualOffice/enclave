import { useEffect, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useT } from '../../../shared/i18n/index.tsx';
import { requestBlob } from '../../../shared/api/client.ts';
import { failureOf } from '../../../shared/api/failure.ts';
import { FailureState, UnbuiltState } from '../../../shared/ui/surface-states.tsx';
import { Skeleton } from '../../../shared/ui/primitives.tsx';
import type { CurrentVersion, FileCapabilities } from '../../../entities/file/api-model.ts';
import './preview-tab.css';

/* The Preview tab — `docs/09 §7`'s peek-before-open, reading real bytes.
 *
 * `GET /files/{id}/preview` answers PNG bytes and this renders them. That is
 * the easy half. The hard half is the four *other* things it answers, because
 * telling them apart is the difference between an honest surface and one that
 * says "not found" about a file the user is looking at in the list behind it.
 *
 * ## The 404 that does not mean "missing"
 *
 * `CLAUDE.md` rule 9: nothing is `AVAILABLE` before antivirus completes, and no
 * read path serves `SCANNING` content. The delivery routes enforce that by
 * answering **404** — never 403, because a 403 would confirm the object exists
 * (rule 7). So a file sitting in the list, whose row the user just clicked,
 * answers 404 here whenever its version is not yet readable.
 *
 * Rendering that as *not found* would be false and alarming. Rendering it as an
 * error with a retry button would be worse: the retry cannot succeed until a
 * scanner runs, which may be never on a deployment with no engine configured.
 *
 * The fix is not to interpret the 404 at all. `isReadable` is the server's own
 * answer to *may these bytes be served* — the same predicate the delivery
 * routes filter on, so it cannot drift from them — and this component **asks
 * that first**, only requesting an image when the answer is yes. The 404 branch
 * then only has to cover the genuinely unexpected, and the common case gets the
 * sentence it deserves.
 *
 * ## Where `isReadable` comes from, and where it used to come from
 *
 * `detail.currentVersion`, which the panel already holds.
 *
 * It used to come from a second request. When this was written, `GET
 * /files/{id}` reported `currentVersion.status: "AVAILABLE"` with nothing beside
 * it to contradict that — byte-identical for a file that previews and one every
 * delivery route answers 404 for — so `GET /files/{id}/versions` was the only
 * endpoint publishing the field and had to be fetched on every peek to reach
 * it. `ENC-825` closed that on the server and `ENC-848` is this half: the
 * workaround is deleted, not merely explained, and the panel makes one request
 * per peek instead of two.
 *
 * Verified against the running binary before the fix, and the case is still the
 * one that matters: a freshly uploaded PNG on a stack with
 * `antivirus.provider: none` settles at `status: AVAILABLE`, `avStatus:
 * SKIPPED`, `isReadable: false` and answers 404 on both delivery routes. A
 * client that branched on `status` would show a spinner, then "not found", on a
 * file it had just successfully uploaded.
 *
 * ## The 503 that is a deployment fact
 *
 * Renditions are generated in process for `image/png`, `image/jpeg` and
 * `image/webp`; every other media type is refused with
 * `503 DEPENDENCY_UNAVAILABLE` because PDFium and the OCR weights are not
 * mounted. That is a **retryable failure** in the taxonomy and it is drawn as
 * one — but the sentence beside it says the media type has no renderer here,
 * rather than implying the file is broken.
 */

/** The media types this deployment can actually render. Read from the start-up banner. */
const RENDERABLE = new Set(['image/png', 'image/jpeg', 'image/webp']);

function usePreviewImage(fileId: string | undefined, enabled: boolean) {
  return useQuery({
    queryKey: ['file', fileId, 'preview'],
    queryFn: () => requestBlob(`/files/${encodeURIComponent(fileId ?? '')}/preview`),
    enabled: enabled && fileId !== undefined && fileId.length > 0,
    /* Bytes behind a capability. Never served stale (`docs/17 §4.1`) — a
     * revoked preview permission must not keep painting from a cache. */
    staleTime: 0,
    retry: false,
  });
}

/**
 * An object URL that is revoked when it stops being used.
 *
 * Without the cleanup every peek leaks a blob for the lifetime of the tab, and
 * walking a hundred rows with `J`/`K` leaks a hundred images.
 */
function useObjectUrl(blob: Blob | undefined): string | undefined {
  const [url, setUrl] = useState<string>();
  useEffect(() => {
    if (blob === undefined) {
      setUrl(undefined);
      return;
    }
    const next = URL.createObjectURL(blob);
    setUrl(next);
    return () => URL.revokeObjectURL(next);
  }, [blob]);
  return url;
}

export function PreviewTab({
  fileId,
  name,
  mimeType,
  capabilities,
  currentVersion,
}: {
  fileId: string | undefined;
  name: string;
  mimeType: string;
  capabilities: FileCapabilities;
  /** From `GET /files/{id}`. Absent only when the file has no committed version. */
  currentVersion: CurrentVersion | undefined;
}) {
  const t = useT();

  /* `isReadable` is read, never recomputed from the `status` and `avStatus`
   * beside it — the same rule as `capabilities`, and the same reason: the
   * server owns the predicate and a client that re-derives it is a second
   * authority that will eventually disagree. */
  const current = currentVersion;
  const readable = current?.isReadable === true;
  const renderable = RENDERABLE.has(mimeType);

  const image = usePreviewImage(fileId, capabilities.preview && readable && renderable);
  const url = useObjectUrl(image.data);

  /* Denied. The server refused *this user*, and the reason is the server's.
   * No retry, and nothing composed here (`docs/17 §7`, `ENC-674`). */
  if (!capabilities.preview) {
    return (
      <div className="peek-preview" data-state="denied">
        {/* `capabilities` carries no per-action reason yet (`ENC-674`), so there
         * is no sentence to show — and inventing one would be worse than none,
         * because a client-composed explanation of a policy decision *is* the
         * client re-deriving that decision. The control is shown, marked
         * refused, and left unexplained until the API can explain it. */}
        <p className="peek-preview-note">{t('library.peek.preview.denied')}</p>
      </div>
    );
  }

  /* No separate pending branch: the panel does not render this tab until
   * `detail` has arrived, so `currentVersion` is as settled as the title above
   * it. The loading state that used to sit here was waiting on the second
   * request that no longer exists. */
  if (current === undefined) {
    return (
      <div className="peek-preview" data-state="empty">
        <p className="peek-preview-note">{t('library.peek.preview.noVersion')}</p>
      </div>
    );
  }

  /* Published, but not servable. The honest sentence, and the reason this
   * component asks `versions` before asking for bytes. */
  if (!readable) {
    return (
      <div className="peek-preview" data-state="not-ready">
        <p className="peek-preview-note">
          {/* **Status before av-status**, and the order is the whole point.
           *
           * A quarantined version on this stack also carries `avStatus:
           * SKIPPED`, because the engine that refused it never inspected it.
           * Testing `SKIPPED` first therefore told a user their quarantined
           * file was merely "not scanned yet" — the softer of the two
           * sentences, on the more serious of the two conditions. Caught by
           * driving the real rows rather than by reading the code. */}
          {t(
            current.status === 'QUARANTINED'
              ? 'library.peek.preview.quarantined'
              : current.avStatus === 'SKIPPED'
                ? 'library.peek.preview.unscanned'
                : 'library.peek.preview.scanning',
          )}
        </p>
      </div>
    );
  }

  /* Readable, but this deployment has no renderer for the type. Unbuilt rather
   * than denied or failed: the policy chain refused nobody and nothing broke —
   * the product does not have the capability here yet. */
  if (!renderable) {
    return (
      <div className="peek-preview" data-state="unbuilt">
        <UnbuiltState
          heading="library.peek.preview.noRenderer"
          note="library.peek.preview.noRenderer.note"
        />
      </div>
    );
  }

  if (image.isPending) {
    return (
      <div className="peek-preview" role="status" aria-busy="true">
        <Skeleton width="100%" />
      </div>
    );
  }

  if (image.isError) {
    return (
      <div className="peek-preview" data-state="error">
        <FailureState failure={failureOf(image.error)} onRetry={() => void image.refetch()} />
      </div>
    );
  }

  return (
    <div className="peek-preview" data-state="ready">
      {url !== undefined && (
        /* The file's own name is the alt text. It is data, not a message, so it
         * never enters the catalog (`docs/14 §6`) — and a generic "preview" alt
         * would tell a screen-reader user strictly less than the filename they
         * already heard in the list. */
        <img className="peek-preview-image" src={url} alt={name} />
      )}
    </div>
  );
}

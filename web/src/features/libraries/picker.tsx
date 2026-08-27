import { useT } from '../../shared/i18n/index.tsx';
import { Skeleton } from '../../shared/ui/primitives.tsx';
import { Icon } from '../../shared/ui/icon-sprite.tsx';
import { EmptyState, FailureState } from '../../shared/ui/surface-states.tsx';
import { failureOf } from '../../shared/api/failure.ts';
import { useLibraries, useWorkspaces } from './picker-api.ts';
import './picker.css';

/* The library picker — the surface that could not exist until `PR #71`.
 *
 * Before it there was no route that enumerated workspaces or libraries, so the
 * screen took an id from the URL and drew the unbuilt treatment when it was
 * absent. That was the honest state of the world then and it is not now:
 * `GET /workspaces` and `GET /workspaces/{id}/libraries` both answer, both
 * carry per-row `capabilities` from the real ACL resolver, and the unbuilt
 * treatment must be withdrawn the moment the thing is built — a `Later` chip on
 * a surface that exists is the same erosion as a denial on one that does not.
 *
 * All four states (`docs/09 §11`) are here. None of them is drawn in the
 * prototype, which shows only the populated case of every screen; that is a gap
 * in the reference rather than permission to ship one state.
 */

/**
 * A workspace and its libraries.
 *
 * Nested queries rather than one flat list, because that is the shape the API
 * has. There is no "every library I can see" endpoint, and faking one by firing
 * a request per workspace would turn a navigation into N+1 calls whose partial
 * failure could not be reported coherently — half a picker with no way to say
 * which half is missing.
 */
function WorkspaceGroup({
  workspaceId,
  name,
  onPick,
}: {
  workspaceId: string;
  name: string;
  onPick: (libraryId: string) => void;
}) {
  const t = useT();
  const libraries = useLibraries(workspaceId);

  return (
    <li className="lib-picker-ws">
      <h3 className="lib-picker-ws-name">
        <bdi dir="auto">{name}</bdi>
      </h3>

      {libraries.isPending && (
        <ul className="lib-picker-libs" aria-busy="true">
          {/* Skeletons share the loaded row's box model, so nothing shifts when
           * the data lands (`docs/09 §11`). */}
          {[0, 1].map((index) => (
            <li key={index} className="lib-picker-lib" aria-hidden="true">
              <Skeleton width="60%" />
            </li>
          ))}
        </ul>
      )}

      {libraries.isError && (
        <FailureState
          failure={failureOf(libraries.error)}
          onRetry={() => void libraries.refetch()}
        />
      )}

      {libraries.data !== undefined && libraries.data.items.length === 0 && (
        <p className="lib-picker-none">{t('library.picker.noLibraries')}</p>
      )}

      {libraries.data !== undefined && libraries.data.items.length > 0 && (
        <ul className="lib-picker-libs">
          {libraries.data.items.map((library) => (
            <li key={library.id}>
              {/* Rendered from the server's `capabilities.read`.
               *
               * A library the viewer may not read is not expected in this
               * listing — the resolver filters it — but the row renders from
               * the capability rather than from its presence, because "it was
               * in the list" is an inference and `capabilities` is an answer
               * (`docs/17 §1`). */}
              <button
                type="button"
                className="lib-picker-lib"
                aria-disabled={library.capabilities.read ? undefined : true}
                onClick={library.capabilities.read ? () => onPick(library.id) : undefined}
              >
                <Icon name="folder" size={14} />
                <bdi className="lib-picker-lib-name" dir="auto">
                  {library.name}
                </bdi>
                {/* External sharing is a fact about the container worth seeing
                 * before opening it. It comes from `settings`, which the server
                 * sent; nothing here derives it. */}
                {library.settings.externalSharing !== 'DISABLED' && (
                  <span className="lib-picker-lib-tag">{t('library.picker.external')}</span>
                )}
              </button>
            </li>
          ))}
        </ul>
      )}
    </li>
  );
}

export function LibraryPicker({ onPick }: { onPick: (libraryId: string) => void }) {
  const t = useT();
  const workspaces = useWorkspaces();

  if (workspaces.isPending) {
    return (
      <div className="lib-picker" role="status" aria-busy="true">
        <p className="lib-picker-title">{t('library.picker.title')}</p>
        <ul className="lib-picker-list">
          {[0, 1, 2].map((index) => (
            <li key={index} className="lib-picker-ws" aria-hidden="true">
              <Skeleton width="40%" />
            </li>
          ))}
        </ul>
      </div>
    );
  }

  if (workspaces.isError) {
    return (
      <div className="lib-picker">
        <FailureState
          failure={failureOf(workspaces.error)}
          onRetry={() => void workspaces.refetch()}
        />
      </div>
    );
  }

  /* Empty (new). A viewer with no workspace is not an error and not a denial —
   * `GET /workspaces` answered, and the answer was none. The sentence says what
   * the surface is for; it offers no "create workspace" action because no
   * endpoint creates one from here. */
  if (workspaces.data.items.length === 0) {
    return (
      <div className="lib-picker" data-state="empty">
        <EmptyState heading="library.picker.empty.title" body="library.picker.empty.body" />
      </div>
    );
  }

  return (
    <div className="lib-picker">
      <p className="lib-picker-title">{t('library.picker.title')}</p>
      <ul className="lib-picker-list">
        {workspaces.data.items.map((workspace) => (
          <WorkspaceGroup
            key={workspace.id}
            workspaceId={workspace.id}
            name={workspace.name}
            onPick={onPick}
          />
        ))}
      </ul>
    </div>
  );
}

import { useCallback, useRef, useState, type DragEvent } from 'react';
import { useUploadStore } from './store.ts';

/* Getting files into the queue, from the two places a user offers them.
 *
 * Lives in `entities/` with the rest of the upload domain because the library
 * screen is the surface that hosts the drop target and `features/libraries` may
 * not import `features/upload` (`docs/17 §2`).
 *
 * ## The drag counter, and why a boolean is not enough
 *
 * `dragenter` and `dragleave` fire for **every element the pointer crosses**,
 * including children of the drop target. A naive `onDragEnter → true` /
 * `onDragLeave → false` flickers the overlay off every time the cursor moves
 * from the list onto a row inside it, which is most of the time the user is
 * dragging. Counting enters against leaves is the standard fix and the reason
 * this is a hook rather than two lines in a component.
 */

export interface UploadTarget {
  /** Whether a drag carrying files is currently over the target. */
  readonly isDragging: boolean;
  /** Open the platform file picker. */
  readonly pickFiles: () => void;
  /** Spread onto the element that accepts drops. */
  readonly dropHandlers: {
    readonly onDragEnter: (event: DragEvent) => void;
    readonly onDragLeave: (event: DragEvent) => void;
    readonly onDragOver: (event: DragEvent) => void;
    readonly onDrop: (event: DragEvent) => void;
  };
  /** Render this. It is the hidden `<input type="file">` `pickFiles` clicks. */
  readonly inputRef: React.RefObject<HTMLInputElement | null>;
  readonly onInputChange: (event: React.ChangeEvent<HTMLInputElement>) => void;
}

/**
 * Wire a surface up as an upload target for one container.
 *
 * `enabled` is the **server's** answer, passed in by the caller from the
 * library's `capabilities.create`. It is not computed here and there is nothing
 * in this file that could compute it — when it is `false` the hook accepts
 * nothing, so a drop on a container the user may not write to never starts a
 * transfer that `POST /uploads` would refuse anyway. That is a courtesy, not an
 * enforcement: the server decides, and it still will.
 */
export function useUploadTarget(
  libraryId: string | undefined,
  parentId: string | undefined,
  enabled: boolean,
): UploadTarget {
  const enqueue = useUploadStore((state) => state.enqueue);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const depth = useRef(0);
  const [isDragging, setDragging] = useState(false);

  const accept = useCallback(
    (files: FileList | null) => {
      if (!enabled || libraryId === undefined || files === null || files.length === 0) return;
      enqueue(Array.from(files), libraryId, parentId);
    },
    [enabled, libraryId, parentId, enqueue],
  );

  const pickFiles = useCallback(() => {
    inputRef.current?.click();
  }, []);

  const onInputChange = useCallback(
    (event: React.ChangeEvent<HTMLInputElement>) => {
      accept(event.target.files);
      /* Reset, so choosing the same file twice in a row fires `change` again.
       * Without this the second attempt is silently ignored. */
      event.target.value = '';
    },
    [accept],
  );

  const carriesFiles = (event: DragEvent): boolean =>
    Array.from(event.dataTransfer.types).includes('Files');

  const dropHandlers = {
    onDragEnter: (event: DragEvent) => {
      if (!enabled || !carriesFiles(event)) return;
      event.preventDefault();
      depth.current += 1;
      setDragging(true);
    },
    onDragLeave: (event: DragEvent) => {
      if (!enabled) return;
      event.preventDefault();
      depth.current -= 1;
      if (depth.current <= 0) {
        depth.current = 0;
        setDragging(false);
      }
    },
    /* `preventDefault` on `dragover` is what makes an element a drop target at
     * all. Without it the browser navigates to the dropped file, which loses
     * the whole application. */
    onDragOver: (event: DragEvent) => {
      if (!enabled || !carriesFiles(event)) return;
      event.preventDefault();
      event.dataTransfer.dropEffect = 'copy';
    },
    onDrop: (event: DragEvent) => {
      if (!enabled) return;
      event.preventDefault();
      depth.current = 0;
      setDragging(false);
      accept(event.dataTransfer.files);
    },
  };

  return { isDragging, pickFiles, dropHandlers, inputRef, onInputChange };
}

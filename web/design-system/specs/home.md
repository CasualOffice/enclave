# home — implementation spec

> Extracted from `enclave-client-prototype.html` by the spec workflow.
> The prototype stays the reference; this is a reading of it, not a replacement.

## Structure

ROUTE /w/:workspaceId -> features/home/HomeScreen.tsx. Sits in the shell sheet panel; shell root = display:grid; grid-template-columns:232px 1fr; height:100%. Sheet panel = margin-block:8px; margin-inline:0 8px; background:var(--sheet); border-radius:var(--r-sheet); box-shadow:var(--el1); flex column; min-width:0; overflow:hidden. Home has NO topbar.
APP BASE (shell root, inherited, never restated): font-family:var(--sans); font-size:13px; line-height:1.45; letter-spacing:-.006em; color:var(--fg); background:var(--canvas).

L0 <main id=home-main tabIndex=-1 aria-labelledby=home-greeting> flex:1; overflow-y:auto; overflow-x:hidden; padding-block:28px 40px; padding-inline:32px
L1 <div.home-column> max-inline-size:860px; margin-inline:auto; flex column; gap:28px

=A= GREETING <header> animation:encIn .25s both
 h2#home-greeting: margin:0; font-family:var(--tight); font-size:24px; weight:600; letter-spacing:-.022em; line-height:1.2 (28.8px box). Text = t('home.greeting.{morning|afternoon|evening|night}',{name}) as ONE ICU message. Bucket from the hour in me.timeZone via Intl.DateTimeFormat(locale,{hour:'numeric',hour12:false,timeZone}).formatToParts. 05-11 morning, 12-16 afternoon, 17-21 evening, else night.
 p: margin:0; margin-block-start:4px; color:var(--fg3); font-size:12.5px (18.1px box). Text = t('home.subtitle',{date,workspace,count}); the message body owns the ' · ' separators so a translator can reorder them. date = Intl.DateTimeFormat(locale,{weekday:'long',month:'long',day:'numeric',timeZone}).format(now). count = tasks.total from the API. While the tasks query is loading or errored, render t('home.subtitle.noCount') (date + workspace only) — never a guessed count.

=B= NEEDS YOUR ATTENTION <section aria-labelledby=home-attn-h> animation:encIn .25s .05s both
 h3#home-attn-h.section-label: margin:0; margin-block-end:10px; font-size:11px; weight:500; color:var(--fg3); text-transform:uppercase; letter-spacing:.06em; line-height:1.45 (16px box).
 <ul> list-style:none; margin:0; padding:0; flex column; gap:8px. Each <li> is one card.
 CARD: flex; align-items:center; gap:10px; padding-block:12px; padding-inline:14px; border-radius:var(--r-surf); box-shadow:var(--hairline); background:var(--sheet). Computed block-size 60px (12 + 36.25 text stack + 12; the text stack is taller than the 26px avatar and the 28px buttons). Pin min-block-size:60px so skeletons cannot shift it.
  1 AVATAR <span aria-hidden>: inline-size/block-size 26px; border-radius:50%; inline-flex; centered; font-size:11px; weight:600; flex:none; background:var(--av-{a|b|c|d}-bg); color:var(--av-{a|b|c|d}-fg). Quartet index = stable hash(task.actor.id) % 4 in entities/user/avatar.ts. Initials via Intl.Segmenter(locale,{granularity:'grapheme'}), max 2 graphemes — never name.split(' ').
  2 TEXT <div> flex:1; min-inline-size:0.
     title <span display:block> weight:500; font-size:13px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis (18.85px). Server-supplied subject; wrap in <bdi>.
     sub <span display:block> color:var(--fg3); font-size:12px (17.4px) = t('home.attn.sub.{taskType}',{actor,relative}), relative from Intl.RelativeTimeFormat.
  3 PRIMARY BUTTON <button type=button>: inline-flex; align-items:center; block-size:28px; padding-inline:10px; border-radius:var(--r-ctrl); border:0; font:inherit; font-size:12.5px; weight:500; background:var(--accent); color:#fff; flex:none; hover filter:brightness(1.08). Label = t('home.attn.cta.{task.ctaKey}') — the server sends ctaKey, never a rendered string.
  4 DISMISS <button type=button>: same box; background:transparent; color:var(--fg2); hover background:var(--hover), color:var(--fg). Visible label t('common.dismiss'); aria-label = t('home.attn.dismiss.aria',{title}).
  Both buttons render from task.capabilities. capabilities.x === false -> the denied treatment carrying the SERVER's reason.

=C= CONTINUE WORKING <section aria-labelledby=home-recent-h> animation:encIn .25s .1s both
 h3#home-recent-h.section-label: as above, margin-block-end:6px.
 <ul> border-radius:var(--r-surf); box-shadow:var(--hairline); overflow:hidden; list-style:none; margin:0; padding:0. Not virtualized — the API hard-caps at 8 rows.
 ROW = <li><a> (router Link to /w/:wid/l/:libraryId/f/:folderId?peek=:fileId): flex; align-items:center; gap:10px; padding-block:10px; padding-inline:14px; text-decoration:none; color:inherit; background:var(--sheet); box-shadow:inset 0 -1px 0 var(--line); hover background:var(--hover). Computed block-size 40px (10 + 20px chip + 10); set min-block-size:40px. The last row keeps its inset divider exactly as the prototype does — the parent's overflow:hidden clips it.
  1 <svg inline-size/block-size:16px; flex:none; color:var(--icon-color)> with <use href="#file"> from the inlined sprite, aria-hidden. --icon-color set from a mime->token map in entities/file/icon.ts.
  2 NAME <span> font-weight:450; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; min-inline-size:0; filename in <bdi>. Inner extension <span> color:var(--fg4); font-size:12px.
  3 CLASSIFICATION <span class="cls cls--{key}"> inline-flex; align-items:center; gap:6px; block-size:20px; padding-block:0; padding-inline:7px 8px; border-radius:999px; font-size:11px; weight:500; letter-spacing:0; white-space:nowrap; flex:none; background:color-mix(in srgb,var(--cc) 11%,transparent); color:color-mix(in srgb,var(--cc) 82%,var(--fg)). ::before content:""; inline-size/block-size:6px; border-radius:50%; background:var(--cc); flex:none. --cc bound by class: pub->--c-pub, int->--c-int, conf->--c-conf, hconf->--c-hconf, restr->--c-restr. Text label t('classification.{key}') is always present (docs 09 §15: colour is never the only carrier).
  4 TIME <time dateTime={iso}> margin-inline-start:auto; color:var(--fg4); font-size:11.5px; font-family:var(--mono); flex:none. Text from shared/i18n/formatRelative.ts: Intl.RelativeTimeFormat(locale,{numeric:'auto',style:'narrow'}) under 7 days, else Intl.DateTimeFormat(locale,{month:'short',day:'numeric'}). One shared 60s tick for the whole page, paused when document.hidden.

=D= RECENT ASKS <section aria-labelledby=home-asks-h> animation:encIn .25s .15s both
 h3#home-asks-h.section-label: margin-block-end:6px.
 <div> flex; gap:8px; flex-wrap:wrap.
 CHIP <button type=button>: inline-flex; align-items:center; gap:6px; block-size:28px; padding-inline:12px; border-radius:999px; border:0; font:inherit; font-size:12.5px; background:var(--sheet); color:var(--fg2); box-shadow:var(--hairline); hover background:var(--sunken), color:var(--fg). Icon <svg inline-size/block-size:12px; color:var(--accent)><use href="#spark">, aria-hidden.
 Ask is M7. Until the M7 flag in /bootstrap is on, this section renders the UNBUILT treatment — not an empty list, and never the denial treatment.

MOTION: @keyframes encIn{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}. Stagger 0/.05/.1/.15s, animation-fill-mode:both. Global @media (prefers-reduced-motion:reduce){*{transition:none!important;animation-duration:.01s!important}} — keep fill:both so nothing is left invisible.
FOCUS: global :focus-visible{outline:2px solid var(--accent-ring); outline-offset:1px; border-radius:6px}.
RESPONSIVE (docs 09 §16): below 900px the rail collapses to a drawer and .home-column padding-inline drops to 16px; the attention card wraps its buttons to a second line (flex-wrap:wrap; text block flex-basis:100%) giving an 88px card — update min-block-size in the same media query so the skeletons still match.

## Interactions

Every interactive element, in DOM order.

1 ATTENTION PRIMARY (Approve / Review / Sign). Click -> POST /workflows/steps/{id}/approve with an Idempotency-Key. Optimistic: NO — docs 17 Q25, it touches access. Renders BUSY in place until the response. Success -> invalidate ['workflows','tasks'] and ['me','recent']; polite announce t('home.attn.approved',{title}). 403 with a code -> the denial treatment inline in the card, no retry affordance. 5xx/network -> the failure treatment inside the card, with retry + copyable request ID. Rendered from task.capabilities.approve; false -> disabled with the server's reason. Keyboard: native button Enter/Space.

2 ATTENTION DISMISS. Click -> POST /workflows/tasks/{id}/dismiss (endpoint does not exist yet — see backendNeeded; until it ships the control renders UNBUILT, not hidden and not denied). Optimistic: YES — the <li> animates out over 120ms and a 10s undo toast appears (docs 09 §14). Rollback restores the row in place and explains itself there.

3 RECENT ROW. Anchor. Click / Enter -> navigate to the containing folder with ?peek={fileId} (docs 09 §7: peek is the preview surface, and a query param not a route, so the list behind survives). Space -> the same navigation with preventDefault so the page does not scroll. Cmd/Ctrl-click and middle-click open a new tab, which works only because it is a real anchor. Hover and keyboard focus both prefetch GET /files/{id} (docs 09 §2, prefetch on hover and on route intent).

4 RECENT LIST ROVING FOCUS. The <ul> is a single tab stop: the row at the last-focused index has tabIndex=0, all others tabIndex=-1. ArrowDown/ArrowUp move focus within the list and do NOT wrap (wrapping steals Tab's job). Home/End jump to first/last. No typeahead on this screen. Tab leaves the list for the Recent asks section.

5 ASK CHIP. Click -> navigate to /w/:wid/ask?q={encoded}. While unbuilt: aria-disabled=true, tabIndex=-1, and no onClick handler is attached at all.

6 GLOBAL KEYS, bound in app/shell rather than in this feature, active while home is the route: Cmd/Ctrl+K command palette; '/' focuses the rail search input (preventDefault, ignored when the event target is an input, textarea or contenteditable); '?' opens the shortcut reference; Cmd/Ctrl+J is REGISTERED AND DISABLED until M7 — pressing it announces the unbuilt message through the live region rather than failing silently (docs 09 §6, D33); Esc closes any open popover or toast and otherwise no-ops, since home has no selection to clear.

7 SCROLL AND FOCUS RESTORATION. #home-main's scrollTop is stored per route key in Zustand (local UI state, session only, deliberately not persisted). On back-navigation restore it in useLayoutEffect before paint, then move focus to #home-main — never leave focus on <body>.

8 LIVE REGION. One <div role=status aria-live=polite aria-atomic=true> in the shell, hidden with clip-path (never a physical offset). Home writes to it for: approval success, dismissal plus undo availability, section error, and the Cmd+J unbuilt message.

9 CAPABILITY RULE. No control on this screen computes its own enabled state. shared/ui/ActionButton takes {capability?: {allowed:boolean; reasonCode?:string; reasonText?:string; remediation?:string}} and renders allowed / denied / unbuilt / busy from that alone. A component that reads task.status or user.role to decide is exactly the defect docs 17 exists to prevent (test F1). Denied text is the server's `reasonText` and `remediation` verbatim; the client composes none of it and never names the rule that matched.

## States

Home has THREE independent data surfaces (attention, recents, asks). Each owns its own four states inside its own <section>. There is never a page-level spinner, and one section's failure never blanks another. The greeting block depends only on /me, which the shell resolves before home mounts.

ATTENTION — GET /workflows/tasks
 LOADING: 2 skeleton <li> (the prototype's placeholder count) with the identical card box — padding-block:12px; padding-inline:14px; border-radius:var(--r-surf); box-shadow:var(--hairline); min-block-size:60px. Inside: a 26px circle, two bars (block-size:10px; border-radius:4px; inline-size 62% then 40%) and two 28px button blocks at 72px and 64px. Shimmer = background:linear-gradient(90deg,var(--sunken) 25%,var(--g150) 50%,var(--sunken) 75%); background-size:200% 100%; animation:encSh 1.4s infinite. aria-busy on the <ul>, aria-hidden on the skeletons.
 EMPTY (NEW — never had a task): one card-shaped panel, same box, block-size:auto, padding-block:20px, text-align:center. Line 1 font-size:13px; color:var(--fg) = t('home.attn.empty.title'). Line 2 margin-block-start:4px; font-size:12px; color:var(--fg3) = t('home.attn.empty.body'), saying what the surface is for. One secondary action (block-size:28px; padding-inline:10px; border-radius:var(--r-ctrl); background:var(--sheet); box-shadow:var(--hairline); hover background:var(--sunken)) = t('home.attn.empty.action') -> Files.
 EMPTY (FILTERED — everything dismissed this session): same panel, t('home.attn.dismissedAll') plus a clear action t('home.attn.showDismissed') restoring the dismissed set. The two empties must not share copy: a user who cleared their own list has to be able to tell that from never having had one.
 ERROR (5xx, network, or Zod parse failure): the section keeps its h3 and renders one panel in the same box, with box-shadow:var(--hairline) and colour var(--danger) on the title only — never a --c-* classification token. Content: t('error.title'), t('error.body.{retryable|permanent}'), a secondary Retry button that refetches only this query, and the request ID in font-family:var(--mono); font-size:11.5px; color:var(--fg4) with a copy button (aria-label from the catalog, success announced politely). The request ID comes from shared/api's response capture.
 DENIAL (403 on the list itself): NOT the error state. Same panel, NO retry, showing the server's code, message and remediation verbatim (docs 06 §24).

RECENTS — GET /me/recent
 LOADING: 3 skeleton rows (the prototype's placeholder count) inside the same bordered container, each min-block-size:40px; padding-block:10px; padding-inline:14px; gap:10px, carrying a 16px square, a 10px bar at 45% inline-size, a 20px x 84px pill and a 10px x 40px bar with margin-inline-start:auto. Same shimmer. Because the radius and hairline live on the <ul> and not on the rows, the reserved and loaded boxes are identical — zero CLS (docs 09 §11).
 EMPTY (NEW): the bordered container is still drawn; inside, padding-block:32px; text-align:center; color:var(--fg3); font-size:13px = t('home.recent.empty.title') + t('home.recent.empty.body'), plus one action t('home.recent.empty.action') -> Files.
 EMPTY (FILTERED): home has no user filter over recents, but the list IS policy-filtered. If the server returns items:[] with filteredCount > 0, render t('home.recent.empty.filtered') with no action. Never say "you have no recent files" when the truth is "some were withheld".
 ERROR: the same error panel shape, inside the bordered container.

RECENT ASKS — M7
 UNBUILT (its state today): the heading renders normally; the body is a single neutral chip — block-size:28px; padding-inline:12px; border-radius:999px; background:var(--sunken); color:var(--fg3); no hairline; aria-disabled=true; tabIndex=-1 — carrying t('common.later') and aria-describedby pointing at a visually hidden <p> holding t('home.asks.unbuilt'): future tense, about the product, no remedy, and NOT the denial colour (docs 17 §6, test F2).
 LOADING / EMPTY(NEW) / EMPTY(FILTERED) / ERROR are specified now so M7 does not reopen the design. LOADING = 3 chip-shaped shimmer blocks, block-size:28px, inline-size 140/112/168px, border-radius:999px. EMPTY(NEW) = one line, color:var(--fg3); font-size:12.5px = t('home.asks.empty'), no action (Ask is reachable from the rail). EMPTY(FILTERED) = t('home.asks.empty.cleared') plus an undo-clear action. ERROR = the same error panel, retryable, with request ID.

THE THREE NON-ACTIONABLE TREATMENTS MUST NOT SHARE A CLASS (docs 17 §6, test F2):
 .is-denied  — focusable (tabIndex 0), aria-disabled=true, aria-describedby -> the server's reason node, var(--danger) on the marker, present tense about the user, exactly one remedy.
 .is-unbuilt — NOT focusable (tabIndex -1), aria-disabled=true, aria-describedby -> the release note, var(--fg3) on var(--sunken), future tense about the product, no remedy. May never use var(--danger) or any --c-* token.
 .is-busy    — focusable, aria-busy=true, the label replaced in place by a 12px spinner (@keyframes encSpin), the button keeping its exact block-size:28px and its measured inline-size so the card does not reflow.
 A test asserts the three class-name sets are disjoint and that .is-unbuilt never carries tabIndex=0.

## Tokens

- `--sheet (card, row and chip background)`
- `--canvas (shell background behind the sheet)`
- `--sunken (chip hover, unbuilt chip background, skeleton base)`
- `--hover (row and secondary-button hover wash)`
- `--line (row divider via inset 0 -1px 0)`
- `--hairline = 0 0 0 1px var(--line) (every card, the recents container, secondary buttons)`
- `--el1 (the sheet panel itself)`
- `--fg (name text; the resolved chip foreground mix)`
- `--fg2 (Dismiss label, ask-chip label)`
- `--fg3 (section labels, subtitle, secondary lines, unbuilt text)`
- `--fg4 (file extension, timestamp, request ID)`
- `--accent (primary button fill, spark icon)`
- `--accent-ring (focus outline)`
- `--danger (error title, denial marker — never on unbuilt)`
- `--r-ctrl 6px (buttons)`
- `--r-surf 10px (attention cards, recents container)`
- `--r-sheet 14px (the shell panel)`
- `--c-pub / --c-int / --c-conf / --c-hconf / --c-restr (LOCKED, bound through --cc; never tenant-overridable)`
- `--av-a-bg/-fg through --av-d-bg/-fg (actor avatar quartet)`
- `--sans (body), --tight (the 24px greeting only), --mono (timestamp, request ID)`
- `--g150 (skeleton shimmer highlight stop)`

## Technique fixes — the prototype breaks a hard rule here

- margin-left:auto on the recents timestamp -> margin-inline-start:auto. Identical in LTR, correct in RTL.
- Classification chip padding:0 8px 0 7px -> padding-block:0; padding-inline:7px 8px. The 7/8 asymmetry exists to optically centre the leading dot, so it must follow the reading direction.
- width/height on avatars, icons, chips and dots -> inline-size/block-size. Same rendered box.
- Inline hex interpolation {{a.avBg}}/{{a.avFg}} -> a class or data-attribute selecting the --av-a..--av-d quartet, index = stable hash of actor.id. The server never sends a colour; a colour in the payload is a token the tenant cannot theme and nobody can test.
- Inline hex {{r.clsBg}}/{{r.clsFg}}/{{r.clsDot}} -> class .cls--{key} setting --cc from the LOCKED classification tokens, with background:color-mix(in srgb,var(--cc) 11%,transparent), color:color-mix(in srgb,var(--cc) 82%,var(--fg)) and the dot as ::before. This is the v2 reference's own .cls rule (design-system-v2.html line 146): pixel-identical output, palette un-overridable.
- {{r.ic}} icon colour arriving as data -> a mime->token map in entities/file/icon.ts.
- <div onClick={{r.open}}> for a recents row -> <li><a> router Link. Restores Enter, Cmd-click, middle-click, the context menu and the link role, none of which the div had. Appearance unchanged after text-decoration:none; color:inherit.
- h2 followed by h4 (skipped level) -> h2 then h3 carrying a .section-label class with the 11px / 500 / uppercase / .06em styling. Visually identical, heading outline valid.
- text-transform:uppercase on section labels -> keep the rule, but catalog strings stay sentence case and the rule is suppressed for locales flagged noUppercase (tr, el, and any locale whose catalog sets it), because CSS uppercasing mangles them.
- '{{greeting}}, Priya' assembled from two nodes -> a single ICU message t('home.greeting.<bucket>',{name}). Concatenated fragments cannot be reordered by a translator.
- 'Thursday, August 20' -> Intl.DateTimeFormat(locale,{weekday:'long',month:'long',day:'numeric',timeZone:me.timeZone}).
- '3 things need your attention' -> an ICU plural inside t('home.subtitle'), count from tasks.total.
- '2 h ago' in {{r.when}} -> <time dateTime={iso}> with Intl.RelativeTimeFormat(locale,{numeric:'auto',style:'narrow'}) under 7 days and Intl.DateTimeFormat({month:'short',day:'numeric'}) beyond it. The mono font already reserves the width.
- Approve and Dismiss rendered unconditionally -> rendered from task.capabilities through shared/ui/ActionButton. A denied action stays visible and disabled with the server's reason (docs 09 §5); it is never hidden, because a hidden action teaches the user nothing.
- title="..." on icon-bearing controls -> aria-label from the catalog. title is not reliably announced and is not translatable from the markup.
- The prototype shows no empty, filtered-empty, loading or error state on this screen at all. The reference is authoritative for token values only (docs 09 §11); all four are specified above, per section.
- The prototype hardcodes 'Priya' and 'Finance workspace' -> GET /api/v1/me.
- sc-for hint-placeholder-count is a prototype shim -> real <Skeleton> components whose box model is asserted equal to the loaded row's in a test (60px card, 40px row).
- Visually-hidden helper: clip-path:inset(50%) with inline-size:1px — never left:-9999px.
- No landmarks in the prototype -> <main>, one <section aria-labelledby> per block, and a single shell-level role=status live region.
- Fonts: the prototype's @font-face declarations already point at web/public/fonts with unicode-range and font-display:swap. Reuse them verbatim in web/src/styles; adding any @import or <link> to a font host is a residency violation (docs 08 §18, ENC-135).

## Backend required

- GET /api/v1/me — display name, locale, timeZone, current workspace id and name. Registered (05-API §21). timeZone must actually be present or the greeting bucket is wrong for anyone travelling.
- GET /api/v1/bootstrap — branding tokens, locale, and the M7 feature flag gating the Recent asks section and Cmd+J. Registered.
- GET /api/v1/workflows/tasks — registered (05-API §20) but its response shape is unspecified. Each task needs {id, type, subjectTitle, subjectFileId, actor:{id,displayName}, ctaKey, occurredAt (RFC3339), capabilities}. ctaKey not a rendered label; occurredAt not a formatted string.
- POST /api/v1/workflows/steps/{id}/approve — registered; needs Idempotency-Key support per 05-API.
- ENC-674 capability reasons — capabilities must become {allowed, reasonCode, reasonText, remediation} rather than nine bare booleans. Until it lands, a false capability can only render as a reasonless disabled control, because a client-invented explanation is forbidden (docs 09 §5). Hard dependency for the denied treatment.
- NEW: POST /api/v1/workflows/tasks/{id}/dismiss plus a DELETE counterpart for the 10s undo (docs 09 §14). Not in 05-API. Until registered, Dismiss renders unbuilt.
- NEW: GET /api/v1/me/recent?limit=8 — does not exist. Per row {fileId, name, extension, mimeType, classification:{key,label,rank}, lastAccessedAt (RFC3339), libraryId, parentFolderId, capabilities}, plus a top-level filteredCount so the policy-filtered empty state can be distinguished from the genuinely empty one. Must be registered in 05-API before build.
- NEW: GET /api/v1/me/recent-asks — M7-owned, does not exist. Section renders unbuilt until then.
- Crate: workflows — not present in the workspace today (crates/ holds audit, auth, config, core, db, events). Blocks the entire attention section.
- Read model for recents — must NOT be derived from audit_events, which is hash-chained and deliberately not a user-facing feed (CLAUDE.md rule 10, docs 17 Q24). Needs a purpose-built tenant-scoped table with tenant_id first, RLS enabled and forced, and composite FKs including tenant_id, defined in 04-DATA-MODEL.md.
- Policy: both new GETs return rows only after PolicyEngine::enforce. Barrier and cross-tenant exclusions drop the row and increment filteredCount rather than returning 403 (CLAUDE.md rule 7).
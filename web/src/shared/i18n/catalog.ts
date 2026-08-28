/* The message catalog.
 *
 * `CLAUDE.md` rule 12 and `docs/14 §8` between them say: no user-facing string
 * literal outside a catalog, every key namespaced and stable, and every key
 * carrying a translator description. The catalog is a single object rather than
 * a JSON file so that `MessageKey` below is a union type — a mistyped key is a
 * compile error rather than a `[missing key]` rendered at a customer.
 *
 * Locale negotiation, lazy per-locale bundles and the `en-XA`/`en-XB`
 * pseudo-locales are M5 step 5 and deliberately absent here: this file
 * establishes the pattern the first component is written against so nothing
 * has to be retrofitted, and stops short of the scaffolding that owns the rest.
 *
 * Keys are never derived from English text (`docs/14 §4`) — rewording
 * "Restricted" must not orphan five translations.
 */

export interface CatalogEntry {
  /** The `en-US` source string, in ICU MessageFormat. Never concatenated. */
  readonly message: string;
  /** Where it appears and what each placeholder means. Required, per `docs/14 §8` rule 5. */
  readonly description: string;
}

export const catalog = {
  'files.list.label': {
    message: 'Files',
    description: 'Accessible name of the file list grid. Announced by a screen reader on entry.',
  },
  'files.list.rowCount': {
    message:
      '{shown, plural, one {# item} other {# items}} of {total, plural, one {# item} other {# items}}',
    description:
      'Polite live-region summary of the virtualized list. "shown" counts rows inside expanded groups; "total" counts every row including collapsed ones.',
  },
  'files.column.name': {
    message: 'Name',
    description: 'File list column header: the file name.',
  },
  'files.column.modified': {
    message: 'Modified',
    description: 'File list column header: who last changed the file and when.',
  },
  'files.column.classification': {
    message: 'Classification',
    description:
      'File list column header: the sensitivity label (Public through Restricted). Not a status.',
  },
  'files.column.status': {
    message: 'Status',
    description:
      'File list column header: effect pills such as a retention period or a download restriction. Empty for most rows.',
  },
  'files.column.size': {
    message: 'Size',
    description: 'File list column header: the file size on disk.',
  },
  'files.group.expand': {
    message: 'Expand {group}',
    description:
      'Accessible name of the collapsed group header button. "group" is the group name, e.g. a folder or a customer.',
  },
  'files.group.collapse': {
    message: 'Collapse {group}',
    description: 'Accessible name of the expanded group header button. "group" is the group name.',
  },
  'files.group.count': {
    message: '{count, plural, one {# item} other {# items}}',
    description:
      'Item count shown beside a group name in the group header, expanded or collapsed. Also the collapsed group’s only clue to what it hides, so it is never omitted.',
  },
  'files.row.checkbox': {
    message: 'Select {name}',
    description: 'Accessible name of a file row’s selection checkbox. "name" is the file name.',
  },

  'app.checkingAccess': {
    message: 'Checking your access…',
    description:
      'Shown beside the animated mark while a route settles or a policy decision is in flight. Names what is happening rather than saying "loading": the policy chain is deciding.',
  },
  'app.brand': {
    message: 'Enclave',
    description:
      'The untenanted product name in the sidebar. Replaced by the tenant’s own name from the branding API (docs/09 §18), so this is a fallback rather than a fixed string.',
  },
  'nav.search': {
    message: 'Search',
    description: 'Sidebar navigation: the search surface. Shortcut ⌘K is shown beside it.',
  },
  'nav.inbox': {
    message: 'Inbox',
    description:
      'Sidebar navigation: items awaiting the user’s action. Carries an unread count as a trailing number.',
  },
  'nav.home': { message: 'Home', description: 'Sidebar navigation: the landing surface.' },
  'nav.ask': {
    message: 'Ask',
    description:
      'Sidebar navigation: the AI surface, which reads the user’s own documents. Shortcut ⌘J.',
  },
  'nav.files': {
    message: 'Files',
    description: 'Sidebar navigation: the file libraries of the current workspace.',
  },
  'nav.lists': { message: 'Lists', description: 'Sidebar navigation: structured list surfaces.' },
  'nav.pages': { message: 'Pages', description: 'Sidebar navigation: authored page surfaces.' },
  'nav.activity': {
    message: 'Activity',
    description: 'Sidebar navigation: the workspace activity feed.',
  },
  'nav.favorites': { message: 'Favorites', description: 'Sidebar navigation: the user’s starred items.' },
  'nav.shared': {
    message: 'Shared with me',
    description: 'Sidebar navigation: items other people have shared with this user.',
  },
  'nav.trash': {
    message: 'Trash',
    description: 'Sidebar navigation: deleted items, still restorable.',
  },
  'nav.admin': {
    message: 'Admin',
    description: 'Sidebar navigation: the administrative surface. Only shown to administrators.',
  },
  'nav.section.personal': {
    message: 'Personal',
    description: 'Sidebar section heading above the current user’s own surfaces.',
  },
  'nav.section.admin': {
    message: 'Administration',
    description:
      'Sidebar section heading above administrative surfaces. Shown only to accounts whose /me response says isAdmin — as navigation, not as enforcement: every admin route still runs the policy chain and refuses on its own authority.',
  },
  'nav.workspaceSwitcher': {
    message: 'Switch workspace',
    description: 'Accessible name of the brand button at the top of the sidebar, which opens the workspace switcher.',
  },
  'nav.signOut': {
    message: 'Sign out',
    description: 'Accessible name of the user chip at the foot of the sidebar.',
  },
  'theme.light': { message: 'Light', description: 'Theme toggle: the light theme.' },
  'theme.dark': { message: 'Dark', description: 'Theme toggle: the dark theme.' },
  'search.filters.label': {
    message: 'Filters',
    description:
      'The search filter control. Renders under the unbuilt treatment: the search endpoint refuses every narrowing filter with a 400, and filtering client-side would narrow what is shown without narrowing what was searched.',
  },
  'search.filters.unbuilt': {
    message: 'Narrowing a search arrives once the API accepts filters',
    description:
      'Release note for the unbuilt search filters, reached through aria-describedby. Future tense, about the product. Never a permission refusal.',
  },
  'library.title': {
    message: 'Files',
    description:
      'The library breadcrumb’s root crumb. The library’s own name is not on the wire — GET /libraries/{id}/items returns items and a page, never the container’s metadata — so this generic label stands in rather than an id dressed up as a title.',
  },
  'library.folder': {
    message: 'Folder',
    description:
      'Breadcrumb crumb for the folder currently open. Generic for the same reason as library.title: the listing payload does not name the folder.',
  },
  'library.breadcrumb': {
    message: 'Location',
    description: 'Accessible name of the breadcrumb navigation landmark in the location bar.',
  },
  'library.toggleDetails': {
    message: 'Toggle details',
    description:
      'Icon button in the location bar that opens or closes the peek panel. aria-pressed reflects whether the panel is open.',
  },
  'library.views': {
    message: 'Saved views',
    description:
      'Accessible name of the saved-view tab strip in the view bar. Only one view is shown today because no endpoint serves saved views.',
  },
  'library.view.all': {
    message: 'All',
    description:
      'The only saved view that exists: every item in the current library or folder, unfiltered.',
  },
  'library.filter': {
    message: 'Filter',
    description:
      'View-bar control for narrowing a listing. Unbuilt: no endpoint filters a listing, and filtering client-side would narrow what is shown without narrowing what was fetched.',
  },
  'library.filter.unbuilt': {
    message: 'Narrowing a listing arrives once the API accepts filters',
    description:
      'Release note for the unbuilt Filter control, reached through aria-describedby. Future tense, about the product. Never a permission refusal.',
  },
  'library.display': {
    message: 'Display',
    description:
      'View-bar control for grouping, sorting and column choices. Unbuilt: nothing stores a display preference and the listing payload supports one grouping.',
  },
  'library.display.unbuilt': {
    message: 'Grouping and sorting options arrive with saved views',
    description:
      'Release note for the unbuilt Display control. Future tense, about the product. Never a permission refusal.',
  },
  'library.new': {
    message: 'New',
    description:
      'View-bar primary action for creating a folder or document. Unbuilt: no endpoint creates a folder.',
  },
  'library.new.unbuilt': {
    message: 'Creating folders arrives with the content write API',
    description:
      'Release note for the unbuilt New control. Future tense, about the product. Never a permission refusal — nobody has been denied anything.',
  },
  'library.upload': {
    message: 'Upload',
    description:
      'View-bar button for adding files. Renders under the unbuilt treatment because the API binds an unconfigured delivery pipeline and the upload route answers 503 in every build.',
  },
  'library.group.folders': {
    message: 'Folders',
    description: 'Group header above the folders in a library listing.',
  },
  'library.group.files': {
    message: 'Files',
    description: 'Group header above the files in a library listing.',
  },
  'library.status.AVAILABLE': {
    message: 'Available',
    description: 'File lifecycle status: the file is ready to read.',
  },
  'library.status.PROCESSING': {
    message: 'Processing',
    description:
      'File lifecycle status: the file is being prepared and is not yet readable. Not an error.',
  },
  'library.status.QUARANTINED': {
    message: 'Quarantined',
    description:
      'File lifecycle status: antivirus flagged this file and no read path will serve it.',
  },
  'library.status.FAILED': {
    message: 'Failed',
    description: 'File lifecycle status: processing did not complete.',
  },
  'library.peek.label': {
    message: 'Details',
    description:
      'Accessible name of the peek panel, which is an aside rather than a dialog: it does not trap focus and the list behind it stays interactive.',
  },
  'library.peek.close': {
    message: 'Close details',
    description: 'Icon button that closes the peek panel and returns focus to the row that opened it.',
  },
  'library.peek.none': {
    message: 'Select a file to see its details',
    description:
      'Shown in the peek panel when it is pinned open with no file selected. Keeps the panel’s width so the list does not reflow when a row is picked.',
  },
  'library.peek.unavailable': {
    message: 'Details unavailable',
    description: 'Title of the peek panel when the request for a file’s details did not succeed.',
  },
  'library.peek.meta': {
    message: 'Version {version} · {size} · {modified}',
    description:
      'The one-line summary under a file’s name in the peek panel. A single message rather than four fragments joined in JavaScript, so a translator controls both the order and the separator.',
  },
  'library.peek.noVersion': {
    message: 'none',
    description:
      'Substituted for the version number when a file has no current version. Lowercase because it appears mid-sentence inside library.peek.meta.',
  },
  'library.peek.fact.status': {
    message: 'Status',
    description: 'Peek panel fact label: the file’s lifecycle status.',
  },
  'library.peek.fact.type': {
    message: 'Type',
    description: 'Peek panel fact label: the media type the server determined.',
  },
  'library.peek.fact.size': {
    message: 'Size',
    description: 'Peek panel fact label: the file size, formatted with Intl.NumberFormat.',
  },
  'library.peek.fact.modified': {
    message: 'Modified',
    description: 'Peek panel fact label: when the file last changed.',
  },
  'library.peek.fact.created': {
    message: 'Created',
    description: 'Peek panel fact label: when the file was first added.',
  },
  'library.peek.fact.governance': {
    message: 'Governance',
    description:
      'Peek panel fact label: whether the file is under legal hold or declared a record, both of which restrict deletion.',
  },
  'library.peek.governance.hold': {
    message: 'On legal hold',
    description: 'Governance value: the file is preserved for litigation and cannot be deleted.',
  },
  'library.peek.governance.record': {
    message: 'Declared a record',
    description: 'Governance value: the file is immutable under a records policy.',
  },
  'library.peek.governance.none': {
    message: 'No restrictions',
    description:
      'Governance value: neither a legal hold nor a records declaration applies to this file.',
  },
  'library.peek.tabs': {
    message: 'File details',
    description: 'Accessible name of the peek panel’s tab strip.',
  },
  'library.peek.tab.preview': {
    message: 'Preview',
    description:
      'Peek panel tab showing a rendered copy of the document. Unbuilt: the API binds an unconfigured delivery pipeline, so no rendition can exist.',
  },
  'library.peek.tab.details': {
    message: 'Details',
    description: 'Peek panel tab showing the file’s facts and what this user may do with it.',
  },
  'library.peek.tab.access': {
    message: 'Access',
    description:
      'Peek panel tab showing who can reach this file. Unbuilt: no endpoint returns an access list.',
  },
  'library.peek.tab.access.unbuilt': {
    message: 'Seeing who has access arrives with the permissions API',
    description:
      'Release note behind the unbuilt Access tab. Future tense, about the product. Not a refusal — the user is not being denied a view that exists.',
  },
  'library.peek.tab.versions': {
    message: 'Versions',
    description: 'Peek panel tab listing the file’s version history.',
  },
  'library.peek.tab.activity': {
    message: 'Activity',
    description:
      'Peek panel tab showing what has happened to this file. Unbuilt: the audit trail is hash-chained evidence and deliberately not a user-facing feed, so this needs a purpose-built read model.',
  },
  'library.peek.tab.activity.unbuilt': {
    message: 'A file’s history needs a read model the audit trail deliberately isn’t',
    description:
      'Release note behind the unbuilt Activity tab. States why it cannot simply be built on the audit log. Future tense, about the product.',
  },
  'library.peek.escHint': {
    message: 'to close',
    description:
      'Caption after the Esc key cap in the peek panel header. Reads as "Esc to close"; the key cap is a separate element so it can be styled and so the glyph can differ per platform.',
  },
  'library.peek.previous': {
    message: 'Previous file',
    description:
      'Icon button that moves the peek panel to the row above. Disabled at the top of the list — a neutral end-of-list state, never the denial treatment.',
  },
  'library.peek.next': {
    message: 'Next file',
    description: 'Icon button that moves the peek panel to the row below.',
  },
  'library.peek.versions.number': {
    message: 'Version {major}.{minor}',
    description:
      'A version’s number in the history list. major and minor are integers from the server.',
  },
  'library.peek.versions.none': {
    message: 'This file has no version history yet.',
    description: 'Empty state of the peek panel’s Versions tab.',
  },
  'library.peek.versions.unreadable': {
    message: 'Not yet readable',
    description:
      'Marks a version the server will not serve as bytes, because antivirus has not cleared it. The server computes this and sends it; the client never recomputes it from the status fields beside it.',
  },
  'library.peek.capabilities': {
    message: 'What you can do',
    description:
      'Heading above the list of actions the server said this user may take on this file. Second person, because a capability is a fact about this user at this moment, not a property of the file.',
  },
  'library.peek.cap.allowed': {
    message: 'allowed',
    description:
      'Screen-reader-only word marking a capability as permitted, so the state is carried by text and not by colour alone.',
  },
  'library.peek.cap.refused': {
    message: 'not allowed',
    description:
      'Screen-reader-only word marking a capability as refused. No reason accompanies it: the capability object carries bare booleans today, and a client-invented explanation is forbidden.',
  },
  'library.peek.cap.preview': {
    message: 'Preview',
    description:
      'Capability name: view a rendered copy in the browser. Distinct from download — never collapse the two.',
  },
  'library.peek.cap.download': {
    message: 'Download',
    description: 'Capability name: obtain the original bytes.',
  },
  'library.peek.cap.print': {
    message: 'Print',
    description: 'Capability name: send to a printer. A separate permission from download.',
  },
  'library.peek.cap.export': {
    message: 'Export',
    description: 'Capability name: convert to another format and take it away.',
  },
  'library.peek.cap.edit': {
    message: 'Edit',
    description: 'Capability name: change the file’s contents.',
  },
  'library.peek.cap.share': {
    message: 'Share',
    description: 'Capability name: grant access to someone inside the organisation.',
  },
  'library.peek.cap.shareExternal': {
    message: 'Share externally',
    description:
      'Capability name: grant access to someone outside the organisation. Deliberately separate from Share.',
  },
  'library.peek.cap.delete': {
    message: 'Delete',
    description: 'Capability name: remove the file.',
  },
  'library.peek.cap.sync': {
    message: 'Sync',
    description:
      'Capability name: keep a copy on a registered device. A separate permission from download.',
  },
  'library.peek.obligations': {
    message: 'Conditions',
    description:
      'Heading above the obligations attached to an allowed action — things that must also happen, such as a watermark or a written justification.',
  },
  'library.peek.obligation.watermark': {
    message: 'Watermarked',
    description: 'Obligation: every rendered copy carries a visible watermark.',
  },
  'library.peek.obligation.justification': {
    message:
      '{count, plural, one {# action needs a justification} other {# actions need a justification}}',
    description:
      'Obligation: the named actions require the user to type a reason before they proceed. count is how many actions carry the requirement.',
  },
  'library.peek.obligation.approval': {
    message:
      '{count, plural, one {# action needs approval} other {# actions need approval}}',
    description:
      'Obligation: the named actions require someone else to approve them first. count is how many actions carry the requirement.',
  },
  'surface.error.title': {
    message: 'This didn’t load',
    description:
      'Title of the failure panel shown when a request did not complete — a server fault, a network drop, or a response that did not parse. Never shown for a permission refusal, which has its own panel.',
  },
  'surface.error.body': {
    message: 'Something went wrong on our side. Trying again may work.',
    description:
      'Body of the failure panel when the failure is retryable (5xx, network, timeout). Paired with a Retry button.',
  },
  'surface.error.bodyFinal': {
    message: 'Something went wrong and trying again won’t help. Quote the request ID below if you report this.',
    description:
      'Body of the failure panel when retrying cannot succeed (a 4xx, or a response that did not match the expected shape). No Retry button is shown, so the text must not promise one.',
  },
  'surface.error.retry': {
    message: 'Try again',
    description:
      'Button that re-issues only the failed request. Shown ONLY on retryable failures, and never on a permission refusal.',
  },
  'surface.error.requestId': {
    message: 'Request ID',
    description:
      'Label before the correlation ID a user quotes when reporting a failure. Followed by the ID in a monospace font.',
  },
  'surface.error.copy': {
    message: 'Copy',
    description: 'Button that copies the request ID to the clipboard.',
  },
  'surface.error.copied': {
    message: 'Copied',
    description:
      'Replaces the Copy button’s label once the request ID has been copied. Past tense, confirming what just happened.',
  },
  'surface.denied.title': {
    message: 'You don’t have access to this',
    description:
      'Title of the refusal panel: the server answered and the answer was no. Present tense, about this user. This panel never offers a retry, because retrying a policy decision cannot change it.',
  },
  'surface.denied.noReason': {
    message: 'The server refused this request but gave no reason to show.',
    description:
      'Fallback body when a 403 arrives with an empty message. The client may never invent an explanation or name the rule that matched, so this states the absence rather than filling it.',
  },
  'surface.denied.codeLabel': {
    message: 'Code',
    description:
      'Label before the stable refusal code (for example ACCESS_DENIED). Shown so a user can quote it when asking for access.',
  },
  'surface.stepUp.title': {
    message: 'Additional verification needed',
    description:
      'Title shown when the server asks for a stronger authentication factor before allowing an action. Neither a refusal nor a fault — a challenge to answer.',
  },
  'surface.stepUp.body': {
    message: 'This action needs you to confirm your identity again. Signing in with your second factor isn’t available in this release.',
    description:
      'Body of the step-up panel. States both what the server asked for and that the client cannot yet answer it, rather than leaving the user at a dead end with no explanation.',
  },
  'later.chip': {
    message: 'Later',
    description:
      'Neutral marker on a control the product does not have yet. Must never read as a refusal — it is about the product’s roadmap, not about this user’s permissions (plans/M5-MVP-GA.md D33). Future tense.',
  },
  'later.arrivesLater': {
    message: 'Arrives in a later release',
    description:
      'The description associated with an unbuilt control. Future tense, about the product. Never offers a remedy, because there is nothing the user can do.',
  },

  /* The denial sentences (`ENC-674`), one per reason code in `docs/05-API.md §5`.
   *
   * These are the wording half of a decision the *server* made: it answers
   * `capabilities.download: false` and names `capabilityReasons.download:
   * "PREVIEW_ONLY"`, and this catalog turns that code into a sentence in the
   * reader's language (`docs/14 §5`). Nothing here chooses which code applies.
   *
   * Three rules for translators and for anyone editing them:
   *
   * 1. **Present tense, about this user, right now.** These are the opposite of
   *    `later.*` above, which is future tense about the product. A denial that
   *    reads like a roadmap note and a roadmap note that reads like a refusal
   *    are the two failures `ENC-673` exists to prevent, and the copy is half of
   *    what keeps them apart.
   * 2. **Never name the rule.** No policy names, thresholds, conditions, or
   *    whether anyone else has access (`docs/06 §24`, `CLAUDE.md` rule 10). Say
   *    what is not available and, where it is genuinely actionable, what would
   *    change it. Never why in terms of the system's own configuration.
   * 3. **Never promise a retry.** A denial is a successful request with a
   *    refusing answer (`docs/17 §7`). "Try again" is false and turns an access
   *    request into a bug report.
   */
  'denial.accessDenied': {
    message: 'You do not have access to this.',
    description:
      'Shown on a control the authorization stage refused. The most general denial there is — used when no more specific rule applied. Do not translate as "forbidden" or "error"; it is a statement about this user’s access, not about a failure.',
  },
  'denial.downloadBlockedByPolicy': {
    message: 'Downloading this file is restricted outside the corporate network.',
    description:
      'Shown on Download when network policy blocks it specifically. Other access to the same file may be permitted, so do not translate as though the whole file were unavailable.',
  },
  'denial.externalShareBlocked': {
    message: 'This file cannot be shared outside your organisation.',
    description:
      'Shown on the external-sharing control. Internal sharing may still be allowed — the restriction is on the audience, not on sharing.',
  },
  'denial.previewOnly': {
    message: 'This file can be viewed but not downloaded.',
    description:
      'Shown on Download, Print and Export when the policy allows a rendition but not the original bytes. Leads with what is permitted, deliberately: the user can still read the document.',
  },
  'denial.networkNotAllowed': {
    message: 'This action is not permitted from your current network.',
    description:
      'Conditional access refused on network. "Current network" rather than any named network or location — never identify which networks are permitted.',
  },
  'denial.deviceNotManaged': {
    message: 'This action requires a managed device.',
    description:
      'Conditional access refused on device posture. Do not describe what makes a device managed; that is the administrator’s to explain.',
  },
  'denial.stepUpRequired': {
    message: 'This action needs a fresher sign-in.',
    description:
      'Authentication succeeded but is not recent or strong enough. Distinct from being signed out — the user is signed in, and the session is simply too old for this particular action.',
  },
  'denial.dlpBlocked': {
    message: 'This content cannot be shared or exported.',
    description:
      'Data-loss-prevention refused outright. Never say what was matched or which rule matched (CLAUDE.md rule 10) — the sentence stops at the outcome.',
  },
  'denial.dlpJustificationRequired': {
    message: 'This action needs a written justification.',
    description:
      'Not a refusal so much as a condition: the action proceeds once the user records a reason. Translate as a requirement, not as a denial.',
  },
  'denial.dlpApprovalRequired': {
    message: 'This action needs approval before it can proceed.',
    description:
      'The action is routed to an approver rather than executed. As above, a condition rather than a refusal — the user is not being told no.',
  },
  'denial.classificationCeiling': {
    message: 'This content is above the sensitivity level available here.',
    description:
      '"Here" means this client or this context, not this user — the same content may be readable elsewhere. Never state the content’s classification, which the user may not be cleared to know.',
  },
  'denial.legalHoldActive': {
    message: 'This item is under legal hold and cannot be changed.',
    description:
      'Shown on Edit and Delete. A statement about the item, not about the user — everyone sees this, including administrators.',
  },
  'denial.retentionBlocksDelete': {
    message: 'A retention policy prevents this item from being deleted.',
    description:
      'Shown on Delete only. Do not name the policy or its period; the user can quote the reason code to an administrator who can.',
  },
  'denial.recordImmutable': {
    message: 'This item is a declared record and cannot be modified.',
    description:
      'Shown on every mutation. A property of the item, like legal hold — not a permission the user is missing.',
  },
  'denial.quotaExceeded': {
    message: 'Your organisation has reached a storage or usage limit.',
    description:
      'Deliberately about the organisation rather than the user: an individual cannot resolve it, and phrasing it personally sends them looking for something to delete.',
  },
  'denial.syncNotPermitted': {
    message: 'This file is available on the web only.',
    description:
      'Shown on Sync. States where the file *is* available rather than where it is not, because the user can still work with it — they simply will not find it in a synced folder.',
  },
  'denial.malwareDetected': {
    message: 'This file did not pass a security scan.',
    description:
      'Shown on every content path. Neutral about cause — a scan verdict is not an accusation about whoever uploaded it.',
  },
  'denial.sessionReplay': {
    message: 'Your session has ended for security reasons.',
    description:
      'The credential was reused in a way that ended the session. Never explain the detection; say what happened and let the sign-in flow take it from there.',
  },
  'denial.unspecified': {
    message: 'This action is not available to you.',
    description:
      'Shown when the server withheld a capability and sent a reason code this build has no wording for — a newer server naming a reason this client cannot phrase yet. Deliberately a restatement of the refusal and never a guess at its cause: an invented explanation is wrong exactly when it matters. Keep it as unspecific in translation as it is here.',
  },
  'classification.public': {
    message: 'Public',
    description:
      'Sensitivity label, lowest of five. Shown as a badge with a locked colour; the text is what carries the meaning (docs/09 §15).',
  },
  'classification.internal': {
    message: 'Internal',
    description: 'Sensitivity label, second of five.',
  },
  'classification.confidential': {
    message: 'Confidential',
    description: 'Sensitivity label, third of five.',
  },
  'classification.highlyConfidential': {
    message: 'Highly confidential',
    description:
      'Sensitivity label, fourth of five. Abbreviate in translation if the column would clip; the badge is 108px wide.',
  },
  'classification.restricted': {
    message: 'Restricted',
    description: 'Sensitivity label, highest of five.',
  },
  'classification.unclassified': {
    message: 'Unclassified',
    description:
      'Shown for a file that has no sensitivity label yet. Not a sixth level — an absence.',
  },

  'files.state.loading': {
    message: 'Loading files',
    description:
      'Announced while the skeleton rows are on screen. The skeleton itself is decorative.',
  },
  'files.state.empty.title': {
    message: 'Nothing here yet',
    description: 'Heading of the empty state for a library that has never had a file in it.',
  },
  'files.state.empty.body': {
    message: 'Upload a file, or create a folder to organise one into.',
    description:
      'Body of the new-empty state. Says what the surface is for and names the one action that starts it (docs/09 §11).',
  },
  'files.state.empty.action': {
    message: 'Upload files',
    description: 'Primary action on the new-empty state.',
  },
  'files.state.filtered.title': {
    message: 'No files match these filters',
    description: 'Heading of the empty state when filters are active and exclude everything.',
  },
  'files.state.filtered.body': {
    message:
      '{count, plural, one {# file is hidden by the active filters.} other {# files are hidden by the active filters.}}',
    description:
      'Body of the filtered-empty state. "count" is how many rows the unfiltered query would return, so the user can tell an empty library from an over-narrow filter.',
  },
  'files.state.filtered.action': {
    message: 'Clear filters',
    description: 'Action on the filtered-empty state. Restores the unfiltered list.',
  },
  'files.state.error.title': {
    message: 'This list could not be loaded',
    description:
      'Heading of the fetch-error state. Says what failed, not why — the reason belongs in the detail disclosure.',
  },
  'files.state.error.body': {
    message: 'The request did not complete. Nothing has changed.',
    description:
      'Body of the retryable fetch-error state. Reassures that a failed read changed nothing.',
  },
  'files.state.error.bodyFinal': {
    message: 'The request cannot be retried from here. Contact support with the request ID below.',
    description: 'Body of the fetch-error state when the failure is not retryable.',
  },
  'files.state.error.retry': {
    message: 'Try again',
    description: 'Retry action on the fetch-error state. Present only when the error is retryable.',
  },

  'home.greeting.morning': {
    message: 'Good morning, {name}',
    description:
      'Page heading on Home, shown before noon in the reader’s own timezone. "name" is the form of address the user is called by, supplied by the server — never assembled in the client, because name order is not universal (docs/14 §6).',
  },
  'home.greeting.afternoon': {
    message: 'Good afternoon, {name}',
    description: 'Page heading on Home, from noon until 18:00 in the reader’s own timezone.',
  },
  'home.greeting.evening': {
    message: 'Good evening, {name}',
    description:
      'Page heading on Home, from 18:00 until midnight in the reader’s own timezone. Also used through the night; there is no separate late-night greeting.',
  },
  'home.subline': {
    message:
      '{date} · {workspace} · {attention, plural, =0 {nothing needs your attention} one {# thing needs your attention} other {# things need your attention}}',
    description:
      'The line under the Home greeting. "date" arrives already formatted by Intl and is never re-formatted here; "workspace" is the workspace name; "attention" is how many items are waiting on this user in this workspace. The middle dot is a separator and may be replaced by whatever separates list items in the target language.',
  },
  'home.attention.title': {
    message: 'Needs your attention',
    description:
      'Section heading on Home over the approvals, reviews and signatures waiting on this user. About the user, present tense.',
  },
  'home.attention.requestedBy': {
    message: 'Requested by {name}',
    description:
      'Second line of an item in the "Needs your attention" list. "name" is the person who sent the request. Followed by the age of the request as a separate relative time.',
  },
  'home.attention.action.approve': {
    message: 'Approve',
    description:
      'Action on an approval waiting on this user. Currently unbuilt (there is no approvals backend), so it renders with a neutral Later chip and is not focusable — never with the denial treatment.',
  },
  'home.attention.action.review': {
    message: 'Review',
    description: 'Action on a document sent to this user to read and comment on. Currently unbuilt.',
  },
  'home.attention.action.sign': {
    message: 'Sign',
    description: 'Action on a document waiting for this user’s signature. Currently unbuilt.',
  },
  'home.attention.empty': {
    message: 'Nothing is waiting on you in this workspace.',
    description:
      'Shown in place of the "Needs your attention" list when it is empty but the rest of Home is not. A statement of fact, not congratulation — the user may simply be new.',
  },
  'home.recent.title': {
    message: 'Continue working',
    description:
      'Section heading on Home over the files this user opened most recently, newest first.',
  },
  'home.recent.empty': {
    message: 'You have not opened anything in this workspace yet.',
    description:
      'Shown in place of the "Continue working" list when this user has no history in this workspace.',
  },
  'home.recent.laterNote': {
    message: 'Opening a file from here arrives in a later release.',
    description:
      'Explains the neutral Later chip beside the "Continue working" heading: the rows are readable but not yet openable. Future tense, about the product, and it offers no remedy — it is not a refusal (docs/17 §6).',
  },
  'home.asks.title': {
    message: 'Recent asks',
    description:
      'Section heading on Home over the questions this user recently put to Ask, the assistant surface.',
  },
  'home.asks.empty': {
    message: 'You have not asked anything yet.',
    description: 'Shown in place of the "Recent asks" row when this user has no ask history.',
  },
  'home.asks.laterNote': {
    message: 'Re-running an ask arrives with Ask, in a later release.',
    description:
      'Explains the neutral Later chip beside the "Recent asks" heading. Ask itself is a later milestone, so the pills record what was asked without being able to run it again.',
  },
  'home.state.loading': {
    message: 'Loading your workspace',
    description:
      'Announced while Home’s skeleton is on screen. The skeleton itself is decorative and hidden from assistive technology.',
  },
  'home.state.empty.title': {
    message: 'Your workspace is quiet',
    description:
      'Heading of Home’s empty state: nothing is waiting, nothing has been opened, nothing has been asked. Usually a brand-new workspace.',
  },
  'home.state.empty.body': {
    message:
      'Home gathers what is waiting on you, what you were last working on, and what you have asked. Add a file to a library and it starts filling up.',
    description:
      'Body of Home’s new-empty state. Says what the surface is for and names the one action that starts it (docs/09 §11).',
  },
  'home.state.empty.action': {
    message: 'Upload a file',
    description:
      'The one action on Home’s new-empty state. Currently unbuilt, so it carries a neutral Later chip rather than a refusal.',
  },
  'home.state.scoped.title': {
    message: 'Nothing here, but not nothing everywhere',
    description:
      'Heading of Home’s scoped-empty state: this workspace is empty for this user, while other workspaces are not. Home’s equivalent of "no results for these filters" — the scope is the workspace rather than a filter bar.',
  },
  'home.state.scoped.body': {
    message:
      '{count, plural, one {# item is waiting for you in another workspace.} other {# items are waiting for you in other workspaces.}}',
    description:
      'Body of Home’s scoped-empty state. "count" is how many attention items the current workspace scope is hiding, so the user can tell "I am done" from "I am looking in the wrong place".',
  },
  'home.state.scoped.action': {
    message: 'Switch workspace',
    description:
      'Action on Home’s scoped-empty state — the equivalent of clearing a filter. Currently unbuilt, so it carries a neutral Later chip.',
  },
  'home.state.error.title': {
    message: 'Home could not be loaded',
    description:
      'Heading of Home’s fetch-error state. Names what failed, not why. A policy refusal never reaches this state (docs/09 §11).',
  },
  'home.state.error.body': {
    message: 'The request did not complete. Nothing has changed.',
    description:
      'Body of the retryable fetch-error state on Home. Reassures that a failed read changed nothing.',
  },
  'home.state.error.bodyFinal': {
    message: 'The request cannot be retried from here. Contact support with the request ID below.',
    description: 'Body of Home’s fetch-error state when the failure is not retryable.',
  },
  'home.state.error.retry': {
    message: 'Try again',
    description:
      'Retry action on Home’s fetch-error state. Present only when the failure is retryable, and never on a policy denial — retrying a denial teaches a user the product is broken rather than that they lack permission (docs/17 §7).',
  },

  /* ------------------------------------------------------------------- ask
   *
   * The Ask surface has no backend in M5 (`plans/M5-MVP-GA.md` D33), so the
   * tense of every string here is load-bearing. `ask.*` copy is **future tense
   * and about the product** — "an answer will show its sources". A denial's
   * copy is present tense and about the user — "downloading this file is
   * restricted outside the corporate network". A translator who collapses the
   * two has erased a security distinction, so each description says so.
   */
  'ask.heading': {
    message: 'Ask',
    description:
      'Heading of the Ask surface — the AI that reads the user’s own documents. Same word as the sidebar entry (nav.ask), kept separate because a heading and a navigation label diverge in languages that inflect.',
  },
  'ask.arrivesInM7': {
    message: 'Arrives in a later release',
    description:
      'The release note on every unbuilt control on the Ask surface. FUTURE tense, about the PRODUCT, and it offers no remedy — there is nothing the user can do to obtain it (plans/M5-MVP-GA.md D33). It must never be translated as a refusal or as anything the user could act on; that phrasing belongs to a policy denial, and confusing the two erases a security signal.',
  },
  'ask.empty.title': {
    message: 'Ask across your libraries',
    description:
      'Heading of the Ask surface when nothing has been asked. Says what the surface is for (docs/09 §11).',
  },
  'ask.empty.body': {
    message:
      'Ask a question in your own words. Answers will be drawn only from documents you can already open, and every ask is audited.',
    description:
      'Body of the Ask empty state. Future tense on the answering, present tense on the auditing, because the audit trail is a standing property of the product and the answering is not built yet.',
  },
  'ask.shape.caption': {
    message: 'What an answer will look like',
    description:
      'Caption above the wireframe that shows the shape of an answer without generating one. Future tense: no answer exists yet and none is being fabricated.',
  },
  'ask.shape.body': {
    message:
      'An answer arrives with its sources beside it. Each source names the document and the page or section the passage came from, and links straight to it. A document you may only preview stays preview-only inside an answer.',
    description:
      'States the source-and-citation contract (docs/09 §10) while the surface is unbuilt, so the promise is made even though no answer can be produced. "preview-only" refers to the preview permission, which is a different permission from download.',
  },
  'ask.composer.label': {
    message: 'Your question',
    description:
      'Accessible name of the Ask composer’s text field. The field is present but inert until the surface is built.',
  },
  'ask.composer.placeholder': {
    message: 'Ask a question about your documents',
    description: 'Placeholder inside the Ask composer’s text field.',
  },
  'ask.composer.send': {
    message: 'Send question',
    description:
      'Accessible name of the Ask composer’s send button, whose visible form is an arrow icon.',
  },
  'ask.composer.scope.libraries': {
    message: 'Every library you can open',
    description:
      'Scope chip on the Ask composer, stating the default breadth of an ask. Describes the access rule rather than naming a library, because the scope picker is not built yet.',
  },
  'ask.composer.scope.anyDate': {
    message: 'Any date',
    description:
      'Scope chip on the Ask composer, stating the default date range. Not a formatted date — it is the absence of a date filter.',
  },
  'ask.state.loading': {
    message: 'Searching the documents you can open',
    description:
      'Announced while an ask is in flight and the answer skeleton is on screen. Names what is happening — a search bounded by the user’s access — rather than saying "loading".',
  },
  'ask.state.scopeEmpty.title': {
    message: 'Nothing in scope',
    description:
      'Heading of the Ask filtered-empty state: the scope chips exclude every document, so there is nothing to answer from.',
  },
  'ask.state.scopeEmpty.body': {
    message:
      '{count, plural, one {# document is outside the current scope.} other {# documents are outside the current scope.}}',
    description:
      'Body of the Ask filtered-empty state. "count" is how many documents the unscoped ask could have read, so a narrow scope is distinguishable from an empty workspace. It is never a count of documents the user cannot open — that number is not disclosed.',
  },
  'ask.state.scopeEmpty.action': {
    message: 'Widen the scope',
    description: 'Action on the Ask filtered-empty state. Clears the scope chips.',
  },
  'ask.state.error.title': {
    message: 'This question could not be answered',
    description:
      'Heading of the Ask fetch-error state. A failure of the request, never a policy refusal — a refusal is a successful request with a refusing answer and renders inline instead (docs/09 §11).',
  },
  'ask.state.error.body': {
    message: 'The request did not complete. Nothing was asked of your documents.',
    description:
      'Body of the retryable Ask error state. Reassures that a failed ask read nothing and recorded nothing.',
  },
  'ask.state.error.bodyFinal': {
    message: 'This question cannot be retried from here. Contact support with the request ID below.',
    description: 'Body of the Ask error state when the failure is not retryable.',
  },
  'ask.state.error.retry': {
    message: 'Ask again',
    description:
      'Retry action on the Ask error state. Present only for a failed request — a policy denial never offers retry (docs/09 §11).',
  },
  'auth.title': {
    message: 'Sign in to {brand}',
    description:
      'Heading of the sign-in screen. "brand" is the tenant’s product name from the branding API (docs/09 §18), falling back to app.brand. It is display text only — the tenant is resolved at the gateway and is never chosen on this screen.',
  },
  'auth.subtitle': {
    message: 'Use your work email address and password.',
    description:
      'One line under the sign-in heading. Says what the primary path is. Must never suggest that the address selects a workspace or organisation — it does not (CLAUDE.md rule 3).',
  },
  'auth.email.label': {
    message: 'Email address',
    description:
      'Label above the email field on sign-in. Rendered above the input and stays visible while typing; the placeholder is a hint, never the label.',
  },
  'auth.email.placeholder': {
    message: 'name@example.com',
    description:
      'Placeholder hint in the sign-in email field. Translate the shape of a local address if that helps; do not translate it into a real domain.',
  },
  'auth.password.label': {
    message: 'Password',
    description: 'Label above the password field on sign-in.',
  },
  'auth.submit': {
    message: 'Sign in',
    description: 'Primary action on the sign-in screen. The email path, which is the working path in M5.',
  },
  'auth.submitting': {
    message: 'Signing in…',
    description:
      'Label of the sign-in button while the request is in flight. The button stays focusable and carries aria-busy; it is not disabled.',
  },
  'auth.or': {
    message: 'or',
    description:
      'The word in the rule separating the primary email path from the alternative sign-in methods. Decorative and hidden from screen readers.',
  },
  'auth.continueWithSso': {
    message: 'Continue with {provider}',
    description:
      'Label of a federated sign-in button. "provider" is the workspace’s own display name for its identity provider, from configuration (docs/13 §3.2) — tenant data, not product copy, so it is not translated.',
  },
  'auth.continueWithPasskey': {
    message: 'Continue with a passkey',
    description:
      'Label of the passkey sign-in button, which is not built yet (plans/M5-MVP-GA.md D33, M6). The label describes the eventual action; the neutral Later chip beside it carries the fact that it does not exist yet.',
  },
  'auth.passkey.later': {
    message: 'Passkeys arrive in a later release.',
    description:
      'Neutral note under the unbuilt passkey button. Future tense, about the product, never about this user’s permissions, and it offers no remedy — there is nothing the user can do (plans/M5-MVP-GA.md D33). Must never read like a policy refusal.',
  },
  'auth.refused': {
    message: 'That email address and password do not match.',
    description:
      'The single sentence shown for EVERY refused sign-in — unknown address, wrong password, locked account alike. It must stay identical in all of those cases and must never name which field was wrong or whether the account exists; that is an account-enumeration control, not copy. Translations must not add a diagnosis.',
  },
  'auth.success.title': {
    message: 'You’re signed in',
    description: 'Heading of the sign-in success state, shown briefly before the workspace loads.',
  },
  'auth.success.body': {
    message: 'Taking you to your workspace…',
    description: 'Body of the sign-in success state.',
  },
  'auth.error.title': {
    message: 'Sign-in could not be completed',
    description:
      'Heading of the sign-in FETCH-ERROR state — the request did not complete (network, 5xx, unparseable response). Never used for a refused sign-in, which is a completed request with a refusing answer.',
  },
  'auth.error.body': {
    message: 'The request did not complete. Nothing has changed and you are not signed in.',
    description:
      'Body of the retryable sign-in error state. Reassures that a failed request left no state behind.',
  },
  'auth.error.bodyFinal': {
    message: 'The request cannot be retried from here. Contact support with the request ID below.',
    description: 'Body of the sign-in error state when the failure is not retryable.',
  },
  'auth.error.retry': {
    message: 'Try again',
    description:
      'Retry action on the sign-in error state. Present only for a failed request — a refused sign-in and a policy denial never offer retry (docs/09 §11, docs/17 §7).',
  },
  'auth.legal.support': {
    message: 'Support',
    description:
      'Footer link on the sign-in screen. The destination is the tenant’s configured support URL (docs/09 §18); the link is not rendered when none is configured.',
  },
  'auth.legal.privacy': {
    message: 'Privacy',
    description: 'Footer link on the sign-in screen, to the tenant’s configured privacy URL.',
  },
  'auth.legal.terms': {
    message: 'Terms',
    description: 'Footer link on the sign-in screen, to the tenant’s configured terms URL.',
  },

  /* ------------------------------------------------------------------ search
   *
   * Owned by `features/search`. Two groups are worth a translator’s attention
   * before the rest: `search.retrieval.*`, which tells a user that this search
   * matched words rather than meaning and must stay calm rather than alarming;
   * and `search.state.*`, which are the four states of `docs/09 §11`.
   */

  'search.title': {
    message: 'Search',
    description:
      'The screen’s heading. Visually hidden — the sheet has no top bar (docs/09 §3) — and read by a screen reader on entry.',
  },
  'search.input.label': {
    message: 'Search',
    description: 'Accessible name of the query field. The field carries no visible label.',
  },
  'search.input.placeholder': {
    message: 'Search files, people and metadata',
    description:
      'Placeholder in the query field. The design reference adds “— or ask a question…”; that is deliberately absent, because asking a question is M7 and the field must not promise it.',
  },
  'key.escape': {
    message: 'Esc',
    description:
      'Key cap for the Escape key, shown in the peek panel header. In the catalog rather than as a literal because the abbreviation differs by locale and by keyboard layout.',
  },
  'key.commandK': {
    message: '⌘K',
    description:
      'Key cap for the command palette, shown beside Search in the sidebar. A key cap is a user-facing string like any other: it reads “Ctrl+K” on Windows and Linux and the modifier glyph is not universal, so it is translated rather than hard-coded.',
  },
  'key.commandJ': {
    message: '⌘J',
    description:
      'Key cap for Ask, shown beside it in the sidebar. Same reasoning as key.commandK. The binding itself is registered and disabled until M7 (plans/M5-MVP-GA.md D33).',
  },
  'search.key.escape': {
    message: 'Esc',
    description:
      'Key cap shown beside the query field; the Escape key clears the query. Translate to the label printed on that key locally — French keyboards read “Échap”.',
  },
  'search.key.arrows': {
    message: '↑↓',
    description: 'Key cap for the up and down arrow keys, shown in the keyboard hint bar.',
  },
  'search.key.enter': {
    message: '⏎',
    description:
      'Key cap for the Enter/Return key, shown in the keyboard hint bar. A glyph rather than a word; replace with the local convention where a glyph is not used.',
  },
  'search.results.label': {
    message: 'Search results',
    description:
      'Accessible name of the results list. The list is virtualized, so this is how a screen-reader user knows what they have entered.',
  },
  'search.results.count': {
    message: '{count, plural, =0 {No results} one {# result} other {# results}}',
    description:
      'How many results the query returned in total, at the end of the filter row. "count" is the total, not the number currently rendered.',
  },
  'search.results.counting': {
    message: 'Searching…',
    description: 'Stands in for the result count while the query is still running.',
  },
  'search.foot.navigate': {
    message: 'move between results',
    description:
      'Keyboard hint in the footer, shown after the ↑↓ key cap. Lower case: it completes the key cap rather than starting a sentence.',
  },
  'search.foot.open': {
    message: 'open',
    description: 'Keyboard hint in the footer, shown after the Enter key cap.',
  },
  'search.foot.access': {
    message: 'Results respect your access',
    description:
      'Standing reassurance at the end of the footer. Every result has been post-filtered against the user’s permissions on the server (CLAUDE.md rule 5); this states that fact and must never imply results were dropped for any other reason.',
  },
  'search.filter.type': {
    message: 'Type',
    description: 'Leading half of the file-type filter chip. A noun, not a verb.',
  },
  'search.filter.classification': {
    message: 'Classification',
    description:
      'Leading half of the sensitivity filter chip. It filters to a ceiling — “Confidential” means at most Confidential.',
  },
  'search.filter.modified': {
    message: 'Modified',
    description: 'Leading half of the last-changed-date filter chip.',
  },
  'search.filter.workspace': {
    message: 'Workspace',
    description:
      'Leading half of the workspace filter chip. Its values are workspace names supplied by the server and are never translated.',
  },
  'search.filter.any': {
    message: 'Any',
    description:
      'The value half of a filter chip that is not narrowing anything. Must read as “no restriction”, never as “unknown”.',
  },
  'search.filter.type.pdf': {
    message: 'PDF',
    description: 'File-type filter value: PDF documents.',
  },
  'search.filter.type.doc': {
    message: 'Document',
    description: 'File-type filter value: word-processing documents (.docx, .doc).',
  },
  'search.filter.type.xls': {
    message: 'Spreadsheet',
    description: 'File-type filter value: spreadsheets (.xlsx, .xls).',
  },
  'search.filter.type.ppt': {
    message: 'Presentation',
    description: 'File-type filter value: presentations (.pptx, .ppt).',
  },
  'search.filter.modified.any': {
    message: 'Any time',
    description: 'Date filter value: no date restriction. The default.',
  },
  'search.filter.modified.week': {
    message: 'Past 7 days',
    description: 'Date filter value: files changed within the last seven days.',
  },
  'search.filter.modified.month': {
    message: 'Past 30 days',
    description: 'Date filter value: files changed within the last thirty days.',
  },
  'search.filter.modified.year': {
    message: 'Past year',
    description: 'Date filter value: files changed within the last year.',
  },
  'search.filter.change': {
    message: 'Change the {filter} filter. Currently {value}',
    description:
      'Accessible name of the button that opens a filter chip’s menu. "filter" is the chip’s name (Type, Classification…); "value" is its current setting.',
  },
  'search.filter.remove': {
    message: 'Remove the {filter} filter',
    description:
      'Accessible name of the ✕ on an active filter chip. Each chip is removable on its own (docs/09 §10), so this names which one.',
  },
  'search.answer.title': {
    message: 'Answers drawn from these documents, with their sources',
    description:
      'The AI-answer slot above the results, shown in the unbuilt treatment with a “Later” chip. Future tense about the product, never about this user’s permissions: the feature is M7, not refused (docs/17 §6). Never word it as though an answer were being withheld.',
  },
  'search.retrieval.head': {
    message: 'Matching on words, not meaning',
    description:
      'Heading of the degraded-search header (docs/09 §10). This is not an error and must not be translated with alarm vocabulary — no “failed”, “problem”, “error”. It states how the search ran.',
  },
  'search.retrieval.stillSearched': {
    message:
      'Every file you can open is still being searched — by name, by metadata, and by the words inside it.',
    description:
      'First line of the degraded-search header, and deliberately the reassuring one: coverage is unchanged and only the matching is narrower. Keep it first in translation.',
  },
  'search.retrieval.lexical': {
    message:
      'A document that says “terminate for convenience” will not be found by searching “cancel the contract”. Finding a document by what it means arrives in a later release.',
    description:
      'Second line, shown when this deployment has no semantic retrieval at all — a product state, so future tense about the product. Replace the quoted example with a natural pair in your language: two ways of saying the same thing that share no words.',
  },
  'search.retrieval.headDense': {
    message: 'Matching on meaning, not exact words',
    description:
      'Heading of the retrieval notice when the vector index answered and the keyword half did not (diagnostics.mode = semantic, degraded = false). The mirror image of search.retrieval.head — do not translate the two the same way, they describe opposite halves of a hybrid search. Not an error; no alarm vocabulary.',
  },
  'search.retrieval.stillSearchedDense': {
    message: 'Every file you can open is still being searched — by what its contents are about.',
    description:
      'First line of the dense variant, and the reassuring one: coverage is unchanged and only the matching is narrower. Deliberately not the same sentence as search.retrieval.stillSearched, which promises matching "by the words inside it" — the exact thing this mode does not do. Keep it first in translation.',
  },
  'search.retrieval.dense': {
    message:
      'An exact phrase may be missed — a file name, a case number or a clause reference is best found by opening the folder it lives in. Matching on the exact words as well arrives in a later release.',
    description:
      'Second line of the dense variant, shown when semantic retrieval answered but keyword retrieval has not run (docs/07 §5 hybrid fusion, ENC-891). Future tense about the product, so it carries the Later chip. The loss is the opposite of search.retrieval.lexical’s: there, meaning is missed; here, the literal string is. Replace the examples with identifiers natural to your language — the point is short exact strings a reader would type verbatim.',
  },
  'search.retrieval.degraded': {
    message:
      'A document that says “terminate for convenience” will not be found by searching “cancel the contract” right now. Finding a document by what it means is temporarily unavailable; it comes back on its own, and there is nothing to retry.',
    description:
      'Second line, shown when semantic retrieval was reachable but is not right now — present tense, about the system, and explicitly no remedy, because retrying a fallback that already returned real results teaches a user the product is broken. Replace the quoted example as above.',
  },
  'search.result.locationPage': {
    message: 'p.{page}',
    description:
      'Where in a document the match sits, when only a page number is known. Abbreviate as your language abbreviates “page”; the value is a number.',
  },
  'search.result.locationPageSection': {
    message: 'p.{page} · {section}',
    description:
      'Where in a document the match sits. "section" is the document’s own section path (“3.2 Topology”) and is never translated. Reorder the two parts if your language reads them the other way.',
  },
  'search.result.noExcerpt': {
    message: 'No matching passage to show',
    description:
      'Shown in place of a result’s excerpt when the API returned none. This is normal rather than a fault (docs/05 §11): a metadata-only caller gets no excerpt, and the lexical path emits none when it cannot locate the matched term. Never phrase it as an error or as content being withheld.',
  },
  'search.state.new.title': {
    message: 'Search everything you can open',
    description:
      'Heading of the empty state before anything has been searched (docs/09 §11, “empty (new)”).',
  },
  'search.state.new.body': {
    message:
      'Files and the words inside them — by name, by who changed them, by workspace, file type or classification. Start typing in the field above.',
    description:
      'Body of the empty (new) state. Says what the surface is for and names the one action that starts it, which is typing in the field directly above.',
  },
  'search.state.loading': {
    message: 'Searching',
    description:
      'Announced while the skeleton rows are on screen. The skeletons themselves are decorative.',
  },
  'search.state.noResults.title': {
    message: 'No results for “{query}”',
    description:
      'Heading of the empty state when a query returned nothing. "query" is the user’s own text, quoted verbatim.',
  },
  'search.state.noResults.advice': {
    message: 'Check the spelling, or search for fewer words.',
    description:
      'Body of the no-results state when no filters are active and the search matched on meaning as well as on words.',
  },
  'search.state.noResults.lexicalAdvice': {
    message:
      'This search matched the words you typed rather than what they mean, so try the words the document itself would use — and check the spelling.',
    description:
      'Body of the no-results state when retrieval was word-matching only. It repeats the point the degraded-search header makes, because this is the moment the user is actually stuck.',
  },
  'search.state.noResults.filtered': {
    message:
      '{count, plural, =0 {Nothing matches this search, with or without the filters below.} one {# result matches this search without the filters below.} other {# results match this search without the filters below.}}',
    description:
      'Body of the no-results state when filters are active. "count" is how many results the same query returns unfiltered — the number that separates “the filters are too narrow” from “this query finds nothing”, which are different problems with different fixes.',
  },
  'search.state.noResults.filterList': {
    message: 'Filters applied to this search',
    description:
      'Accessible name of the list of active filters on the no-results state, so a screen-reader user hears which filters are narrowing the query.',
  },
  'search.state.noResults.clearFilters': {
    message: 'Clear filters',
    description: 'Action on the no-results state. Restores the same query with no filters.',
  },
  'search.state.error.title': {
    message: 'This search could not be run',
    description:
      'Heading of the fetch-error state. Says what failed, not why — the reason belongs with the request ID a support agent can look up.',
  },
  'search.state.error.body': {
    message:
      'The request did not complete. Nothing has changed, and no results are being withheld from you.',
    description:
      'Body of the retryable fetch-error state. The second clause is load-bearing: this state must never be mistaken for a policy denial, which is a successful request with a refusing answer and looks completely different (docs/09 §11).',
  },
  'search.state.error.bodyFinal': {
    message: 'The request cannot be retried from here. Contact support with the request ID below.',
    description: 'Body of the fetch-error state when the failure is not retryable.',
  },
  'search.state.error.retry': {
    message: 'Try again',
    description:
      'Retry action on the fetch-error state. Present only when the failure is retryable, and never on a policy denial or on the degraded-search header.',
  },

  /* ------------------------------------------------------------------ admin
   *
   * `docs/14 §4`: keys are namespaced and stable, never derived from English
   * text, and every one carries a description. The hard case on this surface is
   * the policy-as-a-sentence builder: a sentence assembled from fragments around
   * its controls is exactly the concatenation `§4` forbids, so each clause is
   * **one** ICU message and its controls arrive as placeholders. A translator
   * moves `{categories}` wherever their language wants it and the chips follow.
   */

  'admin.nav.label': {
    message: 'Administration sections',
    description: 'Accessible name of the 200px section rail on the admin screen.',
  },
  'admin.nav.security': {
    message: 'Security',
    description:
      'Heading of the security group in the admin rail, and the first step of the breadcrumb above the policy.',
  },
  'admin.nav.detectors': {
    message: 'Detectors',
    description:
      'Heading of the detectors group in the admin rail. A detector is what finds sensitive data in a file; a policy decides what happens next.',
  },
  'admin.nav.dlp': {
    message: 'Data loss prevention',
    description:
      'Rail entry and breadcrumb step for the DLP surface. Spelled out rather than abbreviated because the abbreviation is English-specific.',
  },
  'admin.nav.conditionalAccess': {
    message: 'Conditional access',
    description: 'Rail entry for the conditional-access surface, which this release does not have.',
  },
  'admin.nav.classification': {
    message: 'Classification',
    description:
      'Rail entry for the classification surface, which this release does not have. The scheme of sensitivity labels, not one file’s label.',
  },
  'admin.nav.barriers': {
    message: 'Information barriers',
    description: 'Rail entry for the ethical-wall surface, which this release does not have.',
  },
  'admin.nav.incidents': {
    message: 'Incidents',
    description: 'Rail entry for the DLP incident queue, which this release does not have.',
  },
  'admin.nav.detectorsBuiltIn': {
    message: 'Built-in detectors',
    description: 'Rail entry for the detectors shipped with the product. Not in this release.',
  },
  'admin.nav.detectorsCustom': {
    message: 'Custom detectors',
    description: 'Rail entry for detectors a tenant defines itself. Not in this release.',
  },
  'admin.crumb.label': {
    message: 'Breadcrumb',
    description: 'Accessible name of the trail above the policy title.',
  },

  'admin.dlp.pageTitle': {
    message: 'Data loss prevention',
    description:
      'The page heading of the DLP policy screen. Same words as the rail entry, different context: this one is an H1 and may be translated differently.',
  },
  'admin.dlp.rules.title': {
    message: 'Policies',
    description: 'Heading above the list of this tenant’s DLP policies in the admin rail.',
  },
  'admin.dlp.rules.searchLabel': {
    message: 'Search policies',
    description:
      'Accessible name and placeholder of the box that narrows the policy list. Used for both, so it must read as a label and as a prompt.',
  },
  'admin.dlp.rules.decodeError': {
    message: 'Cannot be decoded',
    description:
      'Marker beside a stored policy the evaluator can no longer read. Such a policy fails every request in the tenant until it is withdrawn, so it is called out rather than listed silently.',
  },
  'admin.dlp.status.draft': {
    message: 'Draft',
    description:
      'State of a policy that has never been written to the server. It refuses nothing and nobody is affected by it yet.',
  },
  'admin.dlp.status.inForce': {
    message: 'In force',
    description: 'State of a policy the policy chain is evaluating on every request.',
  },
  'admin.dlp.modeNote': {
    message:
      'Whether DLP records, warns or refuses is configured once for the whole tenant. It is not a setting on this policy.',
    description:
      'Sentence under the policy heading. It exists because administrators expect a per-policy simulate/enforce switch and there is none; a switch that was accepted and ignored would be an administrator believing a policy rehearses while it decides.',
  },
  'admin.auditor.pill': {
    message: 'Auditor',
    description:
      'Marker shown when the screen is rendered for a read-only auditor. Describes the viewer’s role, not a restriction placed on them.',
  },
  'admin.auditor.note': {
    message: 'You are seeing the same screen without its editing controls.',
    description:
      'Sentence shown in read-only auditor mode. Present tense and about the viewer, because it is about what they can do rather than about the product’s roadmap.',
  },

  'admin.dlp.band.identity': {
    message: 'This policy',
    description: 'Band heading above the policy’s name and evaluation priority.',
  },
  'admin.dlp.band.when': {
    message: 'When',
    description:
      'Band heading above the conditions. First word of the sentence the builder composes; the clauses beneath finish it.',
  },
  'admin.dlp.band.whenHint': {
    message: 'all of these are true',
    description:
      'Hint beside the "When" band heading. It says the clauses are joined by AND, which is why no conjunction is drawn between them.',
  },
  'admin.dlp.band.then': {
    message: 'Then',
    description: 'Band heading above the effect and what a refused person is told.',
  },
  'admin.dlp.band.where': {
    message: 'Where',
    description: 'Band heading above the policy’s reach across the tenant.',
  },

  'admin.dlp.clause.name': {
    message: 'It is called {name}.',
    description:
      'Identity clause of the policy sentence. "name" is a text field the administrator types in, rendered inline in the sentence.',
  },
  'admin.dlp.clause.priority': {
    message: 'It is evaluated at priority {priority}.',
    description:
      'Identity clause. "priority" is a number field rendered inline. Priority decides which reason code a refused person sees when two policies refuse, not whether a policy fires.',
  },
  'admin.dlp.clause.classification': {
    message: 'The file is classified {level} or higher.',
    description:
      'Condition clause. "level" is the sensitivity-threshold control rendered inline as a badge in the locked classification colour.',
  },
  'admin.dlp.clause.categories': {
    message: 'The file contains {categories}.',
    description:
      'Condition clause. "categories" is a list of detector-category chips joined by the locale’s own "or". Never a matched value — a category is a term, a match is a secret.',
  },
  'admin.dlp.clause.scope': {
    message: 'The attempted action is {actions}.',
    description:
      'Condition clause. "actions" is a list of governed-action chips joined by the locale’s own "or".',
  },
  'admin.dlp.clause.effect': {
    message: 'The effect is {effect}.',
    description: 'Effect clause. "effect" is the control that chooses what the policy does.',
  },
  'admin.dlp.clause.reason': {
    message: 'The person is told the reason code {code} and the sentence below.',
    description:
      'Effect clause. "code" is a stable machine-readable code such as DLP_BLOCKED and is never translated.',
  },
  'admin.dlp.clause.noRefusal': {
    message: 'This effect changes the request rather than refusing it, so nobody is turned away.',
    description:
      'Replaces the reason-code clause when the chosen effect does not refuse anything — a watermark, a read-only session, an audit record.',
  },
  'admin.dlp.clause.messageUnbuilt': {
    message: 'Wording written for this policy, instead of the wording keyed to the reason code',
    description:
      'A builder clause the product does not have yet. Future tense and about the product; it must never read as a refusal aimed at this administrator, and it offers no remedy because there is nothing they can do.',
  },
  'admin.dlp.clause.obligationsUnbuilt': {
    message: 'Extra effects on the same policy, such as notifying security or opening an incident',
    description:
      'A builder clause the product does not have yet. Future tense, about the product, no remedy.',
  },
  'admin.dlp.clause.whereUnbuilt': {
    message: 'Narrowing a policy to particular workspaces or libraries, or excepting one',
    description:
      'A builder clause the product does not have yet. Future tense, about the product, no remedy.',
  },

  'admin.dlp.chip.nameLabel': {
    message: 'Policy name',
    description: 'Accessible name of the text field inside the identity clause.',
  },
  'admin.dlp.chip.priorityLabel': {
    message: 'Evaluation priority',
    description: 'Accessible name of the number field inside the identity clause.',
  },
  'admin.dlp.chip.classificationLabel': {
    message: 'Classification threshold',
    description: 'Accessible name of the sensitivity-level control inside the condition clause.',
  },
  'admin.dlp.chip.effectLabel': {
    message: 'What this policy does',
    description: 'Accessible name of the effect control inside the effect clause.',
  },
  'admin.dlp.chip.addCategory': {
    message: 'Add a detector category',
    description:
      'Accessible name and visible label of the control that adds a category to the condition clause.',
  },
  'admin.dlp.chip.addScope': {
    message: 'Add an action to govern',
    description:
      'Accessible name and visible label of the control that adds a governed action to the condition clause.',
  },
  'admin.dlp.chip.removeCategory': {
    message: 'Remove {category}',
    description:
      'Accessible name of the × on a detector-category chip. "category" is the already-translated category term.',
  },
  'admin.dlp.chip.removeScope': {
    message: 'Remove {action}',
    description:
      'Accessible name of the × on a governed-action chip. "action" is the already-translated action term.',
  },

  'admin.dlp.category.paymentCard': {
    message: 'payment card numbers',
    description:
      'Detector category. Lower case because it reads inside a sentence ("The file contains payment card numbers"). It names a kind of data and never a value.',
  },
  'admin.dlp.category.aadhaar': {
    message: 'Aadhaar numbers',
    description:
      'Detector category: the Indian national identity number. Names the kind, never a value.',
  },
  'admin.dlp.category.apiKey': {
    message: 'API keys',
    description: 'Detector category. Names the kind, never a value.',
  },
  'admin.dlp.category.bankAccount': {
    message: 'bank account numbers',
    description: 'Detector category. Names the kind, never a value.',
  },
  'admin.dlp.category.healthId': {
    message: 'health identifiers',
    description: 'Detector category. Names the kind, never a value.',
  },
  'admin.dlp.category.credential': {
    message: 'credentials',
    description:
      'Detector category covering passwords and secrets found in a document. Names the kind, never a value.',
  },

  'admin.dlp.scope.externalSharing': {
    message: 'external sharing',
    description:
      'A governed action: sharing a file with somebody outside the organisation. Lower case because it reads inside a sentence.',
  },
  'admin.dlp.scope.publicLink': {
    message: 'a public link',
    description: 'A governed action: creating a link anybody with the URL can open.',
  },
  'admin.dlp.scope.download': {
    message: 'download',
    description:
      'A governed action. Download, preview, print, export and sync are five different permissions and are never collapsed into one.',
  },
  'admin.dlp.scope.export': {
    message: 'export',
    description: 'A governed action: taking the content out in another format.',
  },
  'admin.dlp.scope.print': {
    message: 'print',
    description: 'A governed action.',
  },
  'admin.dlp.scope.sync': {
    message: 'sync to a device',
    description: 'A governed action: keeping a local copy on a desktop or phone.',
  },
  'admin.dlp.scope.exposesContent': {
    message: 'anything that exposes content',
    description:
      'A governed action covering every surface that lets content leave. Broader than the named ones and used when a tenant wants the widest reach.',
  },

  'admin.dlp.action.block': {
    message: 'Block',
    description: 'Policy effect: refuse the attempt outright.',
  },
  'admin.dlp.action.quarantine': {
    message: 'Quarantine',
    description: 'Policy effect: refuse the attempt and hold the file for review.',
  },
  'admin.dlp.action.warn': {
    message: 'Warn',
    description: 'Policy effect: let the attempt through, having told the person what was found.',
  },
  'admin.dlp.action.audit': {
    message: 'Audit',
    description: 'Policy effect: let the attempt through and record it.',
  },
  'admin.dlp.action.requireJustification': {
    message: 'Require a justification',
    description: 'Policy effect: let the attempt through once a reason has been recorded.',
  },
  'admin.dlp.action.requireApproval': {
    message: 'Require approval',
    description: 'Policy effect: hold the attempt until somebody else approves it.',
  },
  'admin.dlp.action.noDownload': {
    message: 'Prevent download',
    description: 'Policy effect: allow preview but not a copy of the original.',
  },
  'admin.dlp.action.readOnly': {
    message: 'Make read-only',
    description: 'Policy effect: allow viewing but not editing.',
  },
  'admin.dlp.action.watermark': {
    message: 'Watermark',
    description: 'Policy effect: stamp the viewer’s identity across the rendition.',
  },
  'admin.dlp.action.notifySecurity': {
    message: 'Notify security',
    description: 'Policy effect: alert the security team and let the attempt through.',
  },
  'admin.dlp.action.removeShare': {
    message: 'Remove the share',
    description: 'Policy effect: withdraw the sharing link or grant that carried the file out.',
  },

  'admin.dlp.denial.blocked.message': {
    message: 'This action is not permitted on this file.',
    description:
      'What a refused person is shown for the reason code DLP_BLOCKED. Says nothing about which policy matched, its conditions or its thresholds — that is a leak, not a courtesy.',
  },
  'admin.dlp.denial.blocked.remediation': {
    message:
      'Ask the file’s owner to share it another way, or request an exception from your security administrator.',
    description: 'The one remedy offered with DLP_BLOCKED. An action the person can actually take.',
  },
  'admin.dlp.denial.justification.message': {
    message: 'This action needs a reason recorded before it can go ahead.',
    description: 'What a person is shown for the reason code DLP_JUSTIFICATION_REQUIRED.',
  },
  'admin.dlp.denial.justification.remediation': {
    message: 'Enter why you need it. Your reason is recorded in the audit log.',
    description:
      'The remedy for DLP_JUSTIFICATION_REQUIRED. It says plainly that the reason is recorded, because collecting one quietly is worse than refusing.',
  },
  'admin.dlp.denial.approval.message': {
    message: 'This action needs an approval before it can go ahead.',
    description: 'What a person is shown for the reason code DLP_APPROVAL_REQUIRED.',
  },
  'admin.dlp.denial.approval.remediation': {
    message: 'Send it for approval, or ask your security administrator.',
    description: 'The remedy for DLP_APPROVAL_REQUIRED.',
  },

  'admin.dlp.preview.title': {
    message: 'What a refused person sees',
    description:
      'Heading of the panel that previews the denial this policy would produce. Shown to the administrator writing the policy, not to the refused person.',
  },
  'admin.dlp.preview.codeLabel': {
    message: 'Reason code',
    description: 'Label before the stable machine-readable code in the denial preview.',
  },
  'admin.dlp.preview.none': {
    message:
      'This effect changes the request rather than refusing it, so nobody is shown a denial.',
    description: 'Replaces the denial preview when the chosen effect refuses nothing.',
  },
  'admin.dlp.preview.note': {
    message:
      'A denial names a stable code, a sentence and one remedy. It never names this policy, its conditions or its thresholds.',
    description:
      'Sentence under the denial preview. It states the rule the preview obeys, so an administrator does not go looking for a field to add the policy name to.',
  },

  'admin.dlp.sim.heading': {
    message: 'Simulation',
    description: 'Heading of the section that rehearses the policy against recent activity.',
  },
  'admin.dlp.sim.title': {
    message: 'Rehearsed against the last {days, plural, one {# day} other {# days}}',
    description: 'Heading of the results. "days" is the length of the window the rehearsal covered.',
  },
  'admin.dlp.sim.ranAt': {
    message: 'Run {when}',
    description:
      'Timestamp beside the results. "when" is an already-formatted relative time; the absolute time is in the tooltip.',
  },
  'admin.dlp.sim.run': {
    message: 'Test against the last {days, plural, one {# day} other {# days}}',
    description:
      'Action that starts the rehearsal. "days" is the window, currently 30. Shown on a policy that has never been rehearsed.',
  },
  'admin.dlp.sim.rerun': {
    message: 'Run it again',
    description: 'Action that repeats the rehearsal, after an edit or to refresh the window.',
  },
  'admin.dlp.sim.running': {
    message: 'Rehearsing this policy against recent activity',
    description: 'Announced while the results are being computed and the skeleton is on screen.',
  },
  'admin.dlp.sim.stale': {
    message:
      'This rehearsal describes the policy as it was before your last edit. Run it again before putting it in force.',
    description:
      'Shown when the policy changed after being rehearsed. A result that no longer describes the policy on screen is worse than no result.',
  },
  'admin.dlp.sim.empty.title': {
    message: 'Not rehearsed yet',
    description: 'Heading shown before a policy has ever been simulated.',
  },
  'admin.dlp.sim.empty.body': {
    message:
      'A policy that refuses anything is never put in force before it has been rehearsed against real activity.',
    description: 'Body shown before a policy has ever been simulated. Says why the step exists.',
  },
  'admin.dlp.sim.stat.wouldRefuse': {
    message: 'Attempts it would have refused',
    description:
      'Label of the headline number: how often this policy would have turned somebody away.',
  },
  'admin.dlp.sim.stat.attempts': {
    message: 'Attempts it would have matched',
    description:
      'Label of the number of attempts whose conditions matched, refused or not. Larger than the refused count for a non-blocking effect.',
  },
  'admin.dlp.sim.stat.people': {
    message: 'People affected',
    description: 'Label of the count of distinct people who would have met this policy.',
  },
  'admin.dlp.sim.stat.files': {
    message: 'Files involved',
    description: 'Label of the count of distinct files that would have matched.',
  },
  'admin.dlp.sim.blastRadius': {
    message:
      'This affects {files, plural, one {# file} other {# files}} across {libraries, plural, one {# library} other {# libraries}}.',
    description:
      'The reach of the policy, stated before it is applied rather than after. One message with two plural categories, never a count glued to a noun.',
  },
  'admin.dlp.sim.byWorkspace': {
    message: 'Would refuse, by workspace',
    description: 'Heading of the breakdown of refusals across workspaces.',
  },
  'admin.dlp.sim.barRow': {
    message:
      '{workspace} — {count, plural, one {# attempt} other {# attempts}} refused. That is {share, number, percent} of everything matched.',
    description:
      'The spoken form of one bar in the breakdown, for screen readers. "workspace" is a name, "count" the refusals there, "share" a fraction between 0 and 1.',
  },
  'admin.dlp.sim.events': {
    message: 'Sample events',
    description: 'Heading of the list of individual attempts the rehearsal would have refused.',
  },
  'admin.dlp.sim.event': {
    message: '{person} attempted {action} on {resource}.',
    description:
      'One rehearsed attempt. "person" is a display name, "action" an already-translated governed action, "resource" a document title. The document’s contents never appear.',
  },
  'admin.dlp.sim.eventCategories': {
    message: 'Detected: {categories}.',
    description:
      'What the detectors found in that attempt. "categories" is a list of category terms joined by the locale’s own "and" — the kinds of data, never the data.',
  },
  'admin.dlp.sim.noValues': {
    message:
      'Detector categories only. A matched value is never shown here, exported, or written to the audit log.',
    description:
      'Sentence under the sample events. It tells an administrator not to go looking for the matched values, because their absence is deliberate rather than a gap.',
  },

  'admin.dlp.diff.title': {
    message: 'Field-level diff',
    description: 'Heading of the panel comparing the policy in force with the edited one.',
  },
  'admin.dlp.diff.field': {
    message: 'Field',
    description: 'Column header of the diff: which part of the policy the row is about.',
  },
  'admin.dlp.diff.before': {
    message: 'In force now',
    description: 'Column header of the diff: the value the policy chain is using today.',
  },
  'admin.dlp.diff.after': {
    message: 'After this change',
    description: 'Column header of the diff: the value it would use once the change is in force.',
  },
  'admin.dlp.diff.unset': {
    message: 'Not set',
    description:
      'Stands in for a field with no value. Distinct from an empty list, which would mean something different.',
  },
  'admin.dlp.diff.newPolicy': {
    message: 'This policy has never been written, so every field is an addition.',
    description: 'Shown above the diff when there is nothing to compare against.',
  },
  'admin.dlp.diff.changedCount': {
    message:
      '{count, plural, =0 {No field differs from the policy in force.} one {# field differs from the policy in force.} other {# fields differ from the policy in force.}}',
    description: 'Summary above the diff. "count" is how many rows changed.',
  },
  'admin.dlp.diff.makerCheckerUnbuilt': {
    message: 'A second administrator approving the change before it takes effect',
    description:
      'A step the product does not have yet. Future tense, about the product, no remedy — never the treatment used when policy has refused this administrator something.',
  },
  'admin.dlp.diff.confirm': {
    message: 'I have read every row above.',
    description:
      'Label of the confirmation the administrator must tick before the policy can be put in force. First person, because they are the one asserting it.',
  },
  'admin.dlp.field.name': {
    message: 'Name',
    description: 'Diff row: the policy’s name, which is also its identity to the evaluator.',
  },
  'admin.dlp.field.priority': {
    message: 'Priority',
    description: 'Diff row: the evaluation priority.',
  },
  'admin.dlp.field.scope': {
    message: 'Actions governed',
    description: 'Diff row: which attempts this policy has anything to say about.',
  },
  'admin.dlp.field.classification': {
    message: 'Classification threshold',
    description: 'Diff row: the sensitivity level at or above which the policy applies.',
  },
  'admin.dlp.field.categories': {
    message: 'Detector categories',
    description: 'Diff row: the kinds of sensitive data the policy looks for.',
  },
  'admin.dlp.field.action': {
    message: 'Effect',
    description: 'Diff row: what the policy does when it matches.',
  },

  'admin.dlp.gate.title': {
    message: 'Before this policy can be put in force',
    description:
      'Heading of the checklist of remaining steps. It is a path with steps left in it, not a refusal.',
  },
  'admin.dlp.gate.simulate': {
    message: 'Rehearse it against recent activity',
    description: 'Checklist step: run the simulation.',
  },
  'admin.dlp.gate.simulateWhy': {
    message: 'A policy that refuses anything is never enforced before it has been simulated.',
    description: 'Why the simulation step exists, shown beneath it.',
  },
  'admin.dlp.gate.simulateOptional': {
    message: 'This effect refuses nothing, so a rehearsal is not required for it.',
    description:
      'Replaces the reason under the simulation step when the chosen effect does not refuse. The step is then already satisfied.',
  },
  'admin.dlp.gate.diff': {
    message: 'Read the field-level diff and confirm it',
    description: 'Checklist step: tick the confirmation under the diff.',
  },
  'admin.dlp.gate.diffWhy': {
    message: 'A security-sensitive change is confirmed field by field, not in summary.',
    description: 'Why the diff step exists, shown beneath it.',
  },
  'admin.dlp.gate.stepUp': {
    message: 'Re-authenticate with a second factor',
    description:
      'Checklist step the product does not have yet. Future tense, about the product, no remedy.',
  },
  'admin.dlp.gate.stepUpWhy': {
    message:
      'Writing a DLP policy is a privileged operation and needs recent multi-factor authentication.',
    description: 'Why the step-up step exists, shown beneath it.',
  },
  'admin.dlp.gate.done': {
    message: 'Done',
    description: 'Status of a checklist step that is satisfied.',
  },
  'admin.dlp.gate.outstanding': {
    message: 'Outstanding',
    description:
      'Status of a checklist step still to do. Neutral: nothing has been refused, the step simply has not happened.',
  },
  'admin.dlp.commit.putInForce': {
    message: 'Put this policy in force',
    description:
      'The action that would write the policy and start the policy chain evaluating it. Named for what it does rather than "Save", because a saved policy here begins refusing people.',
  },

  'admin.dlp.json.title': {
    message: 'The same policy, as it is stored',
    description: 'Heading of the JSON view, for power users and for copying between tenants.',
  },
  'admin.dlp.json.note': {
    message:
      'The vocabulary the policy chain decodes. It follows the builder above; it is not a second place to edit.',
    description:
      'Sentence under the JSON heading. Says the view is read-only and why, so nobody looks for a save button.',
  },
  'admin.dlp.json.label': {
    message: 'The stored policy, as JSON',
    description:
      'Accessible name of the scrollable JSON block, which is focusable so it can be scrolled by keyboard.',
  },

  'admin.state.loading': {
    message: 'Loading policies',
    description:
      'Announced while the policy skeleton is on screen. The skeleton itself is decorative.',
  },
  'admin.state.empty.title': {
    message: 'No DLP policies yet',
    description: 'Heading of the empty state for a tenant that has never written a DLP policy.',
  },
  'admin.state.empty.body': {
    message:
      'A policy decides what happens when a file holding sensitive data is shared, downloaded or exported. Write the first one.',
    description:
      'Body of the empty state. Says what the surface is for and names the one action that starts it.',
  },
  'admin.state.empty.action': {
    message: 'New policy',
    description:
      'Primary action on the empty state, and the accessible name of the + beside the policy list.',
  },
  'admin.state.filtered.title': {
    message: 'No policies match this search',
    description: 'Heading of the empty state when the search box excludes everything.',
  },
  'admin.state.filtered.body': {
    message:
      '{count, plural, one {# policy is hidden by the search.} other {# policies are hidden by the search.}}',
    description:
      'Body of the filtered-empty state. "count" is how many policies exist unfiltered, so an over-narrow search reads differently from a tenant with none.',
  },
  'admin.state.filtered.action': {
    message: 'Clear the search',
    description: 'Action on the filtered-empty state. Restores the whole list.',
  },
  'admin.state.error.title': {
    message: 'These policies could not be loaded',
    description: 'Heading of the fetch-error state. Says what failed, not why.',
  },
  'admin.state.error.body': {
    message: 'The request did not complete. Nothing has changed.',
    description: 'Body of the retryable fetch-error state. A failed read changed nothing.',
  },
  'admin.state.error.bodyFinal': {
    message: 'The request cannot be retried from here. Contact support with the request ID below.',
    description: 'Body of the fetch-error state when the failure is not retryable.',
  },
  'admin.state.error.retry': {
    message: 'Try again',
    description:
      'Retry action on the fetch-error state. Present only when the failure is retryable, and never on a refusal.',
  },
  'admin.state.fixture': {
    message: 'Review fixture',
    description:
      'Marker shown when the screen is rendering sample data because no server answered. It must never be mistaken for a tenant’s real policies.',
  },
  'admin.state.fixtureNote': {
    message: 'No gateway is answering, so these are sample policies rather than this tenant’s.',
    description: 'Sentence beside the review-fixture marker, saying why the data is not real.',
  },

  /* ------------------------------------------------------------- the picker */

  'library.picker.title': {
    message: 'Choose a library',
    description:
      'Heading over the workspace/library chooser shown when no library is open. Neutral instruction, not a question.',
  },
  'library.picker.noLibraries': {
    message: 'No libraries in this workspace.',
    description:
      'Shown under a workspace whose library listing came back empty. A statement of fact, not an error and not a refusal.',
  },
  'library.picker.external': {
    message: 'External sharing',
    description:
      'Tag on a library whose settings permit sharing outside the tenant. A property of the container, not a warning.',
  },
  'library.picker.empty.title': {
    message: 'No workspaces yet',
    description:
      'Empty (new) state of the library picker: the viewer belongs to no workspace. Not an error — the request succeeded and the answer was none.',
  },
  'library.picker.empty.body': {
    message: 'Workspaces hold the libraries your team files work in. An administrator can add you to one.',
    description:
      'Body of the picker’s empty state: says what the surface is for and who can change the situation.',
  },

  /* ------------------------------------------------------------- the upload */

  /* `library.upload.denied` was here, and it is gone rather than kept
   * (`ENC-674`). It was the client's own sentence for a refusal the server had
   * not explained — honest at the time, because it restated the boolean and
   * claimed no cause, but it was still one screen's private wording for a fact
   * every screen has to state. The reason now arrives as a code and is phrased
   * by `denial.*` above, so keeping this key would be a second answer to the
   * same question, differing by surface. */
  'upload.dropHere': {
    message: 'Drop files to upload',
    description: 'Overlay shown over the file list while files are dragged over it.',
  },
  'upload.queue.label': {
    message: 'Files being uploaded',
    description:
      'Accessible name of the list of in-flight uploads shown above the file grid.',
  },
  'upload.tray.label': {
    message: 'Uploads',
    description: 'Accessible name of the floating upload tray.',
  },
  'upload.tray.active': {
    message:
      '{active, plural, one {# file uploading} other {# files uploading}} of {total, plural, one {# file} other {# files}}',
    description:
      'Aggregate progress in the upload tray header. A count rather than a percentage: summing per-file fractions implies a total that a growing queue does not have.',
  },
  'upload.tray.done': {
    message: '{total, plural, one {# upload} other {# uploads}}',
    description: 'Upload tray header once nothing is still in flight.',
  },
  'upload.tray.hide': {
    message: 'Hide uploads',
    description: 'Accessible name of the button that collapses the upload tray.',
  },
  'upload.clearDone': {
    message: 'Clear finished',
    description: 'Removes settled rows from the upload tray. Does not delete any file.',
  },
  'upload.cancel': {
    message: 'Cancel',
    description: 'Stops an upload that is still running and releases its staged bytes.',
  },
  'upload.retry': {
    message: 'Try again',
    description:
      'Retries a failed transfer. Shown only for a failure — never for a policy refusal, which retrying cannot change (docs/17 §7).',
  },
  'upload.dismiss': {
    message: 'Dismiss',
    description: 'Removes one settled row from the upload tray.',
  },

  'upload.step.up': {
    message: 'Up',
    description:
      'First of the three progress dots drawn on an uploading row, abbreviating “Uploading”. The full phase name is what a screen reader is given.',
  },
  'upload.step.scan': {
    message: 'Scan',
    description: 'Second progress dot: the file is being scanned and processed.',
  },
  'upload.step.index': {
    message: 'Index',
    description: 'Third progress dot: the file is being indexed for search.',
  },

  'upload.phase.queued': {
    message: 'Queued',
    description: 'Upload phase: waiting to start.',
  },
  'upload.phase.hashing': {
    message: 'Checking',
    description:
      'Upload phase: the client is reading the file and computing its SHA-256 before anything is sent. Its own phase because a large file spends real time here and a row that looked stalled would be untrue.',
  },
  'upload.phase.uploading': {
    message: 'Uploading',
    description: 'Upload phase: bytes are being sent to object storage.',
  },
  'upload.phase.scanning': {
    message: 'Scanning',
    description:
      'Upload phase: the bytes are stored and antivirus has not cleared them. Nothing is readable in this phase (CLAUDE.md rule 9).',
  },
  'upload.phase.processing': {
    message: 'Processing',
    description: 'Upload phase: renditions and text extraction are running.',
  },
  'upload.phase.indexing': {
    message: 'Indexing',
    description: 'Upload phase: the content is being added to the search index.',
  },
  'upload.phase.ready': {
    message: 'Ready',
    description:
      'Upload phase: the server reports the version readable. Reached only when isReadable is true — never inferred from status alone.',
  },
  'upload.phase.quarantined': {
    message: 'Quarantined',
    description:
      'Upload phase: the scanner refused the content, or refused to admit it unscanned. Terminal, and a statement about the file rather than about the user.',
  },
  'upload.phase.failed': {
    message: 'Failed',
    description: 'Upload phase: the transfer or one of its calls did not complete.',
  },
  'upload.phase.aborted': {
    message: 'Cancelled',
    description: 'Upload phase: the user stopped it. Neutral — not an error.',
  },
  'upload.phase.refused': {
    message: 'Not permitted',
    description:
      'Upload phase: the policy chain refused the upload. Neutral, never the failure treatment, and carries no retry (docs/17 §7).',
  },

  'upload.note.unscanned': {
    message: 'Published, but no scanner inspected it — it cannot be opened yet.',
    description:
      'Shown on a version whose status is AVAILABLE but whose av_status is SKIPPED. AVAILABLE means published, not scanned, and SKIPPED is not CLEAN — so the file is deliberately not served (CLAUDE.md rule 9).',
  },
  'upload.note.scanError': {
    message: 'The scanner could not read this file, so it cannot be opened.',
    description: 'Shown on a version whose av_status is ERROR.',
  },
  'upload.note.awaitingScan': {
    message: 'Waiting for a scan before it can be opened.',
    description: 'Shown on a published version that is not yet readable for any other reason.',
  },

  /* -------------------------------------------------------- the preview tab */

  'library.peek.preview.denied': {
    message: 'You do not have permission to preview this file.',
    description:
      'Shown on the Preview tab when the server’s capabilities report preview=false. Says only that; `capabilities` carries no reason yet (ENC-674) and the client must not invent one.',
  },
  'library.peek.preview.noVersion': {
    message: 'This file has no version to preview.',
    description: 'Shown when the versions listing came back empty.',
  },
  'library.peek.preview.unscanned': {
    message: 'No scanner has inspected this file, so its contents are not served.',
    description:
      'Preview tab, version published but av_status SKIPPED. The honest sentence for the 404 the delivery route answers — not “not found”, because the file plainly exists.',
  },
  'library.peek.preview.quarantined': {
    message: 'This file was quarantined, so its contents are not served.',
    description: 'Preview tab, version QUARANTINED.',
  },
  'library.peek.preview.scanning': {
    message: 'This file is still being scanned.',
    description: 'Preview tab, version PENDING or SCANNING.',
  },
  'library.peek.preview.noRenderer': {
    message: 'No preview for this file type yet',
    description:
      'Preview tab heading when the file is readable but this deployment renders only PNG, JPEG and WebP. Unbuilt, not denied and not failed: nobody was refused and nothing broke.',
  },
  'library.peek.preview.noRenderer.note': {
    message: 'This deployment renders images only. Other formats need the document renderer.',
    description: 'Release note behind the unbuilt Preview state, naming the actual blocker.',
  },
} as const satisfies Record<string, CatalogEntry>;

export type MessageKey = keyof typeof catalog;

/** The shape `react-intl` wants: key to ICU string, descriptions dropped. */
export function messagesFor(source: typeof catalog): Record<string, string> {
  return Object.fromEntries(Object.entries(source).map(([key, entry]) => [key, entry.message]));
}

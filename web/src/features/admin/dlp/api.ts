import { request } from '../../../shared/api/client.ts';
import { DlpRuleList } from './model.ts';

/* The one endpoint on this screen that is actually specified.
 *
 * `docs/05 §14.2`: the path is `/admin/dlp/**rules**`, not the `policies` the
 * map in §14 lists — `04-DATA-MODEL.md §12.3` records which documented columns
 * were deliberately not created, and a path naming a resource whose fields are
 * ignored is a path an operator tunes in vain. It is spelled out here rather
 * than guessed, because a made-up path is a 404 nobody notices until integration.
 *
 * `GET` returns the whole live set and needs no cursor loop: the same set is
 * loaded on every request in the policy chain, so it is small by construction
 * and `page.hasMore` is always `false`.
 *
 * **Reading does not require step-up; writing does.** So there is no `create`
 * or `withdraw` here. `docs/05 §14.2`: "Writing and withdrawing require recent
 * multi-factor authentication", and the step-up flow does not exist yet — which
 * makes the write path *unbuilt*, not denied, and the screen says so with the
 * neutral treatment rather than the denial one (`docs/17 §6`). Shipping a
 * `createDlpRule()` that cannot complete would be the same lie one layer down.
 */

export const DLP_RULES_PATH = '/admin/dlp/rules';

export const dlpRulesQueryKey = ['admin', 'dlp', 'rules'] as const;

export async function fetchDlpRules(signal: AbortSignal): Promise<DlpRuleList> {
  return request(DLP_RULES_PATH, DlpRuleList, { signal });
}

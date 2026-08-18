import type { AccessDecision, AccessRequest } from '../access-control/AccessPolicy';
import { AccessGate } from '../access-control/AccessGate';

/**
 * Authentication adapters should call this before issuing or accepting a session.
 * A denied decision must terminate the authentication flow.
 */
export async function authorizeAuthentication(
  gate: AccessGate,
  request: AccessRequest,
): Promise<AccessDecision> {
  return gate.evaluateAsync(request);
}

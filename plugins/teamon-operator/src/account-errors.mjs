// Only product-owned codes cross the MCP/browser boundary, never upstream prose.
const definitions = {
  account_login_required: ['login', false, 'account_login_open'],
  account_access_denied: ['authorization', false, 'contact_administrator'],
  account_service_unavailable: ['account_discovery', true, 'installation_status'],
  invalid_account_response: ['account_discovery', false, 'contact_administrator'],
  account_response_too_large: ['account_discovery', false, 'contact_administrator'],
  unsafe_account_session: ['local_session', false, 'contact_administrator'],
  account_changed: ['identity', false, 'new_operator_chat'],
  account_reconnect_required: ['identity', false, 'new_operator_chat'],
  not_configured: ['login', false, 'account_login_open'],
};
export function accountErrorCode(error) {
  return Object.hasOwn(definitions,error?.message) ? error.message : 'account_service_unavailable';
}
export function accountErrorDetails(code) {
  const [stage,retryable,next_action]=definitions[code] || definitions.account_service_unavailable;
  return {code,stage,retryable,next_action,checked_at:new Date().toISOString()};
}
export const ACCOUNT_ERROR_CODES=Object.freeze(Object.keys(definitions));

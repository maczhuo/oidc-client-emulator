export class OIDCEmulatorError extends Error {
  constructor(public readonly code: string, message: string) {
    super(message);
    this.name = 'OIDCEmulatorError';
  }
}

export class AuthorizationResponseError extends OIDCEmulatorError {
  constructor(public readonly oauthError: string) {
    // Do not reflect provider-controlled descriptions or URLs into logs.
    super('AUTHORIZATION_DENIED', 'The provider returned an authorization error.');
    this.name = 'AuthorizationResponseError';
  }
}

/**
 * Exception hierarchy mirroring swarmauth/exceptions.py. Every class here
 * carries a stable `code` matching SPEC.md §7's protocol-level error codes
 * -- the class name itself is this SDK's choice, not the spec's; a verifier
 * in another language should key off `code`, not the TypeScript class name.
 */

export abstract class SwarmAuthError extends Error {
  abstract readonly code: string;

  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

export class MalformedTokenError extends SwarmAuthError {
  readonly code = "MALFORMED_TOKEN";
}

export class InvalidSignatureError extends SwarmAuthError {
  readonly code = "INVALID_SIGNATURE";
}

export class TokenExpiredError extends SwarmAuthError {
  readonly code = "TOKEN_EXPIRED";
}

export class TokenNotYetValidError extends SwarmAuthError {
  readonly code = "TOKEN_NOT_YET_VALID";
}

export class TokenRevokedError extends SwarmAuthError {
  readonly code = "TOKEN_REVOKED";
}

export class AudienceMismatchError extends SwarmAuthError {
  readonly code = "AUDIENCE_MISMATCH";
}

export class UnknownIssuerError extends SwarmAuthError {
  readonly code = "UNKNOWN_ISSUER";
}

export class CapabilityViolationError extends SwarmAuthError {
  readonly code = "CAPABILITY_VIOLATION";
  constructor(
    message: string,
    readonly required?: string,
    readonly granted: readonly string[] = [],
  ) {
    super(message);
  }
}

export class ConstraintViolationError extends SwarmAuthError {
  readonly code = "CONSTRAINT_VIOLATION";
  constructor(
    message: string,
    readonly constraint?: string,
  ) {
    super(message);
  }
}

export { KeyPair, verifySignature } from "./crypto.js";
export {
  ALG,
  MAX_TTL_SECONDS,
  TOKEN_TYPE,
  buildToken,
  checkCapability,
  checkParams,
  issue,
  parse,
  verify,
} from "./token.js";
export type { CapabilityClaims, Constraints, IssueOptions, NormalizedConstraints, ParsedToken, VerifyOptions } from "./token.js";
export {
  AudienceMismatchError,
  CapabilityViolationError,
  ConstraintViolationError,
  DelegationError,
  InvalidSignatureError,
  MalformedTokenError,
  SwarmAuthError,
  TokenExpiredError,
  TokenNotYetValidError,
  TokenRevokedError,
  UnknownIssuerError,
} from "./errors.js";
export { b64urlDecode, b64urlEncode } from "./base64.js";

export { KeyRegistry, InMemoryRevocationStore, type RevocationStore } from "./registry.js";
export { attenuate, type AttenuateOptions, MAX_LEEWAY_SECONDS } from "./token.js";

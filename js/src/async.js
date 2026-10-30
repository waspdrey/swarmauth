import { parse, verifyAndCheck, SwarmAuthError, currentToken, useToken } from "./index.js";

/** Await every network check and reservation before returning authorization. */
export async function asyncVerifyAndCheck(token, options = {}) {
  let claims, reservation;
  const capture = {
    requiresChain: Boolean(options.tracker?.requiresChain),
    supportsSharedBudgets: Boolean(options.tracker?.supportsSharedBudgets),
    checkAndRecord(item, amount) { reservation = { chain: [item], amount }; },
    checkAndRecordChain(chain, amount) { reservation = { chain, amount }; },
  };
  try {
    claims = verifyAndCheck(token, { ...options, revocationStore: undefined, onDecision: undefined,
      tracker: options.tracker ? capture : undefined });
    const chain = claims.prf ? [parse(claims.prf).claims, claims] : [claims];
    if (options.revocationStore) {
      for (const item of chain) {
        if (await options.revocationStore.isRevoked(item.jti)) {
          throw new SwarmAuthError("TOKEN_REVOKED", `Token '${item.jti}' has been revoked`);
        }
      }
    }
    if (options.tracker) {
      if (reservation.chain.length > 1) {
        if (typeof options.tracker.checkAndRecordChain !== "function") {
          throw new SwarmAuthError("CONSTRAINT_VIOLATION", "Delegated limits require atomic chain accounting");
        }
        await options.tracker.checkAndRecordChain(reservation.chain, reservation.amount);
      } else await options.tracker.checkAndRecord(claims, reservation.amount);
    }
  } catch (error) {
    if (error instanceof SwarmAuthError && options.onDecision) await options.onDecision({ decision: "denied",
      code: error.code, issuer: claims?.iss ?? null, audience: options.audience ?? null,
      capability: options.requiredCapability ?? null, tokenId: claims?.jti ?? null });
    throw error;
  }
  if (options.onDecision) await options.onDecision({ decision: "allowed", code: null, issuer: claims.iss,
    audience: claims.sub, capability: options.requiredCapability ?? null, tokenId: claims.jti });
  return claims;
}

export function asyncGuard(fn, options) {
  return async (args = {}) => {
    const token = args.token || currentToken();
    if (!token) {
      if (options.onDecision) await options.onDecision({ decision: "denied", code: "CAPABILITY_VIOLATION",
        issuer: null, audience: options.audience ?? options.capability, capability: options.capability, tokenId: null });
      throw new SwarmAuthError("CAPABILITY_VIOLATION", "No JCT supplied");
    }
    const params = { ...args };
    delete params.token;
    await asyncVerifyAndCheck(token, { ...options, audience: options.audience ?? options.capability,
      requiredCapability: options.capability, params, amount: options.amountArg ? params[options.amountArg] : undefined });
    return fn(params);
  };
}

/** Express-compatible propagation. Endpoints must still use guard/asyncGuard.
 * Express is intentionally not a runtime dependency. */
export function tokenContextMiddleware({ maxTokenBytes = 65536 } = {}) {
  if (!Number.isSafeInteger(maxTokenBytes) || maxTokenBytes < 1) throw new RangeError("Invalid maxTokenBytes");
  return (req, res, next) => {
    const headers = req.rawHeaders ?? [];
    const credentials = [];
    for (let index = 0; index < headers.length; index += 2) {
      if (headers[index].toLowerCase() === "authorization") credentials.push(headers[index + 1]);
    }
    const header = credentials.length === 1 ? credentials[0] : null;
    const match = typeof header === "string" ? /^Bearer ([A-Za-z0-9_.-]+)$/i.exec(header) : null;
    if (!match || Buffer.byteLength(match[1]) > maxTokenBytes) {
      res.setHeader("WWW-Authenticate", "Bearer");
      res.status(401).json({ error: "invalid_bearer_credential" });
      return;
    }
    // useToken keeps asynchronous descendants isolated across requests.
    useToken(match[1], next);
  };
}

import { createHash } from "node:crypto";
import { addAmounts, amountExceeds, RETENTION_AFTER_EXP_SECONDS, SwarmAuthError } from "./index.js";

const deny = (message) => { throw new SwarmAuthError("CONSTRAINT_VIOLATION", message); };
const safe = (value) => Number.isSafeInteger(value) && value >= 0;

export class BudgetRule {
  constructor({ id, issuers, currency, maxAmountMinor, expiresAt, maxCalls = null }) {
    if (typeof id !== "string" || !id || !Array.isArray(issuers) || !issuers.length ||
      !issuers.every((issuer) => typeof issuer === "string" && issuer) || typeof currency !== "string" || !/^[A-Z]{3}$/.test(currency) ||
      !safe(maxAmountMinor) || !safe(expiresAt) || expiresAt === 0 ||
      (maxCalls !== null && (!safe(maxCalls) || maxCalls === 0))) throw new TypeError("Invalid budget rule");
    Object.assign(this, { id, issuers: Object.freeze([...issuers]), currency, maxAmountMinor, expiresAt, maxCalls });
    Object.freeze(this);
  }
}

export class BudgetUsageTracker {
  constructor(rules = [], { requireBudget = true } = {}) {
    this.rules = new Map(rules.map((rule) => [rule.id, new BudgetRule(rule)]));
    if (this.rules.size !== rules.length) throw new TypeError("Budget ids must be unique");
    this.requireBudget = requireBudget;
    this.requiresChain = true;
    this.supportsSharedBudgets = true;
    this.entries = new Map();
  }

  records(chain, now) {
    if (!chain.length || new Set(chain.map((item) => item.jti)).size !== chain.length) deny("Token ids must be distinct");
    const records = chain.map((claims) => {
      if (now >= claims.exp + RETENTION_AFTER_EXP_SECONDS) throw new SwarmAuthError("TOKEN_EXPIRED", "Token expired before reservation");
      return { key: JSON.stringify(["token", claims.jti]), expiry: claims.exp + RETENTION_AFTER_EXP_SECONDS,
        maxCalls: claims.constraints.max_calls, maxUsd: claims.constraints.max_amount_usd,
        rate: claims.constraints.rate_limit_per_min, minor: 0 };
    });
    const pins = chain.at(-1).constraints.allowed_params;
    const budgetId = chain.at(-1).constraints.shared_budget;
    if (budgetId == null && !this.requireBudget) return records;
    const rule = this.rules.get(budgetId);
    if (!rule) deny("Token must pin a configured budget_id");
    if (!rule.issuers.includes(chain[0].iss)) deny("Issuer cannot charge this budget");
    if (now >= rule.expiresAt) deny("Shared budget expired");
    if (!safe(pins.amount_minor)) deny("Token must pin a non-negative safe integer amount_minor");
    if (pins.currency !== rule.currency) deny("Token currency does not match shared budget");
    records.push({ key: JSON.stringify(["budget", rule.id]), expiry: rule.expiresAt,
      maxCalls: rule.maxCalls, minorLimit: rule.maxAmountMinor, minor: pins.amount_minor });
    return records;
  }

  pending(record, current, now, amount) {
    const calls = (current.calls ?? 0) + 1;
    const usd = addAmounts(current.usd ?? "0", amount);
    const minor = (current.minor ?? 0) + record.minor;
    const recent = (current.timestamps ?? []).filter((stamp) => stamp >= now - 60);
    if (record.maxCalls != null && calls > record.maxCalls) deny("Call allowance exhausted");
    if (record.maxUsd != null && amountExceeds(usd, record.maxUsd)) deny("Token USD allowance exhausted");
    if (record.rate != null && recent.length + 1 > record.rate) deny("Token rate allowance exhausted");
    if (record.minorLimit != null && minor > record.minorLimit) deny("Shared currency budget exhausted");
    return { calls, usd, minor, timestamps: record.rate != null ? [...recent, now] : [], expiry: record.expiry };
  }

  checkAndRecord(claims, amount = 0) { return this.checkAndRecordChain([claims], amount); }
  checkAndRecordChain(chain, amount = 0) {
    if (typeof amount !== "number" || !Number.isFinite(amount) || amount < 0) deny("Invalid amount");
    const now = Date.now() / 1000;
    const records = this.records(chain, now);
    const pending = records.map((record) => [record.key, this.pending(record, this.entries.get(record.key) ?? {}, now, amount)]);
    for (const [key, entry] of this.entries) if (entry.expiry <= now) this.entries.delete(key);
    for (const [key, entry] of pending) this.entries.set(key, entry);
  }
}

/** Native async node-redis backend. Pass a connected createClientPool() pool.
 * Every reservation owns an isolated connection for WATCH/MULTI/EXEC.
 * No redis dependency is loaded by SwarmAuth. Use asyncGuard, not guard.
 */
export class RedisUsageTracker {
  constructor(pool, { rules = [], requireBudget = false, keyPrefix = "swarmauth:ledger:", maxRetries = 64 } = {}) {
    if (typeof pool.execute !== "function" || !Number.isSafeInteger(maxRetries) || maxRetries < 1) {
      throw new TypeError("RedisUsageTracker requires a client pool and positive maxRetries");
    }
    this.pool = pool;
    this.ledger = new BudgetUsageTracker(rules, { requireBudget });
    this.keyPrefix = keyPrefix;
    this.maxRetries = maxRetries;
    this.requiresChain = true;
    this.supportsSharedBudgets = true;
  }
  checkAndRecord(claims, amount = 0) { return this.checkAndRecordChain([claims], amount); }
  async checkAndRecordChain(chain, amount = 0) {
    if (typeof amount !== "number" || !Number.isFinite(amount) || amount < 0) deny("Invalid amount");
    return this.pool.execute(async (client) => {
      try {
        for (let attempt = 0; attempt < this.maxRetries; attempt++) {
          try {
            let now = Date.now() / 1000;
            let records = this.ledger.records(chain, now);
            const keys = records.map((record) => this.keyPrefix + createHash("sha256").update(record.key).digest("hex"));
            await client.watch(keys);
            const current = await client.mGet(keys);
            now = Date.now() / 1000;
            records = this.ledger.records(chain, now);
            const pending = records.map((record, index) => this.ledger.pending(record, JSON.parse(current[index] ?? "{}"), now, amount));
            const transaction = client.multi();
            records.forEach((record, index) => transaction.set(keys[index], JSON.stringify(pending[index]),
              { PX: Math.max(1, Math.ceil((record.expiry - now) * 1000)) }));
            await transaction.exec();
            return;
          } catch (error) {
            if (error.name === "WatchError" || error.constructor.name === "WatchError") continue;
            throw error;
          }
        }
        deny("Shared ledger contention exceeded retry limit");
      } finally { await client.unwatch(); }
    });
  }
}

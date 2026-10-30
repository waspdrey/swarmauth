"""Cross-runtime accounting against one live Redis database (CI integration)."""
import json
import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from swarmauth import BudgetRule, CapabilityToken, Constraints, ConstraintViolationError, KeyPair, RedisBudgetUsageTracker
from swarmauth.middleware import verify_and_check

ROOT = Path(__file__).resolve().parent.parent
URL = os.environ.get("SWARMAUTH_TEST_REDIS_URL")


@pytest.mark.skipif(not URL or not shutil.which("node") or not (ROOT / "js/node_modules/redis").exists(),
                    reason="Requires live Redis and npm ci in js/")
def test_python_and_node_share_budget_and_token_counters():
    import redis
    client = redis.Redis.from_url(URL)
    keys = KeyPair.generate()
    rule = BudgetRule("task-unicode-药", ("issuer",), "GHS", 100, int(time.time()) + 3600)
    prefix = "swarmauth:interop:" + os.urandom(8).hex() + ":"
    tracker = RedisBudgetUsageTracker(client, [rule], key_prefix=prefix)

    def credential(amount):
        params = {"budget_id": rule.id, "currency": "GHS", "amount_minor": amount}
        token = CapabilityToken.issue(issuer_keypair=keys, iss="issuer", sub="tool:x", capabilities=["tool:x"],
                                      constraints=Constraints(max_calls=1, shared_budget=rule.id, allowed_params=params),
                                      ttl_seconds=30)
        return token, params

    first, params = credential(60)
    verify_and_check(first, issuer_public_key=keys.public_bytes, tracker=tracker, params=params)
    rejected, rejected_params = credential(50)
    last, last_params = credential(40)
    program = """
import { readFileSync } from 'node:fs';
import { createClientPool } from 'redis';
import { RedisUsageTracker, asyncVerifyAndCheck } from './src/index.js';
const data=JSON.parse(readFileSync(0,'utf8'));
const pool=createClientPool({url:process.env.SWARMAUTH_TEST_REDIS_URL,
  socket:{reconnectStrategy:false,connectTimeout:2000}});
pool.on('error',()=>{});await pool.connect();
try {
 const tracker=new RedisUsageTracker(pool,{keyPrefix:data.prefix,requireBudget:true,rules:[data.rule]});
 const outcomes=[];
 for(const request of data.requests) {
   try {
     await asyncVerifyAndCheck(request.token,{publicKey:Buffer.from(data.publicKey,'hex'),tracker,params:request.params});
     outcomes.push('allowed');
   }
   catch(error){outcomes.push(error.code);}
 }
 process.stdout.write(JSON.stringify(outcomes));
} finally {await pool.close();}
"""
    data = {"prefix": prefix, "publicKey": keys.public_bytes.hex(),
            "rule": {"id": rule.id, "issuers": list(rule.issuers), "currency": rule.currency,
                     "maxAmountMinor": rule.max_amount_minor, "expiresAt": rule.expires_at},
            "requests": [{"token": first, "params": params}, {"token": rejected, "params": rejected_params},
                         {"token": last, "params": last_params}]}
    try:
        result = subprocess.run(["node", "--input-type=module", "-e", program], input=json.dumps(data),
                                text=True, capture_output=True, cwd=ROOT / "js", check=True, timeout=20)
        assert json.loads(result.stdout) == ["CONSTRAINT_VIOLATION", "CONSTRAINT_VIOLATION", "allowed"]
        final, final_params = credential(1)
        with pytest.raises(ConstraintViolationError):
            verify_and_check(final, issuer_public_key=keys.public_bytes, tracker=tracker, params=final_params)
    finally:
        for key in client.scan_iter(prefix + "*"):
            client.delete(key)

# SwarmAuth design-partner pilot

## Who we want

Platform, security, or infrastructure teams operating AI agents that can take
one or more consequential actions:

- issue refunds or payments;
- modify production infrastructure;
- export or mutate customer data;
- update regulated or business-critical records.

The team should have a real workflow, an owner for the agent runtime, and a
security stakeholder who can evaluate authorization evidence.

## Pilot promise

In one working session, protect one high-risk tool call so that:

1. the model never sees or supplies the authorization token;
2. unauthorized capabilities are denied at execution time;
3. limits such as amount, parameters, calls, and expiry are enforced;
4. every allow/deny decision is attributable and exportable;
5. key revocation stops a compromised agent without code changes.
6. high-stakes actions can pause for a named human reviewer and resume only
   after an authenticated approval.

## Integration shape

- Python or TypeScript agent/tool runtime; Python uses the SDK directly and
  TypeScript uses the matching `@swarmauth/core` token verifier at its own
  execution boundary;
- MCP or ordinary HTTP tool transport;
- existing OAuth/OIDC provider remains the identity source;
- SwarmAuth is the action-authorization and execution-boundary layer;
- local SQLite control plane for the pilot, with no production data required.

## Four-week pilot plan

### Week 1 — map the action

- Select one tool and its highest-impact failure mode.
- Record current credentials, scopes, callers, and audit trail.
- Define the allowed capability, audience, parameters, and limits.
- Establish a baseline: current integration time and current audit fields.

### Week 2 — integrate the boundary

- Register the agent and tool.
- Add the OAuth-to-JCT adapter.
- Wrap the tool with `secure_mcp_tool` or `secure_tool_call`.
- Connect a decision sink and local viewer.
- Add an approval gate for one action class and deliver reviews through Slack,
  email, or the team's existing webhook channel.

### Week 3 — attack and operate

- Run prompt-injection and forged-token scenarios.
- Test expiry, replay, revocation, key rotation, and concurrency.
- Measure latency and false denials under normal traffic.

### Week 4 — review value

- Compare blocked unauthorized actions with the baseline.
- Review whether an operator can explain every decision.
- Estimate prevented-loss, review-time reduction, and integration cost.
- Decide whether to proceed to a paid control-plane pilot.

## Scorecard

| Metric | Target | Evidence |
| --- | --- | --- |
| Time to protect first tool | ≤ 1 working day | engineer log |
| Unauthorized action blocked | 100% of test cases | adversarial test report |
| Token exposure in model schema | 0 occurrences | schema snapshot |
| Decision completeness | 100% of decisions have outcome, actor, tool, and capability; JTI is present whenever a token was supplied | decision export |
| Revocation response | next request denied without code deployment | incident test |
| Added authorization latency | p95 < 10 ms excluding network calls | benchmark |
| False denials | 0 in agreed happy-path suite | replayed workload |
| Operator investigation time | < 10 minutes for a sampled denial | timed exercise |
| Human review latency | p95 < 5 minutes during agreed working hours | approval event export |
| Approval attribution | 100% of resolved requests have an authenticated reviewer | approval store |
| Customer willingness to continue | named owner and paid next step | pilot review |

## Interview questions

1. Which agent actions would create a material incident if misused?
2. Where is authorization decided today, and where is it actually enforced?
3. Can you identify the human, agent, tool, and policy behind one past action?
4. What would security need to approve autonomous execution in production?
5. Which systems must integrate before this can be deployed?
6. Would you buy an SDK, a hosted control plane, a self-hosted service, or a combination?

## Do not claim yet

The current pilot core is not a production multi-tenant service. Before a paid
production deployment, it needs authenticated API access, tenant isolation,
RBAC, durable migrations/backups, encrypted transport, operational monitoring,
and an independent security review.

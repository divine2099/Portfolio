# Findings report — BattleChain Confidence Pools

Cyfrin / CodeHawks · Solidity / EVM · commit `58e8ba4`.

Reachability and call-chain synthesis over the nine model batches, filtered through the privilege map
(auth gates) and the threat model. Every candidate below was traced backward from the value-moving or
state-mutating function to a concrete entrypoint, and each auth gate on the path was verified against
source. The honest disposition: **1 BROKEN (Low), 2 UNCERTAIN (contingent Low/Info), 76 HOLDS.** The
codebase is well built. There is no unconditional externally-profitable fund drain. The one
externally-realizable loss is a timing-triggered bonus misdirection (Low); the rest are
privileged-config or trusted-role hazards that are in-model per the protocol's own design docs, surfaced
here with their exact reach. This is the zero-submit result I stand behind: I kept the ledger instead
of dressing a weak chain up as a win.

Trust boundary (fixed): registry singleton out of model; moderator and factory owner are the protocol
DAO, modeled as compromised-key roles only to bound blast radius.

Target-specific tags: `[RISK-WINDOW]` (registry-observation latch machine), `[K2-ACCUM]` (k=2
time-weighted accumulator), `[SNAPSHOT]` (snapshot-vs-live divergence), `[BRANCH-CONFUSION]`
(outcome-branch selection), `[SWEEP-RESERVE]` (sweep reservation math), `[CENTRALIZATION]` (in-model DAO
power surfaced for completeness).

---

## Externally Exploitable Vulnerabilities

Reachable by an unauthenticated attacker or by any role any user can hold (staker, bonus contributor,
permissionless resolver/sweeper/poker). Value verdict stated per finding.

### `registry_observation_risk_window-EXT-1` — Unobserved active-risk window zeroes all staker bonus, silently redirecting `snapshotTotalBonus` to `recoveryAddress`

- **Entry point (loss realization):** `ConfidencePool.sol:474` `sweepUnclaimedBonus()` (permissionless,
  `nonReentrant` only). Resolution reached via either `ConfidencePool.sol:512` `claimExpired()`
  (permissionless) or `:322` `flagOutcome()` (moderator).
- **Call-chain trace:**
  1. Registry goes UNDER_ATTACK, then advances UNDER_ATTACK → PROMOTION_REQUESTED → PRODUCTION purely by
     elapsed time (`AttackRegistry._getAgreementState` has time-only edges, no tx), with zero pool
     interaction during the active-risk interval. No `stake`/`contributeBonus`/`withdraw`/
     `pokeRiskWindow`/`flagOutcome` fires while active-risk is live.
  2. First observation is therefore terminal. `_observePoolState():784` → `:793`
     `riskWindowStart == 0 && _isActiveRiskState(state)` is false (state is terminal), so
     `_markRiskWindowStart()` never runs; `:796` seals `riskWindowEnd` only. `riskWindowStart` stays `0`
     forever (one-way latch, never back-dated).
  3. Resolution snapshots (`flagOutcome:357-360` or `claimExpired:524-527`) freeze
     `snapshotTotalBonus = totalBonus` with `riskWindowStart == 0`.
  4. Every staker's `_bonusShare():699` returns `0` (`if (riskWindowStart == 0) return 0`). Stakers get
     principal back but zero bonus.
  5. `sweepUnclaimedBonus():483-488`: because `riskWindowStart == 0`, `reserved` holds back only
     principal (`totalEligibleStake`) and treats the entire `snapshotTotalBonus` as unreserved; `:492`
     `amount = freeBalance - reserved`; `:506` `safeTransfer(recoveryAddress, amount)`. The whole bonus
     lands at the sponsor's `recoveryAddress`.
- **Auth gates traversed:** none that stop it. `sweepUnclaimedBonus` gate = `outcome ∈ {SURVIVED,
  EXPIRED}` (`:475`), satisfied. `claimExpired` gate = `block.timestamp ≥ expiry` (`:513`), satisfied
  post-term. The only mitigation, `pokeRiskWindow()` (`:649`, permissionless), must be called during the
  active-risk interval by someone, and no party is economically forced to, since poking earns the caller
  nothing.
- **Reachability & verdict:** reachable, no privilege required. Realized entirely through no-auth
  entrypoints and by the passage of time; harms untrusted stakers. The beneficiary is the sponsor
  (`recoveryAddress`), so it is not an attacker-profit drain, but a malicious or passive sponsor is
  incentivized to not poke and let the window pass unobserved, which is costless. The loss to stakers is
  real and has no retroactive fix (`riskWindowStart` cannot be set after resolution).
- **Severity:** Low. Bonus (not principal) only; design-adjacent ("no observable risk, no bonus") but the
  loss is genuine and purely timing-triggered rather than a stated policy for unobserved-but-real risk.
- **Tags:** `[ORACLE]` (registry + `block.timestamp` observation timing), `[RISK-WINDOW]`,
  `[SWEEP-RESERVE]`, `[SNAPSHOT]`.
- **Recommendation:** on a terminal-without-start observation, back-date `riskWindowStart` from the
  registry's own risk-window timestamps; or prominently document that stakers must ensure
  `pokeRiskWindow` is called during active-risk to earn any bonus.

> No other externally-reachable finding survived tracing. Every deposit/withdraw/claim/sweep/bounty path
> (models 5-9) is `nonReentrant` with state writes before the single transfer, CEI-clean, and its
> conservation identities hold. Sybil deposit-splitting is amount-linear; the eager-reset vs lazy-clamp
> seam is consistent because `stake` clamps-before-add and `withdraw` only completes while
> `riskWindowStart == 0`. The permissionless overflow-brick is externally triggerable but requires a
> privileged token-allowlist precondition, filed under Privileged-Only below.

---

## Privileged-Only Configuration Risks

Require a privileged role (factory owner, or the deployer) to enable. Some have a permissionless trigger
once the privileged precondition is set, noted per finding.

### `bonus_math_k2-PRIV-1` — Absurd-supply allowlisted token overflow-bricks observation, resolution, and claims (funds trapped)

- **Entry point (privileged enabler):** `ConfidencePoolFactory.sol:155` `setStakeTokenAllowed(token,
  true)` (`onlyOwner`). Trigger entrypoints (permissionless, post-allowlist): `ConfidencePool.sol:222`
  `stake` (whale), and any of `:382 claimSurvived` / `:512 claimExpired` / observation-driven resolution.
- **Call-chain trace:**
  1. Owner allowlists a token with astronomical supply (`~1e40+` at 18dp). `createPool` accepts it
     (`Factory:77` allowlist check passes by construction).
  2. A whale (permissionless) stakes so `totalEligibleStake > ~6.4e57` base units.
  3. Observation path: `_observePoolState():793` → `_markRiskWindowStart():814-815` computes
     `sumStakeTimeSq = totalEligibleStake * t * t` in checked arithmetic → overflow revert. This reverts
     `_observePoolState`, called from every pre-resolution gated entrypoint (`stake:227`, `withdraw:290`,
     `flagOutcome:328`, `claimExpired:523`, `pokeRiskWindow`), bricking resolution and trapping all
     staked funds.
  4. Independently, claim path: `_bonusShare():704,708` computes `T * T * userEligible` and
     `T * T * snapshotTotalStaked` as plain uint256 multiplies (not `mulDiv`) → overflow revert inside
     `claimSurvived`/`claimExpired`, stranding the claimant.
- **Auth gates traversed:** privileged `onlyOwner` allowlist gate (`Factory:155`) is the load-bearing
  precondition; downstream trigger has no gate beyond ordinary staking.
- **Reachability & verdict:** contingent. Not reachable against a normal-supply ERC20; the owner-curated
  allowlist is the enforcement point and admitting such a token is the owner's error. Once admitted, the
  brick is permissionlessly triggerable and permanent.
- **Severity:** Low / Informational (contingent on a governance mis-allowlist; overflow threshold vs
  plausible token supply routed to fuzz).
- **Tags:** `[K2-ACCUM]`, `[TOKEN-ASSUMPTION]`, `[DOS]`, `[ROUNDING]` (widen-then-multiply boundary).
- **Recommendation:** cap accepted supply or bound `totalEligibleStake` at stake time, or use
  `mulDiv`-style 512-bit intermediates for the `T²·stake` terms; assert the overflow boundary under fuzz.

### `factory_clone_deployment-PRIV-1` — `setSafeHarborRegistry` repoints registry for every live pool (sole factory lever reaching deployed clones)

- **Entry point:** `ConfidencePoolFactory.sol:128` `setSafeHarborRegistry()` (`onlyOwner`).
- **Call-chain trace:** pool reads the registry live, never cached: `_getAgreementState():741`
  `safeHarborRegistry.getAttackRegistry()`. Unlike `poolImplementation` / `defaultOutcomeModerator`
  (snapshotted per-clone at init, future-only), the registry pointer is resolved fresh each observation.
  Repointing it changes the observed `ContractState` feeding `_observePoolState` for all live pools at
  once → shifts risk-window latches, resolution branch (`claimExpired:532/557/561`), and outcome
  compatibility (`flagOutcome:338/347`).
- **Auth gates traversed:** `onlyOwner` (single gate).
- **Reachability & verdict:** privileged only. Not reachable by an unprivileged attacker. In-model: a
  malicious registry equals "trusted DAO attacking its own infra." Surfaced because it is the one factory
  setter with reach into already-deployed clones, worth an explicit integrator note that pool safety is
  only as good as the current registry pointer.
- **Severity:** Informational (`[CENTRALIZATION]`, in-model).
- **Tags:** `[ORACLE]`, `[RISK-WINDOW]`, `[CENTRALIZATION]`.

### `factory_clone_deployment-PRIV-2` — Factory UUPS upgrade rewrites all factory logic; no in-code timelock

- **Entry point:** `ConfidencePoolFactory.sol:174` `_authorizeUpgrade()` (`onlyOwner`, empty body) via
  `upgradeToAndCall`.
- **Call-chain trace:** owner upgrades the factory implementation → arbitrary future factory logic (new
  `createPool`, allowlist, moderator/registry pointers). Cannot reach existing pool-clone funds (clones
  are non-upgradeable EIP-1167; `setPoolImplementation:137` is future-clone-only). Storage-gap discipline
  (`__gap[45]`, `:40`) is convention-only: a future upgrade appending a var without decrementing `__gap`
  silently collides (not machine-enforced).
- **Auth gates traversed:** `onlyOwner`.
- **Reachability & verdict:** privileged only, no fund reach into live clones. In-model DAO power.
- **Severity:** Informational (`[CENTRALIZATION]`); storage-gap is an upgrade-hygiene watch-item.
- **Tags:** `[PROXY]` `[EVM]`, `[CENTRALIZATION]`.

### `factory_clone_deployment-PRIV-3` — Non-atomic proxy deploy/init lets an attacker front-run factory `initialize` and seize UUPS authority + all pointers

- **Entry point:** `ConfidencePoolFactory.sol:50` `initialize()` (`initializer` one-shot).
- **Call-chain trace:** the in-scope deploy (`script/Deploy.s.sol:31-33`) constructs `ERC1967Proxy` with
  the `initialize` calldata as `_data`, so deploy+init are atomic, no mempool window. Only if a future
  deployer split deploy and init across two txs could an attacker front-run `initialize` to become owner
  (UUPS upgrade authority) and set registry/impl/moderator pointers. Impl `_disableInitializers()`
  (`:45-47`) protects the logic contract itself.
- **Auth gates traversed:** `initializer` (one-shot), bypassed only by being first, which the atomic
  deploy forecloses.
- **Reachability & verdict:** not reachable as shipped (atomic deploy). Reachable only under a non-atomic
  deployment variant, a deployment-hygiene landmine, not a code bug.
- **Severity:** Informational (deployment hygiene).
- **Tags:** `[PROXY]` `[EVM]`.

---

## Trusted Role Operational Risks

Reachable while a trusted role (moderator, sponsor/owner) performs a normal, sanctioned action. All
in-model per the design docs; surfaced with exact blast radius.

### `outcome_resolution_finality-TRUSTED-1` — Moderator mis-flag is irreversibly locked by the first claimant

- **Entry point:** moderator `flagOutcome():322` (`onlyModerator`); lock via any permissionless claimant
  `claimSurvived():382`.
- **Call-chain trace:** moderator flags SURVIVED on a pool whose in-scope contract was actually CORRUPTED
  (an off-chain judgement error; `flagOutcome` is not scope-gated by design, `:330-340` accepts CORRUPTED
  registry for SURVIVED). The first `claimSurvived` sets `claimsStarted = true` (`:402`); thereafter
  `flagOutcome:327` reverts `OutcomeAlreadySet`. The moderator can no longer correct the error, and that
  first claimant drew principal + bonus on a pool that should have swept to recovery.
- **Auth gates traversed:** `onlyModerator` (flag) then no gate (first claim). Re-flag window closes on
  `claimsStarted`, value-movement finality, not front-runnable.
- **Reachability & verdict:** requires the trusted moderator to make an error during a sanctioned flag;
  then any staker locks it. In-model (trusted-DAO moderator), an operational hazard, not an attacker
  capability.
- **Severity:** Informational / accepted (blast-radius note).
- **Tags:** `[BRANCH-CONFUSION]`, `[CENTRALIZATION]`.

### `factory_clone_deployment-TRUSTED-1` — Moderator is immutable and un-rotatable; a lost/compromised key degrades every live pool at once

- **Entry point:** none, the absence of any `outcomeModerator` setter (grep-confirmed; written once at
  pool `initialize:207`).
- **Call-chain trace:** `outcomeModerator` is snapshotted from the factory's `defaultOutcomeModerator` at
  clone init and has no setter. A compromised/lost moderator key cannot be rotated on any existing pool,
  and factory setters (`setDefaultOutcomeModerator:146`) affect future clones only. Blast radius of a
  single key compromise = every currently-live pool. Mitigation floor: pools still auto-resolve via
  permissionless `claimExpired` after `expiry` (+180d grace for CORRUPTED), so a hostile/absent moderator
  can stall but not steal, it degrades pools to the timing backstop.
- **Auth gates traversed:** n/a (structural).
- **Reachability & verdict:** operational limitation; in-model. No factory lever can rescue or worsen a
  live clone's moderator.
- **Severity:** Informational (`[CENTRALIZATION]`, blast-radius note).
- **Tags:** `[CENTRALIZATION]`.

### `pool_config_sponsor_controls-TRUSTED-1` — Sponsor can retarget `recoveryAddress` up to sweep execution (bounded: own entitlement only)

- **Entry point:** `ConfidencePool.sol:611` `setRecoveryAddress()` (`onlyOwner`, no phase gate);
  front-runs a pending `claimCorrupted():408` / `sweepUnclaimedCorrupted():456` / `sweepUnclaimedBonus():474`.
- **Call-chain trace:** sweeps read `recoveryAddress` live at `:423/:468/:506`; there is no gate
  preventing `setRecoveryAddress` after resolution. The sponsor (or an ordering attacker) can redirect
  the destination right before the sweep lands. But that destination only ever receives the sponsor's own
  entitlement: bad-faith CORRUPTED remainder or SURVIVED/EXPIRED excess. It cannot touch the attacker
  bounty (paid to `attacker`, `:449`) or staker principal (returned to stakers). No cross-party theft.
- **Auth gates traversed:** `onlyOwner`. Bounded by which funds the destination can receive.
- **Reachability & verdict:** in-model sponsor trust surface. Behavioral note for integrators: resolution
  does not pin the payout destination.
- **Severity:** Informational / accepted.
- **Tags:** `[SNAPSHOT]`, `[CENTRALIZATION]`.

### `survived_expired_claims-TRUSTED-1` — `sweepUnclaimedBonus` does not finalize the outcome; moderator may still re-flag SURVIVED→CORRUPTED afterward

- **Entry point:** `sweepUnclaimedBonus():474` (permissionless) then `flagOutcome():322` (moderator).
- **Call-chain trace:** `sweepUnclaimedBonus:503-505` deliberately omits `claimsStarted = true`
  (donation-grief defense: a 1-wei direct transfer would otherwise let anyone flip the latch and block
  the moderator's pre-claim re-flag window). Consequence: after a bonus/dust sweep, if the registry is
  CORRUPTED the moderator can still re-flag SURVIVED→CORRUPTED (`flagOutcome:347` requires registry
  CORRUPTED, a legitimate correction) and route the remaining balance to recovery. The prior sweep took
  only genuine excess (principal + owed bonus reserved, `:482-492`), so no wei is paid twice, but "a
  sweep happened" is not "outcome is final."
- **Auth gates traversed:** none on sweep; `onlyModerator` + registry-CORRUPTED on the re-flag.
- **Reachability & verdict:** in-model behavioral note; no double-pay. Integrators must not treat a
  completed bonus sweep as outcome finality.
- **Severity:** Informational (behavioral).
- **Tags:** `[SWEEP-RESERVE]`, `[BRANCH-CONFUSION]`.

### `pool_config_sponsor_controls-TRUSTED-2` — Agreement-owner sponsor picks pool params at `createPool` (bounded: on-chain-visible opt-in)

- **Entry point:** `ConfidencePoolFactory.sol:67` `createPool()` (`whenNotPaused` +
  `IAgreement(agreement).owner() == msg.sender`).
- **Call-chain trace:** any address that is `IAgreement(agreement).owner()` may create a pool for that
  agreement with an allowlisted token, choosing `recoveryAddress` / scope / `expiry` / `minStake` (all
  validated non-degenerate at `initialize:179-202`). A malicious agreement owner can pick sponsor-favorable
  params, but stakers opt in against on-chain-visible parameters, and post-stake latches (`expiryLocked`,
  `scopeLocked`) foreclose moving them under committed stakers.
- **Auth gates traversed:** factory pause + agreement-owner equality; then pool init validation.
- **Reachability & verdict:** in-model bounded sponsor trust. No lever escapes the documented bound onto
  already-committed principal.
- **Severity:** Informational / accepted.
- **Tags:** `[CENTRALIZATION]`.

---

## Cross-cutting Summary

Priority order (highest expected value first):

**Externally exploitable**
- `registry_observation_risk_window-EXT-1` — Low, the only BROKEN property. Unobserved active-risk window
  (registry traverses risk → terminal by time with zero pool interaction) leaves `riskWindowStart == 0`;
  every `_bonusShare` returns 0 and the whole `snapshotTotalBonus` sweeps to `recoveryAddress` via
  permissionless `sweepUnclaimedBonus`. Timing-triggered, no privilege, no retroactive fix; beneficiary
  is the sponsor.

**Privileged-only configuration**
- `bonus_math_k2-PRIV-1` — Low/Info, contingent. Owner-allowlisted absurd-supply token → permissionless
  whale stake or claim overflow-bricks observation/resolution/claims. Routed to fuzz for the exact
  boundary.
- `factory_clone_deployment-PRIV-1` — Info. `setSafeHarborRegistry` is the sole factory setter reaching
  all live pools (registry read live, never cached).
- `factory_clone_deployment-PRIV-2` — Info. Factory UUPS upgrade rewrites all factory logic, no in-code
  timelock; cannot reach clone funds; `__gap[45]` discipline is convention-only.
- `factory_clone_deployment-PRIV-3` — Info. `initialize` front-run only under a non-atomic deploy; the
  in-scope atomic `ERC1967Proxy` `_data` deploy forecloses it.

**Trusted-role operational hazards**
- `outcome_resolution_finality-TRUSTED-1` — moderator mis-flag locked irreversibly by the first claimant.
- `factory_clone_deployment-TRUSTED-1` — moderator immutable/un-rotatable; one key compromise degrades
  every live pool (stall, not steal).
- `pool_config_sponsor_controls-TRUSTED-1` — `recoveryAddress` retargetable up to sweep execution (own
  entitlement only).
- `survived_expired_claims-TRUSTED-1` — bonus sweep doesn't finalize the outcome; re-flag
  SURVIVED→CORRUPTED still possible (no double-pay).
- `pool_config_sponsor_controls-TRUSTED-2` — sponsor picks pool params at create (bounded, visible opt-in).

**Overall posture:** the value-bearing seams the mental model flagged as thinnest, eager-reset vs
lazy-clamp consistency, snapshot-vs-live divergence, `claimsStarted` finality, sweep reservation, bounty
monotonicity, CEI on every value mover, all re-confirm safe at the integration level. The single
externally-realizable loss is the Low unobserved-risk bonus misdirection; everything else requires a
privileged config error or a trusted-role action and is in-model.

### Tag legend

- `[ORACLE]` — registry-state / `block.timestamp` observation timing: `registry_observation_risk_window-EXT-1`, `factory_clone_deployment-PRIV-1`.
- `[RISK-WINDOW]` — risk-window latch machine: `registry_observation_risk_window-EXT-1`, `factory_clone_deployment-PRIV-1`.
- `[SWEEP-RESERVE]` — sweep reservation math: `registry_observation_risk_window-EXT-1`, `survived_expired_claims-TRUSTED-1`.
- `[SNAPSHOT]` — snapshot-vs-live divergence: `registry_observation_risk_window-EXT-1`, `pool_config_sponsor_controls-TRUSTED-1`.
- `[K2-ACCUM]` — k=2 accumulator arithmetic: `bonus_math_k2-PRIV-1`.
- `[TOKEN-ASSUMPTION]` — non-standard token behavior: `bonus_math_k2-PRIV-1`.
- `[ROUNDING]` — precision / widen-then-multiply boundary: `bonus_math_k2-PRIV-1`.
- `[DOS]` — brick / trap-funds: `bonus_math_k2-PRIV-1`.
- `[PROXY]` `[EVM]` — proxy/upgrade/init: `factory_clone_deployment-PRIV-2`, `factory_clone_deployment-PRIV-3`.
- `[BRANCH-CONFUSION]` — outcome-branch selection: `outcome_resolution_finality-TRUSTED-1`, `survived_expired_claims-TRUSTED-1`.
- `[CENTRALIZATION]` — in-model DAO / sponsor power surfaced: `factory_clone_deployment-PRIV-1`, `factory_clone_deployment-PRIV-2`, `outcome_resolution_finality-TRUSTED-1`, `factory_clone_deployment-TRUSTED-1`, `pool_config_sponsor_controls-TRUSTED-1`, `pool_config_sponsor_controls-TRUSTED-2`.

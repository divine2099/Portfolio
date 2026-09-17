# Findings report — dreUSD

Sherlock · Solidity / EVM · commit `224019ebf858f8d3c27fb0345efd90e4ac18a0f2`.

Cross-model attack-vector analysis. For every candidate vector, the code path is traced backward from the vulnerable function through every authorization gate to establish whether an unprivileged actor can reach it. Findings are bucketed by the least privilege required to trigger them:

- **Externally Exploitable** — reachable by an unauthenticated attacker, a malicious cross-chain / LayerZero actor, a sanctioned or frozen holder, or an external-dependency failure. No protocol role required.
- **Privileged-Only Configuration Risks** — require a privileged configuration role to trigger (moderator, withdrawal-config, default-admin, upgrader / owner).
- **Trusted Role Operational Risks** — manifest while a trusted operational role performs a normal, sanctioned action (keeper, express operator, custodian signer, treasury, guardian, pauser, or a single-address slot holder).

**Target-specific tags:** `[BRIDGE]` LayerZero credit/compose path · `[COMPLIANCE]` sanctions/freeze bypass or DoS · `[BACKING]` supply-vs-collateral identity · `[EXPRESS-CAPACITY]` express accounting desync · `[VEST]` rewards vesting math/reset · `[PAUSE]` pause-state cross-effects · `[SLOT]` single-address manager slot · `[TIMELOCK]` un-timelocked privileged action · `[DEPEG]` deviation-band oracle pricing.

---

## Externally Exploitable Vulnerabilities

### token_core-EXT-1 — Bridge `_credit` strands value at frozen / sanctioned / keyless addresses

- **Entry point:** `dreUSD._credit(address _to, uint256 _amountLD, uint32)` — `contracts/dreUSD.sol:184`.
- **Call-chain trace:** LZ endpoint → `OFTUpgradeable.lzReceive` → `_credit` (`dreUSD.sol:184`) → `if (_to == address(0)) _to = address(0xdead)` (`:189`) → `ERC20Upgradeable._update(address(0), _to, _amountLD)` (`:191`, base `_update`, **not** the overridden compliance hook at `:163`).
- **Auth gates traversed:** LZ peer/DVN authentication upstream (trusted bridge config); **no** `_validateAddress` / `frozen` / `sanctions` check on `_to` (the override is deliberately bypassed, `:190` comment). No protocol role.
- **Reachability / externally-exploitable verdict:** **Reachable.** Any cross-chain sender, or an honest sender who misaddresses `_to`, lands tokens at a recipient that the local compliance hook would reject. Two terminal states result: (a) `_to == address(0)` → minted to `0xdead`, keyless and permanently unspendable yet counted in destination `totalSupply`; (b) `_to` frozen/sanctioned on this chain → tokens minted but quarantined — every later `transfer`/`_debit` re-validates `from` (`:165`) and reverts, so they can never be moved, redeemed, or bridged out until guardian `unfreeze`. There is no on-chain sweep/burn to restore the "outstanding == spendable/recoverable" identity.
- **Severity:** Low–Medium. Value conservation globally holds (source burned first); the defect is permanent stranding of misaddressed/quarantined value with no recovery primitive, plus the compliance-state corner `blocked(addr) ∧ balanceOf(addr) > 0` that is unreachable by any non-bridge path (surface owned jointly with `bridging`).
- **Tags:** `[BRIDGE]` `[COMPLIANCE]` `[DOS]` `[EVM]`

**Cross-references (surface in `token_core`, owned elsewhere):**
- Deviation-band over-issuance with no supply cap — root owned by `oracle_pricing-EXT-1`; `dreUSD.mint` (`:88`) imposes no ceiling, so the band leak materializes here with zero defense-in-depth.
- Sanctions-oracle outage bricks all `mint`/`burn`/`transfer` via `_update`→`_validateAddress` — owned by `compliance-EXT-1` / `compliance-EXT-2`.
- `setDreUSDManager`/`setSanctionsList`/`renounceOwnership` slot & config power — owned by `authorization_and_upgrade-PRIV-*` and `compliance-PRIV-*`.

### offchain_authorization-EXT-1 — `mintFrom` authorization cannot be cancelled

- **Entry point:** `dreUSDManager.mintFrom(from, asset, amountIn, receiver, minAmountOut, deadline, permitSig, authorizeSig)` — `contracts/dreUSDManager.sol:373` (`nonReentrant whenNotPaused`, **no role**).
- **Call-chain trace:** open caller → `_preMintChecks` → `_validateAddress(from/receiver)` → `_authorize` (`:845`, `ECDSA.recover(digest, authorizeSig) == from`, digest binds all value params + `authNonce[from]`) → `authNonce[from]++` (`:394`) → `_executePermit(from,…)` → `_transferAndMint(asset, from, …, receiver)`.
- **Auth gates traversed:** EIP-712 signature by `from` (self-authorization); no protocol role. Replay bounded by `authNonce[from]`, deadline, and domain (`block.chainid` + `address(this)`).
- **Reachability / verdict:** **Reachable by any relayer.** Once `from` signs, *any* third party can execute exactly that mint up to `deadline`; there is **no explicit cancel / nonce-bump entrypoint**. `from` can only revoke by getting a different `mintFrom` mined (to bump the nonce) or by pulling the token approval (which makes `_transferAndMint` revert *without* consuming the nonce). The relayer can only execute what `from` signed (value binding HOLDS), so this is an authorization-lifetime / UX gap, not a value theft.
- **Severity:** Low (bounded). Recommendation: add a `cancelAuth`/nonce-increment function.
- **Tags:** `[SIG]` `[EVM]`

### withdrawal_lifecycle-EXT-1 — Express capacity permanently stranded by an un-fillable (blocked) owner, no reclaim path *(flagship liveness)*

- **Entry point:** `dreUSDManager.requestExpressWithdrawal(dreUSDAmount, minUsdcAmount, deadline)` — `contracts/dreUSDManager.sol:506` (the capacity-consume); `fillExpressWithdrawals` — `:595` (the would-be restore).
- **Call-chain trace:** request → `_queueExpressWithdrawal` → `expressWithdrawalAvailable -= totalUsdc` (`:733`, gross). Capacity is restored *only* via `payExpressDebt`→`_paybackExpressFiller` (`:794`, `available += amount`), which is gated behind `fillExpressWithdrawals` (`:636`, `expressFillerDebt += totalRequired`). If the NFT owner is blocked, `fillExpressWithdrawals` hits `isBlockedAddress(currentOwner)` (`:620`) → `emit WithdrawalSanctioned` → `continue` (`:622`) **forever** — debt never accrues, payback never fires, `available` never returns. There is **no reclaim / cancel / expiry transition anywhere in the state machine**.
- **Auth gates traversed:** `requestExpressWithdrawal` is open. The *blocking* of the owner requires **no protocol role** in the A19/A20 path: a Chainalysis sanctioning of the owner after request, or a sanctions-oracle outage (`isBlockedAddress`→true), strands the slice. (The A13 guardian-freeze trigger is the trusted variant — see compliance.)
- **Reachability / verdict:** **Reachable.** A user requests an express withdrawal, then becomes sanctioned (external Chainalysis state, no role) → their position is skipped indefinitely and its capacity slice is locked. Cumulative strands monotonically drive `expressWithdrawalAvailable → 0`, at which point `requestExpressWithdrawal` reverts for everyone (`expressWithdrawalAvailable != 0` / `totalUsdc <= available` guards) — a global express-queue freeze.
- **Severity:** Medium (liveness; no fund loss but permanent capacity loss with no recovery). Recommendation: add a `WITHDRAWAL_CONFIG`/`TREASURY` capacity-reclaim for provably un-fillable positions.
- **Tags:** `[EXPRESS-CAPACITY]` `[COMPLIANCE]` `[DOS]` `[EVM]`
- **Cross-ref:** guardian-freeze trigger owned by `compliance-TRUSTED-1`; oracle-outage skip-everyone owned by `compliance-EXT-2`.
- **Formal write-up prepared** (Sherlock audit-report template; reconfirmed source-live on `224019eb`).

### withdrawal_lifecycle-EXT-2 — `fillWithdrawal` reverts the whole batch on one not-ready/unfunded token (automation grief)

- **Entry point:** `dreUSDManager.fillWithdrawal(uint256[] tokenIds, bool useVault)` — `contracts/dreUSDManager.sol:534` (invoked by the keeper bot, which must hold TREASURY_ROLE).
- **Call-chain trace:** per token, `NotReady` (`:553`) and `NoBalance` (`:558`/`:560`) **`revert` the entire batch**, whereas the blocked-owner case only `continue`s (`:569`). An unprivileged attacker who shrinks the payout source below one position's `usdcAmount` — by draining the custodian multisig's aUSDC/allowance or Aave USDC liquidity (`useVault=true`, balance read at `:557`) — between the keeper's off-chain `checkUpkeep` snapshot and on-chain `performUpkeep` flips a fillable batch into a full revert.
- **Auth gates traversed:** The grief actions (liquidity drain, forcing a TOCTOU) need **no role**; the fill itself is TREASURY-gated but the *victim* is the keeper/treasury, not the attacker.
- **Reachability / verdict:** **Reachable.** Classic TOCTOU between the keeper's snapshot and execution; a single griefable token stalls all fills in the batch (throughput DoS). Funds are safe; liveness is grief-able. The aToken 1-wei rounding variant (`liquidity_routing` UNCERTAIN) reverts the batch the same way.
- **Severity:** Low–Medium (liveness). Recommendation: `continue` (skip) on `NotReady`/`NoBalance` so the batch makes partial progress.
- **Tags:** `[DOS]` `[FLASH]` `[EVM]`
- **Cross-ref:** liquidity snapshot/TOCTOU and aToken rounding owned by `liquidity_routing-EXT-1` / `liquidity_routing` UNCERTAIN.
- **Formal write-up prepared** (Sherlock audit-report template; covers `withdrawal_lifecycle-EXT-2` + `liquidity_routing-EXT-1`; reconfirmed source-live on `224019eb`).

**Cross-references (surface in `withdrawal_lifecycle`, owned elsewhere):**
- Band-edge redemption arb — `requestWithdrawal` at $0.99, fill in full after repeg (no role) — owned by `oracle_pricing-EXT-1`.
- In-flight claim immobilized by guardian freeze and system-wide fill stall during sanctions-oracle outage — owned by `compliance-TRUSTED-1` / `compliance-EXT-2`.

### oracle_pricing-EXT-1 — Quotes return the reported in-band price, not clamped to peg (deviation-band depeg arb) *(root)*

- **Entry points:** `dreUSDOracle.getUsdValue(token, amount)` — `contracts/dreUSDOracle.sol:214` (mint side, value at `:243`); `getTokenAmount(token, dreUSDAmount)` — `:250` (redeem side, value at `:287-292`).
- **Call-chain trace:** both quotes run the validity gate (sequencer → staleness → `answer>0` → `_checkDeviation`) then return the value at the **reported** price — there is **no clamp to $1**. `_checkDeviation` only *gates* `price ∈ expected·[1e4∓bps]/1e4` (default ±1%); within that band the reported price flows straight into the amount math. Mint: `dreUSDManager._mintDreUSD` (`:957`) mints `1.01` dreUSD/USDC at a reported $1.01. Redeem: `requestWithdrawal`/`requestExpressWithdrawal` (`:496`/`:521`) lock ~1% more USDC/dreUSD at a reported $0.99.
- **Auth gates traversed:** **None.** `getUsdValue`/`getTokenAmount` are open views; mint and request entrypoints are open and MEV-orderable. The depeg must be genuinely *reported* by Chainlink (within band).
- **Reachability / verdict:** **Reachable.** An unprivileged actor times a mint to a reported sub-$1.01 and a redeem to a reported $0.99, extracting ≤ the band per depeg→repeg cycle. The consumers treat the oracle as "reverts on bad price else ≈$1" — their trust outruns what the gate enforces.
- **Severity:** Low–Medium (bounded by `deviationBps`, requires a real reported off-peg). Recommendation: clamp mint to `min(price, peg)` and redeem to `max(price, peg)`.
- **Tags:** `[ORACLE]` `[DEPEG]` `[ROUNDING]` `[EVM]`
- **Cross-ref:** mint-side materialization `mint_accounting`; redeem-side `withdrawal_lifecycle`; no-cap amplifier `token_core`.

### oracle_pricing-EXT-2 — Withdrawal quote is frozen at request; the fill re-checks no oracle state

- **Entry point:** `dreUSDManager.requestWithdrawal/requestExpressWithdrawal` → `dreUSDOracle.getTokenAmount` — `contracts/dreUSDOracle.sol:250`; stored at `dreWithdrawalNFT.sol:114`; settled by `fillWithdrawal` (`dreUSDManager.sol:534`, **no re-quote**).
- **Call-chain trace:** `getTokenAmount` validates sequencer/staleness/deviation at the *request* instant (`:256-276`); the USDC owed is frozen into the NFT; the fill (up to 14 days later) pays the stored amount with **no** oracle re-check.
- **Auth gates traversed:** Request is open. No role.
- **Reachability / verdict:** **Reachable.** An actor submits `requestWithdrawal` in the last valid second before a sequencer outage or depeg; the quote passes then, and the later fill honors it unconditionally — a quote the oracle would now reject is paid in full. Compounds EXT-1 (lock a band-edge quote, settle after repeg).
- **Severity:** Low. Recommendation: re-validate (or re-quote with a floor) at fill time, or bound the request→fill price drift.
- **Tags:** `[ORACLE]` `[DEPEG]` `[EVM]`

### oracle_pricing-EXT-3 — No graceful degradation: any oracle/sequencer revert hard-fails all mint + withdrawal

- **Entry point:** consumer paths call the reverting `getUsdValue` (`:214`) / `getTokenAmount` (`:250`); the non-reverting `validatePrice`/`getLatestPrice` (`:302-329`) are **unused**.
- **Call-chain trace:** any oracle-side revert — stale round, sequencer down / in-grace, deviation breach, or a reverting Chainlink feed — propagates through `getUsdValue`/`getTokenAmount` and reverts the entire mint or withdrawal-request tx. There is no consumer path that degrades to skip/queue.
- **Auth gates traversed:** None — driven by external-dependency failure.
- **Reachability / verdict:** **Reachable** as an external condition. Mint and withdrawal-request liveness are fully coupled to oracle + sequencer availability; combined with the sanctions-oracle DoS (`compliance-EXT-1`) the whole protocol's liveness rests on uncontrolled external dependencies.
- **Severity:** Medium (liveness). Recommendation: consider a degradation path (e.g., consume `validatePrice` and queue rather than hard-revert) for non-safety-critical flows.
- **Tags:** `[ORACLE]` `[DOS]` `[EVM]`

### compliance-EXT-1 — Sanctions-oracle outage bricks every transfer / mint / burn / deposit / withdraw (whole-protocol DoS)

- **Entry point:** `dreUSD._validateAddress(address)` — `contracts/dreUSD.sol:132` (the `sanctionsList.isSanctioned` staticcall at `:137`, **no try/catch**), reached from every `_update` host.
- **Call-chain trace:** every value-moving call routes through some `_update` → `dreUSD._validateAddress` → `ISanctionsList(sanctionsList).isSanctioned(addr)` (`:137`). A reverting or gas-heavy Chainalysis oracle makes that staticcall revert, which propagates and reverts the whole transfer/mint/burn/deposit/withdraw across dreUSD, dreUSDs, the NFTs, and the spoke OFT.
- **Auth gates traversed:** None — driven purely by external-dependency failure. No role.
- **Reachability / verdict:** **Reachable** as an external condition. The sanctions oracle's *availability* is a hard, un-cached, un-circuit-broken dependency of all token movement. `view`/staticcall precludes reentrancy but not the liveness coupling.
- **Severity:** Medium (protocol-wide liveness). Recommendation: wrap the oracle call in try/catch with a defined fail policy, or cache / circuit-break it.
- **Tags:** `[ORACLE]` `[COMPLIANCE]` `[DOS]` `[EVM]`

### compliance-EXT-2 — `isBlockedAddress` conflates "errored" with "blocked": outage makes fills skip every owner

- **Entry point:** `dreUSD.isBlockedAddress(address)` — `contracts/dreUSD.sol:148` (try/catch → `true` on any revert); consumed by `fillWithdrawal` (`dreUSDManager.sol:567`) and `fillExpressWithdrawals` (`:620`).
- **Call-chain trace:** `isBlockedAddress` calls `this.validateAddress` in a try/catch and returns `true` for **any** revert — including a sanctions-oracle outage or OOG (`:149-153`). The fill loops then take the blocked branch (`continue`) for **every** owner, skipping all of them.
- **Auth gates traversed:** None. The fills are TREASURY/EXPRESS_OPERATOR-gated but the failure mode is owner-independent.
- **Reachability / verdict:** **Reachable.** Under the same outage as EXT-1, the `_update` hosts fail-closed by reverting while the fill-skips fail-closed by skipping everyone — both closed, divergent effect (no settlement proceeds, and express capacity strands per `withdrawal_lifecycle-EXT-1`).
- **Severity:** Medium. Recommendation: distinguish "oracle errored" from "address sanctioned" (don't map errors to blocked).
- **Tags:** `[ORACLE]` `[COMPLIANCE]` `[DOS]` `[EVM]`

### compliance-EXT-3 — Per-chain `frozen` map does not propagate; a holder evades freeze by bridging out first

- **Entry point:** `dreUSD.frozen` (per-deployment, `contracts/dreUSD.sol:40`); spoke `dreShareOFT._update` delegates to its own chain's compliance instance (`ovault/dreShareOFT.sol:78-80`).
- **Call-chain trace:** `frozen` is local to each `dreUSD`/compliance deployment. A holder who bridges value to a spoke *before* being frozen on the hub retains free use of it there — the spoke reads its own (empty) `frozen` map. Bridge-*out* from the freezing chain is still blocked (OFT `_debit`→`_burn`→`_update` validates `from`).
- **Auth gates traversed:** None for the evader; the gap exists regardless of role.
- **Reachability / verdict:** **Reachable.** Sanctions/freeze are only as global as the operator's per-chain coverage; value moved pre-freeze lives freely on other chains unless every chain freezes independently (and mirrors the same oracle).
- **Severity:** Low (operational). Recommendation: freeze-on-every-chain runbook, or a cross-chain freeze-propagation message.
- **Tags:** `[BRIDGE]` `[COMPLIANCE]` `[EVM]`

### bridging-EXT-1 — Composer accumulates unsweepable shared-decimal dust when `minAmountLD == 0`

- **Entry point:** `dreOVaultComposer._depositAndSend(...)` / `_redeemAndSend(...)` — `contracts/ovault/dreOVaultComposer.sol:72` / `:112`.
- **Call-chain trace:** the user's `minAmountLD` bounds both the vault conversion (`_assertSlippage`) and the preserved OFT-send minimum. With `minAmountLD == 0` (user-chosen), sub-shared-decimal (sub-1e12) dust is trimmed on the OFT send and accretes in the composer; there is **no sweep/recover function** to reconcile it.
- **Auth gates traversed:** None — open compose path; self-inflicted by a loose `minAmountLD`.
- **Reachability / verdict:** **Reachable** but bounded: slow monotonic dust accretion in the composer, no theft and no user loss beyond the trimmed dust. The slippage protection itself holds when `minAmountLD > 0`.
- **Severity:** Informational–Low. Recommendation: add a `recoverToken` sweep on the composer; document `minAmountLD` guidance.
- **Tags:** `[ROUNDING]` `[BRIDGE]` `[EVM]`

### liquidity_routing-EXT-1 — Liquidity snapshot TOCTOU: shrinking any of {vault balance, allowance, Aave liquidity} reverts the whole fill batch

- **Entry point:** `dreAaveAdapter.getAvailableBalance` — `contracts/dreAaveAdapter.sol:136`; snapshot at `dreWithdrawalKeeperBot.sol:47`; on-chain recheck at `dreUSDManager.sol:557`.
- **Call-chain trace:** the keeper selects a batch within an off-chain `getAvailableBalance = min(aUsdc.balanceOf(vault), aUsdc.allowance(vault, adapter), usdc.balanceOf(aUsdc))` snapshot; `fillWithdrawal` re-reads it per token on-chain (`:557`) and **reverts** the whole batch on `NoBalance` (`:558`). All three inputs live on external contracts (the custodian multisig + Aave).
- **Auth gates traversed:** None for the griefer — anyone can reduce the multisig's aUSDC/allowance exposure or Aave USDC liquidity between the two reads.
- **Reachability / verdict:** **Reachable.** A single mempool-hop liquidity drop flips a valid batch into a full revert — the keeper acts on a stale view. Griefable automation stall, funds safe.
- **Severity:** Low–Medium (liveness). Recommendation: skip-not-revert on `NoBalance`; on-chain re-derive the fillable set.
- **Tags:** `[DOS]` `[FLASH]` `[EVM]`
- **Cross-ref:** manager-side batch-revert asymmetry owned by `withdrawal_lifecycle-EXT-2`.

### liquidity_routing-EXT-2 — aToken 1-wei ray-rounding reverts a legitimate adapter withdraw (and aborts the batch) *(UNCERTAIN — fork-test)*

- **Entry point:** `dreAaveAdapter.withdraw(amount, to)` — `contracts/dreAaveAdapter.sol:109`.
- **Call-chain trace:** `withdraw` enforces strict `delta < amount → WithdrawalFailed` (`:125`) and `withdrawn < amount → WithdrawalFailed` (`:130`), assuming "redeem `amount` aUSDC yields exactly `amount` USDC." Aave's ray-scaled aToken math only guarantees this approximately; a 1-wei shortfall trips the strict check, reverting the withdraw. Since `fillWithdrawal` lacks `nonReentrant` and propagates the revert, the **entire batch** aborts.
- **Auth gates traversed:** None — driven by Aave ray-math at fill time.
- **Reachability / verdict:** **UNCERTAIN.** Whether real Base aUSDC actually rounds against the adapter at realistic amounts requires a fork-test (Step 15). If it does, intermittent rounding stalls fills.
- **Severity:** Low–Medium (liveness, conditional). Recommendation: tolerate a ≤1-wei shortfall; fuzz/fork-test against the live aToken.
- **Tags:** `[ROUNDING]` `[DOS]` `[EVM]`


---

## Privileged-Only Configuration Risks

### mint_accounting-PRIV-1 — `updateVault` redirects all mint collateral with no timelock

- **Entry point:** `dreUSDManager.updateVault(address _custodianVault)` — `contracts/dreUSDManager.sol:237`.
- **Call-chain trace:** `updateVault` (`:237`, `onlyRole(MODERATOR_ROLE)`, non-zero + `SameVault` guard, **no timelock**) sets `custodianVault`. Every subsequent mint reads it fresh: `mint`(`:352`/`:406`) → `_transferAndMint` (`:916`) → `IERC20(asset).safeTransferFrom(from, custodianVault, amountIn)` (`:927`) → `_mintDreUSD` → `dreUSD.mint(receiver, dreUSDAmount)` (`:964`).
- **Auth gates traversed:** `MODERATOR_ROLE` on the manager. No timelock, no is-multisig check on the new sink.
- **Reachability / verdict:** **Privileged.** A compromised/erroneous MODERATOR repoints the collateral sink to an attacker address; a victim mint submitted before/around the change forwards collateral to the attacker sink while `dreUSD` still mints to the victim. No mint-time failure signals the broken backing. On single-sequencer Base, A10 + an MEV orderer can place the `updateVault` immediately before a pending victim mint.
- **Severity:** Medium. Silent backing erosion; blast radius = all collateral flowing during the window. Contingent on MODERATOR being a timelocked multisig (it is not enforced on-chain — see `authorization_and_upgrade-PRIV-5`).
- **Tags:** `[BACKING]` `[TIMELOCK]` `[EVM]`

### mint_accounting-PRIV-2 — Allowlist and oracle feed are decoupled (mint DoS or under-backed mint)

- **Entry point:** `dreUSDManager.updateAllowedList(address token, bool)` — `contracts/dreUSDManager.sol:338` (paired with oracle `setOracle`/`removeOracle`/`setDeviationThreshold`).
- **Call-chain trace:** `_preMintChecks` (`:807`) checks only `allowed[asset]` (`:810`) — **not** that a feed exists. (a) Asset listed without a feed → `_mintDreUSD`→`oracle.getUsdValue` reverts `OracleNotSet` → mint DoS. (b) Asset listed while its deviation check is disabled (`oracle.setDeviationThreshold(token,0)`) → `getUsdValue` returns a depegged price → mint under-backs dreUSD.
- **Auth gates traversed:** `MODERATOR_ROLE` on the manager (allowlist) and `MODERATOR_ROLE` on the oracle (feed) — nominally the same role name on two different contracts; their states are never coordinated.
- **Reachability / verdict:** **Privileged.** Both forms require MODERATOR action (or inaction). The decoupling is the defect: no atomic invariant ties `allowed[asset]` to a fresh, peg-protected feed.
- **Severity:** Low–Medium (DoS form is liveness; the under-backed form is bounded by the deviation config).
- **Tags:** `[ORACLE]` `[DEPEG]` `[BACKING]` `[DOS]` `[EVM]`

**Cross-references (surface in `mint_accounting`, owned elsewhere):**
- Deviation-band depeg arb — mint at $1.01 / redeem at $1 (no role) — owned by `oracle_pricing-EXT-1`; materializes at `_mintDreUSD` (`:948`), which has no peg clamp.
- `mintAndStake` inflated-price deposit during distributor pause — owned by `savings_vault-TRUSTED-1`.

### offchain_authorization-PRIV-1 — MODERATOR can enable/expand fiat-mint authority (custodian self-add + cap raise)

- **Entry points:** `dreUSDManager.updateCustodianList(address, bool)` — `:246`; `dreUSDManager.setDailyFiatMintCap(uint256)` — `:261`.
- **Call-chain trace:** `updateCustodianList(attacker, true)` (`:246`, `onlyRole(MODERATOR_ROLE)`) marks `custodians[attacker]=true`; `setDailyFiatMintCap(100_000_000_00)` (`:261`, clamped to `MAX_DAILY_FIAT_MINT_CAP_USD`) raises the only on-chain throttle. With a colluding/compromised KEEPER, `mintFromUsd` (`:456`) → `_mintFromFiatUsd` (`:975`) now passes `custodians[signer]` for an attacker-signed `FiatMint` and mints up to 100M USD/day of unbacked dreUSD.
- **Auth gates traversed:** `MODERATOR_ROLE` on the manager — single un-timelocked tx each; plus `KEEPER_ROLE` to relay. No on-chain delay.
- **Reachability / verdict:** **Privileged.** Requires MODERATOR; fully exploitable when combined with KEEPER. The default fail-safe (cap 0, no custodians) holds for an honest config — this is a config-abuse / role-concentration vector.
- **Severity:** Medium–High, contingent on MODERATOR/KEEPER not being timelocked multisigs.
- **Tags:** `[BACKING]` `[SIG]` `[TIMELOCK]` `[EVM]`
- **Cross-ref:** general role-concentration owned by `authorization_and_upgrade-PRIV-4`.

### withdrawal_lifecycle-PRIV-1 — `updateWithdrawal` retroactively re-times all pending standard positions

- **Entry point:** `dreUSDManager.updateWithdrawal(uint256 waitingTime)` — `contracts/dreUSDManager.sol:314`.
- **Call-chain trace:** `updateWithdrawal` (`onlyRole(WITHDRAWAL_CONFIG_ROLE)`, clamps `waitingTime ∈ [1d,14d]`) sets the single `withdrawalWaitingTime`. `fillWithdrawal` reads the **current** value against each position's `createdAt` (`:553`) — there is **no per-position snapshot of the wait at request time**. So a config change re-times every pending standard position at once.
- **Auth gates traversed:** `WITHDRAWAL_CONFIG_ROLE`. No timelock.
- **Reachability / verdict:** **Privileged.** A11 sets `14d` to delay every queued redemption to the max, or `1d` to make the whole standard queue instantly fillable. Bounded by the [1d,14d] clamp.
- **Severity:** Low (governance parameter). Recommendation: snapshot the wait into the NFT at request time.
- **Tags:** `[TIMELOCK]` `[EVM]`

### withdrawal_lifecycle-PRIV-2 — Express filler reimbursement can be diverted to a non-filler address

- **Entry point:** `dreUSDManager.updateExpressPaybackAddress(address newAddress)` — `contracts/dreUSDManager.sol:275`; settled via `payExpressDebt`→`_paybackExpressFiller` (`:768`).
- **Call-chain trace:** `_paybackExpressFiller` (`:794`) sends `usdc.safeTransferFrom(treasury, expressPaybackAddress, amount)` — `expressPaybackAddress` is **not** bound to the `msg.sender` that actually fronted USDC in `fillExpressWithdrawals` (`:640`). If `WITHDRAWAL_CONFIG_ROLE` points `expressPaybackAddress` at an address ≠ the active EXPRESS_OPERATOR, the operator fronts the payout and the reimbursement goes elsewhere.
- **Auth gates traversed:** `WITHDRAWAL_CONFIG_ROLE` to set the address; the victim is the EXPRESS_OPERATOR performing a normal fill.
- **Reachability / verdict:** **Privileged** (config-set), with the loss landing on a trusted operational role. Also a benign-looking misconfig (operator key rotated without updating payback) reproduces it.
- **Severity:** Low (operator loss, no user-fund impact). Recommendation: reimburse the recorded filler, or assert `operator == expressPaybackAddress`.
- **Tags:** `[EXPRESS-CAPACITY]` `[EVM]`

### withdrawal_lifecycle-PRIV-3 — `fillWithdrawal` carries no `nonReentrant`; cross-function reentrancy is latent behind a swappable adapter / non-standard payout token

- **Source:** cross-function and cross-contract reentrancy patterns (Low, latent). No invariant currently BROKEN (CEI holds for same-token double-fill).
- **Entry point:** `dreUSDManager.fillWithdrawal(uint256[] tokenIds, bool useVault)` — `contracts/dreUSDManager.sol:534` (`TREASURY_ROLE whenNotPaused`, **no `nonReentrant`** — contrast `fillExpressWithdrawals` `:597` which has it).
- **Call-chain trace:** per token CEI is correct — `nft.burn` (`:574`, EFFECTS) precedes the payout (`:582` `adapter.withdraw` / `:585` `usdc.safeTransferFrom` to `currentOwner`). Same-token double-fill is therefore impossible. **But** the function never enters the transient reentrancy guard, so a callback raised *during* the payout can re-enter the *other* guarded entrypoints (`requestWithdrawal` `:483`, `mint*` `:358/:411/:431`, `fillExpressWithdrawals` `:597`) whose guard `fillWithdrawal` does not hold — a classic cross-function opening. With the **current** payout assets (USDC: no transfer hook; Aave adapter: no callback to `currentOwner`) this is unreachable.
- **Auth gates traversed:** Triggering it requires a payout asset that *can* call back. Two routes, both privileged: (a) `WITHDRAWAL_CONFIG_ROLE.updateVaultAdapter` (`:328`) swaps in a hostile/buggy adapter that re-enters on `withdraw`; or (b) the settlement token (`usdc` immutable) is not in fact callback-free. Route (a) is the live one — same role family as `liquidity_routing-PRIV-1`.
- **Reachability / verdict:** **Privileged / latent.** Not unprivileged-reachable on `224019eb`; it is a defense-in-depth gap that becomes live only after a privileged adapter swap to a contract with a recipient callback. Cross-references the batch-revert TOCTOU (`withdrawal_lifecycle-EXT-2`) and the aToken-rounding batch abort (`liquidity_routing-EXT-1`), which share `fillWithdrawal`'s un-guarded propagation.
- **Severity:** Low (defense-in-depth; no current exploit path). Recommendation: add `nonReentrant` to `fillWithdrawal` for parity with `fillExpressWithdrawals`.
- **Tags:** `[REENTRANCY]` `[DOS]` `[EVM]`
- **Cross-ref:** hostile-adapter swap owned by `liquidity_routing-PRIV-1`; batch-revert grief owned by `withdrawal_lifecycle-EXT-2`.

### savings_vault-PRIV-1 — `setRewardsDistributor` swap reverts under old-distributor pause and strands unvested rewards

- **Entry point:** `dreUSDs.setRewardsDistributor(address)` — `contracts/dreUSDs.sol:78`.
- **Call-chain trace:** if `oldDistributor != 0`, the swap calls `old.claimVested` (`:84`) which is `whenNotPaused` + vault-only on the distributor — if the **old distributor is paused**, this **reverts**, DoSing the swap. Even when it succeeds, `claimVested` only pulls the *vested* slice; any **unvested** rewards remaining in the old distributor are **stranded** (no migration).
- **Auth gates traversed:** `DEFAULT_ADMIN_ROLE` on dreUSDs; the DoS leg additionally needs `PAUSER_ROLE` on the old distributor.
- **Reachability / verdict:** **Privileged.** Both legs require admin action (+pauser for the DoS). Share-price continuity itself holds; the defect is a swap that can be blocked and value left stranded.
- **Severity:** Low. Recommendation: unpause-then-swap runbook; settle/migrate unvested before swapping.
- **Tags:** `[VEST]` `[PAUSE]` `[EVM]`

### savings_vault-PRIV-2 — `setShareOFTAdapter` slot inverts share-transfer compliance if mis-set

- **Entry point:** `dreUSDs.setShareOFTAdapter(address)` — `contracts/dreUSDs.sol:95`; effect in `_update` — `:262`.
- **Call-chain trace:** `_update` (`:262`, `whenNotPaused`) skips **both** `from` and `to` `_validateAddress` when `from == shareOFTAdapter` (`:263`). If the slot is set to a non-adapter or compromised address, that address can move dreUSDs shares to/from any counterparty — including sanctioned/frozen — with no compliance check.
- **Auth gates traversed:** `DEFAULT_ADMIN_ROLE` to set the slot; no is-genuine-lockbox verification.
- **Reachability / verdict:** **Privileged.** With the genuine hub adapter the bypass only produces *quarantined* shares (recipient can't re-transfer/redeem). The break is a mis-set/compromised slot, a single-slot compliance inversion.
- **Severity:** Medium (compliance bypass), contingent on admin trust. Recommendation: verify the slot is the deployed adapter; consider a code/interface check.
- **Tags:** `[COMPLIANCE]` `[SLOT]` `[BRIDGE]` `[EVM]`

### rewards_vesting-PRIV-1 — `addRewards` lacks a `vault.rewardsDistributor == address(this)` self-assertion (stale-distributor accounting mismatch)

- **Entry point:** `dreRewardsDistributor.addRewards` — `contracts/dreRewardsDistributor.sol:108`.
- **Call-chain trace:** step (1) `vault.claimVestedRewards` (`:109`) claims from the vault's **current** `rewardsDistributor`; step (2) `newRewards = balanceOf(this) - rewards` (`:111`) reads **this** contract's balance. If invoked on a *deprecated* distributor after `dreUSDs.setRewardsDistributor(B)`, step (1) flushes B while step (2) prices A — an accounting mismatch. No assertion ties the two.
- **Auth gates traversed:** `MODERATOR_ROLE` on the (old) distributor; reachable only by manual misuse after a `DEFAULT_ADMIN` swap of the vault distributor.
- **Reachability / verdict:** **Privileged (manual misuse).** The supported path (`mintRewards` always targets the current distributor) never hits it; the missing self-assertion is the latent defect.
- **Severity:** Low (manual-misuse only). Recommendation: assert `vault.rewardsDistributor == address(this)` at the top of `addRewards`.
- **Tags:** `[VEST]` `[EVM]`

### oracle_pricing-PRIV-1 — Peg / staleness / feed protections are MODERATOR-disablable with no timelock

- **Entry points:** `dreUSDOracle.setDeviationThreshold(token, bps)` — `contracts/dreUSDOracle.sol:168`; `setStalenessThreshold(token, s)` — `:157`; `setOracle(token, feed, s)` — `:91`; `removeOracle(token)` — `:179`.
- **Call-chain trace:** `setDeviationThreshold(token, 0)` (`:174`) makes `_checkDeviation` (`:407-411`) return immediately → any `answer > 0` priced at its crashed value (under-backed mint / over-pay redeem); `bps = 10000` gives band `[0, 2×peg]` (no lower bound). `setStalenessThreshold(token, 86400)` accepts 24h-old prices. `setOracle(token, hostileFeed)` points a token at a feed reading ~$1 at config time. All take effect on the consumers' very next `getUsdValue`/`getTokenAmount` call.
- **Auth gates traversed:** `MODERATOR_ROLE` on the oracle — a *distinct grant* from the manager's same-named role; single un-timelocked tx each.
- **Reachability / verdict:** **Privileged.** Default config (1% band, heartbeat staleness, sanity-checked feed) is safe; the break is a MODERATOR disabling/loosening a protection, after which mint/redeem price off attacker-chosen values. The `setOracle` config-time `[$0.50,$2.00]` band is one-time and can also *reject* a legit feed during a real depeg (liveness).
- **Severity:** Medium (centralization/config). Recommendation: forbid `bps == 0`, cap deviation at a small max, set staleness to the feed heartbeat, timelock these setters.
- **Tags:** `[ORACLE]` `[DEPEG]` `[BACKING]` `[TIMELOCK]` `[EVM]`
- **Cross-ref:** `removeOracle` on a still-allowed token (mint DoS) is the mirror of `mint_accounting-PRIV-2` (allowlist/feed decouple).

### compliance-PRIV-1 — `setSanctionsList` can globally disable screening (0) or brick all transfers (bad contract)

- **Entry point:** `dreUSD.setSanctionsList(address)` — `contracts/dreUSD.sol:80` (`DEFAULT_ADMIN_ROLE`, dedupe guard only, **no zero/code check**).
- **Call-chain trace:** setting `sanctionsList = 0` makes `_validateAddress` (`:137`) skip the sanctions branch entirely → sanctioned-but-not-frozen addresses transact freely (and fiat mints to sanctioned receivers succeed). Setting it to a reverting/garbage contract makes every `_update` revert → all token movement bricked.
- **Auth gates traversed:** `DEFAULT_ADMIN_ROLE`, single un-timelocked tx.
- **Reachability / verdict:** **Privileged.** Either a compliance-evasion (disable) or a self-DoS (brick) depending on the address; no on-chain delay or alarm.
- **Severity:** Medium (liveness). Recommendation: timelock + alarm list changes; reject non-contract addresses.
- **Tags:** `[COMPLIANCE]` `[TIMELOCK]` `[EVM]`

### compliance-PRIV-2 — Whitelist-wrapper mode: empty whitelist bricks the token; `removeFromWhitelist` is a second freeze authority

- **Entry points:** `dreUSD.setSanctionsList(wrapper)` — `contracts/dreUSD.sol:80`; `SanctionsListWhitelistWrapper.isSanctioned` — `whitelist/SanctionsListWhitelistWrapper.sol:42`; `removeFromWhitelist` — `:62`.
- **Call-chain trace:** with `sanctionsList` pointed at the wrapper, `isSanctioned(a) = !_whitelisted[a] || underlying.isSanctioned(a)` (`:42-44`) — non-whitelisted short-circuits `true` with **no oracle call**. An empty whitelist makes every `_update` host revert — including `dreUSD.mint`'s `to`-validation (`:168`) — so mint/withdrawal/bridge-delivery all fail except `_credit`→`0xdead`. `removeFromWhitelist(victim)` makes an address "sanctioned" without any oracle — a soft-freeze authority distinct from `GUARDIAN_ROLE`.
- **Auth gates traversed:** `DEFAULT_ADMIN_ROLE` to point at the wrapper; wrapper `MODERATOR_ROLE` for whitelist management.
- **Reachability / verdict:** **Privileged.** A single config choice (which `sanctionsList` to use) re-gates mint/withdrawal/bridge across every model into a permissioned token; the wrapper MODERATOR gains freeze-like power.
- **Severity:** Medium. Recommendation: document the allowlist mode; gate the wrapper MODERATOR like the guardian.
- **Tags:** `[COMPLIANCE]` `[DOS]` `[EVM]`
- **Cross-ref:** `setShareOFTAdapter` unchecked-conduit owned by `savings_vault-PRIV-2`.

### bridging-PRIV-1 — Single `Ownable` owner controls ovault upgrades and LZ peers (forged-peer unbacked mint / arbitrary bridge logic)

- **Entry points:** `dreShareOFT._authorizeUpgrade` — `contracts/ovault/dreShareOFT.sol:124`; `dreShareOFTAdapter._authorizeUpgrade` — `ovault/dreShareOFTAdapter.sol:101`; `setStuckFundsRecipient` (`:62`); LZ `setPeer` on all OFT/adapter/composer (inherited `onlyOwner`).
- **Call-chain trace:** all three ovault contracts gate `_authorizeUpgrade`, `setStuckFundsRecipient`, and LZ peer/delegate config on a single `Ownable.onlyOwner` — no role separation, no visible timelock. `setPeer(hostile)` makes a subsequent `_credit` (`dreUSD.sol:191` / `dreShareOFT.sol:109`) mint on this chain with **no source burn the destination can verify** (cross-chain supply conservation is an LZ-trust assumption); `upgradeToAndCall(malicious)` rewrites bridge logic arbitrarily.
- **Auth gates traversed:** `Ownable` owner — the same single key that secures cross-chain conservation.
- **Reachability / verdict:** **Privileged.** Conservation/quarantine hold under honest LZ config; the break is owner compromise/misconfig → unbacked cross-chain mint or arbitrary bridge code.
- **Severity:** High (cross-chain unbacked mint), contingent on owner being a timelocked multisig (not enforced). Recommendation: role-separate and timelock ovault ownership; monitor `setPeer`.
- **Tags:** `[PROXY]` `[BRIDGE]` `[BACKING]` `[TIMELOCK]` `[EVM]`
- **Cross-ref:** protocol-wide UUPS authority and dreUSD-OFT `setPeer`=mint-authority owned by `authorization_and_upgrade-PRIV-2` / `-PRIV-3`.

### liquidity_routing-PRIV-1 — Incompatible/malicious vault-adapter swap halts all useVault fills (DoS, no theft)

- **Entry point:** `dreUSDManager.updateVaultAdapter(address adapter)` — `contracts/dreUSDManager.sol:328`.
- **Call-chain trace:** `updateVaultAdapter` only asserts `adapter.getUsdc == usdc` (`:333`). A malicious or merely incompatible adapter passing that check can be installed, but it holds **zero allowance** from the custodian multisig, so `adapter.withdraw` (`dreAaveAdapter.sol:113`) reverts — every `fillWithdrawal(_, useVault=true)` then fails. The real custody gate (the multisig allowance) is outside the contract, so theft is not reachable; liveness is.
- **Auth gates traversed:** `WITHDRAWAL_CONFIG_ROLE`. No timelock.
- **Reachability / verdict:** **Privileged.** Custody holds (no theft); the break is a DoS of the vault-funded fill path.
- **Severity:** Low. Recommendation: stronger adapter validation; timelock `updateVaultAdapter`.
- **Tags:** `[DOS]` `[TIMELOCK]` `[EVM]`

### liquidity_routing-PRIV-2 — Using `dreVault` as the custodian sink strands non-USDC collateral *(UNCERTAIN — deployment-config-dependent)*

- **Entry point:** `dreUSDManager.updateVault(dreVaultHop)` — `:237` (MODERATOR config choice); `dreVault.performUpkeep` — `contracts/dreVault.sol:53`.
- **Call-chain trace:** every mint pushes the allowed stablecoin to `custodianVault` (`dreUSDManager.sol:927`). If `custodianVault` is a `dreVault` hop, `performUpkeep` auto-forwards only the immutable `token` (USDC) to `forwardVault` (`:53-58`); a USDT mint lands there and **accretes** until a manual `recoverToken` (allowed since `USDT != token`).
- **Auth gates traversed:** `MODERATOR_ROLE` deployment/config choice of the sink; non-USDC stablecoin must be allowlisted.
- **Reachability / verdict:** **UNCERTAIN / config-dependent.** Only occurs if the deployment uses `dreVault` (not a multisig) as `custodianVault` and a non-USDC stablecoin is listed — the recommendation is to use a multisig sink.
- **Severity:** Low (conditional). Recommendation: use a multisig custodian, or document USDC-only forwarding.
- **Tags:** `[BACKING]` `[EVM]`

### authorization_and_upgrade-PRIV-1 — Single-address slots are repointable in one un-timelocked tx (instant unbounded mint/burn/withdraw)

- **Entry points:** `dreUSD.setDreUSDManager` — `contracts/dreUSD.sol:103`; `dreWithdrawalNFT.setDreUSDManager` (×2) — `dreWithdrawalNFT.sol:94`; `dreAaveAdapter.setDreUSDManager`/`setVault` — `dreAaveAdapter.sol:175`/`:190`.
- **Call-chain trace:** each slot is a plain `address` checked `msg.sender != slot`; `DEFAULT_ADMIN_ROLE` overwrites it with `setDreUSDManager(attacker)` (non-zero guard only, **no timelock, no propose/accept**). The new address instantly holds unbounded `dreUSD.mint`/`burn` (no economic ceiling), NFT mint/burn, or `dreAaveAdapter.withdraw`. Slots are not roles — they cannot be partially revoked, only overwritten.
- **Auth gates traversed:** `DEFAULT_ADMIN_ROLE`, single tx.
- **Reachability / verdict:** **Privileged.** Authority outruns every value check; the corner every other model's backing assumption forbids.
- **Severity:** High un-timelocked / Medium timelocked. Recommendation: timelock + two-step propose/accept on slot setters.
- **Tags:** `[SLOT]` `[TIMELOCK]` `[BACKING]` `[EVM]`

### authorization_and_upgrade-PRIV-2 — UUPS upgrade is unconstrained authority over every model

- **Entry point:** `_authorizeUpgrade(address)` on the 8 proxies (e.g. `dreUSDManager.sol:1048`, `dreUSD.sol:199`); `onlyOwner` upgrade on the ovault trio.
- **Call-chain trace:** `UPGRADER_ROLE` (8 proxies) or `onlyOwner` (ovault) calls `upgradeToAndCall(malicious)` → arbitrary storage rewrite / mint / drain, bypassing every other check. No timelock; no second weaker path; `_disableInitializers` in every constructor prevents impl-takeover, so this is the *only* upgrade path — but it is total.
- **Auth gates traversed:** `UPGRADER_ROLE` / ovault `Ownable` owner.
- **Reachability / verdict:** **Privileged.** Every "verified-correct" property in the other 10 models is conditional on no malicious upgrade.
- **Severity:** High. Recommendation: timelocked upgrader multisig; role-separate ovault ownership.
- **Tags:** `[PROXY]` `[TIMELOCK]` `[EVM]`
- **Cross-ref:** ovault single-owner specifics owned by `bridging-PRIV-1`.

### authorization_and_upgrade-PRIV-3 — LZ peer/owner is a second unbounded-mint authority; `renounceOwnership` is an irreversible foot-gun

- **Entry points:** `dreUSD.transferOwnership` — `contracts/dreUSD.sol:205`; `renounceOwnership` — `:214`; LZ `setPeer` (inherited, owner-gated).
- **Call-chain trace:** `dreUSD`'s `Ownable.owner` (re-gated to `DEFAULT_ADMIN_ROLE`) controls `setPeer`; a hostile/incorrect peer lets `_credit` (`dreUSD.sol:191`, compliance-bypassing) mint on this chain with no source burn the destination can verify — a *second* unbounded-mint surface independent of the manager slot (PRIV-1). `renounceOwnership` (`:214`) sets the LZ owner to `address(0)` **permanently**, freezing all peer/delegate config (terminal, no recovery).
- **Auth gates traversed:** `DEFAULT_ADMIN_ROLE` / owner.
- **Reachability / verdict:** **Privileged.** Two separate authority surfaces (manager slot + LZ owner) both reduce to DEFAULT_ADMIN and each confer unbounded mint.
- **Severity:** High for hostile peer; Medium for the renounce foot-gun. Recommendation: timelock peer/delegate config; remove or guard `renounceOwnership`.
- **Tags:** `[BRIDGE]` `[BACKING]` `[TIMELOCK]` `[EVM]`

### authorization_and_upgrade-PRIV-4 — `MODERATOR_ROLE` concentrates "issue money + price money" (role-separation collapse)

- **Entry points:** manager `updateCustodianList`/`updateVault`/`setDailyFiatMintCap`/`updateAllowedList` (`dreUSDManager.sol:246`/`:237`/`:261`/`:338`); oracle `setDeviationThreshold`/`setStalenessThreshold`/`removeOracle` (`dreUSDOracle.sol:168`/`:157`/`:179`); `dreUSDs.initialize` (`:66-68`, admin+upgrader+pauser to one key).
- **Call-chain trace:** a single `MODERATOR_ROLE` holder (on manager + oracle) can self-add as custodian (fiat-mint to cap, with KEEPER), repoint `custodianVault` (redirect all collateral), raise the cap to 100M, and disable the oracle deviation gate — i.e. issue *and* price money. Separately `dreUSDs.initialize` grants DEFAULT_ADMIN + UPGRADER + PAUSER to one key. `DEFAULT_ADMIN` can also `grantRole(MODERATOR, self)`.
- **Auth gates traversed:** `MODERATOR_ROLE`, optionally reached via `DEFAULT_ADMIN` grant.
- **Reachability / verdict:** **Privileged.** Separation is *possible* via init params but collapses in these wirings; one compromised role mints unbacked and breaks backing.
- **Severity:** Medium. Recommendation: distinct role addresses; split + timelock; separate the oracle MODERATOR from the manager MODERATOR.
- **Tags:** `[BACKING]` `[ORACLE]` `[TIMELOCK]` `[EVM]`
- **Cross-ref:** consumers `mint_accounting-PRIV-1`, `offchain_authorization-PRIV-1`, `oracle_pricing-PRIV-1`.

### authorization_and_upgrade-PRIV-5 — `dreTimelockController` is unreferenced: all "timelocked" safety is a deploy-script choice *(foundational)*

- **Entry point:** `governance/dreTimelockController.sol` (thin OZ `TimelockController`, `admin = address(0)`); **no in-scope contract references it**.
- **Call-chain trace:** every "un-timelocked" break above (PRIV-1/-2/-3/-4) is *immediate* unless the deploy script sets each proxy's `DEFAULT_ADMIN`/`UPGRADER`/`owner` to the timelock address. The contracts enforce neither. Even when wired, an `executors` array containing `address(0)` opens execution to anyone.
- **Auth gates traversed:** None at runtime — this is a deployment-configuration property.
- **Reachability / verdict:** **Foundational / deploy-dependent.** The safety of every cross-model authority boundary is decided outside the audited code; the single highest-leverage deployment assumption.
- **Severity:** Informational-as-code / Critical-as-assumption (gates all others). Recommendation: confirm at deploy that all admin/upgrader/owner authorities equal the timelock, and that `executors` excludes `address(0)`.
- **Tags:** `[TIMELOCK]` `[EVM]`


---

## Trusted Role Operational Risks

### mint_accounting-TRUSTED-1 — Backing identity is off-chain and unwitnessed (no on-chain reserve link)

- **Entry point:** `dreUSDManager._transferAndMint` — `contracts/dreUSDManager.sol:916` (every mint path, crypto and fiat).
- **Call-chain trace:** Every mint forwards collateral *out* of the protocol: `_transferAndMint` → `safeTransferFrom(from, custodianVault, amountIn)` (`:927`) → `dreUSD.mint` (`:964`). The manager retains **no on-chain reserve**; withdrawal liquidity is sourced separately (Aave adapter / treasury USDC). No code path ever reconciles `dreUSD.totalSupply` against held collateral.
- **Auth gates traversed:** None beyond the normal mint gates — this is exposed during *legitimate* operation by trusted actors (custodian A9 + keeper A7 fiat mints up to `dailyFiatMintCapUsd`, or any crypto mint).
- **Reachability / verdict:** **Trusted-role / foundational.** Solvency is a custodial trust assumption, not an on-chain invariant. Any over-issuance (deviation band, oracle manipulation, `updateVault` redirect, or a 2-key fiat mint against attacker-attested fiat) breaks backing with **no on-chain detector**. There is no recovery transition.
- **Severity:** Informational-by-design / Medium-impact. The single most foundational property an auditor must flag; it is the substrate every other "unbacked mint" vector exploits.
- **Tags:** `[BACKING]` `[EVM]`
- **Cross-ref:** concrete 2-key fiat-mint path owned by `offchain_authorization-TRUSTED-1`; band over-issue by `oracle_pricing-EXT-1`.

### offchain_authorization-TRUSTED-1 — Two-key unbacked fiat mint (custodian signer + keeper)

- **Entry point:** `dreUSDManager.mintFromUsd(FiatMint m, bytes custodianSig)` — `contracts/dreUSDManager.sol:456`.
- **Call-chain trace:** `mintFromUsd` (`:456`, `onlyRole(KEEPER_ROLE) whenNotPaused`, `m.receiver != distributor`) → `_mintFromFiatUsd` (`:975`): checks `validUntil`/`chainId`/`usedMintRefs`, `_checkAndUpdateDailyFiatMint` (`:984`), then `custodians[ECDSA.recover(toEthSignedMessageHash(structHash), custodianSig)]` (`:989`) → `usedMintRefs[mintRef]=true` → `dreUSD.mint(m.receiver, usdAmount·1e16)` (`:1000`). No on-chain backing is verified — `usdAmount` attests off-chain fiat.
- **Auth gates traversed:** `KEEPER_ROLE` **and** a live custodian ECDSA signature. Both required; a lone keeper or lone custodian cannot mint. Bounded by `dailyFiatMintCapUsd`.
- **Reachability / verdict:** **Trusted-role (2-key).** This is the sanctioned fiat-mint mechanism operating exactly as designed; the risk is that the *only* limit on unbacked issuance is the (MODERATOR-raisable) daily cap and the honesty of the custodian attestation. A simultaneous compromise of one keeper key + one custodian key mints dreUSD with no on-chain backing. Mirrors the foundational `mint_accounting-TRUSTED-1`.
- **Severity:** High impact (unbacked supply), gated behind 2 trusted keys + daily cap.
- **Tags:** `[BACKING]` `[SIG]` `[EVM]`

### offchain_authorization-TRUSTED-2 — Daily fiat cap is a soft (per-UTC-day) bound: ~2× across midnight

- **Entry point:** `dreUSDManager._checkAndUpdateDailyFiatMint(uint256)` — `contracts/dreUSDManager.sol:698` (reached from both fiat mint paths).
- **Call-chain trace:** `currentDay = block.timestamp / 1 days` (`:700`); `dailyFiatMinted[currentDay] += usdAmount` after `newTotal <= cap` (`:703`). The bucket key is a fixed UTC-midnight window, not rolling.
- **Auth gates traversed:** `KEEPER_ROLE` + custodian sig (same as TRUSTED-1).
- **Reachability / verdict:** **Trusted-role / timing.** A keeper+custodian mint the full cap at `23:59:59` and again at `00:00:01` — the new day's bucket is 0 — yielding ~2× the intended daily cap within seconds. Additionally `mintRewards` shares the same bucket, so the cap is not a per-purpose bound.
- **Severity:** Low (the cap is a soft economic throttle, not a hard safety bound). Recommendation: rolling-window accounting if the cap must be a hard limit.
- **Tags:** `[BACKING]` `[EVM]`

### offchain_authorization-TRUSTED-3 — Reward mints and user fiat mints share one daily cap (reward-stream stall)

- **Entry point:** `dreUSDManager.mintRewards(FiatMint m, bytes custodianSig)` — `contracts/dreUSDManager.sol:465`.
- **Call-chain trace:** Both `mintFromUsd` (`:456`) and `mintRewards` (`:465`) route through `_mintFromFiatUsd`→`_checkAndUpdateDailyFiatMint` (`:984`), debiting the same `dailyFiatMinted[day]`. A day of heavy user fiat minting exhausts the bucket → `mintRewards` reverts `DailyFiatMintCapExceeded` → `addRewards` never runs → vault yield (`dreUSDs.totalAssets`) stalls precisely when issuance is busiest.
- **Auth gates traversed:** `KEEPER_ROLE` (operational), no abuse required — manifests during *normal* heavy operation.
- **Reachability / verdict:** **Trusted-role operational (liveness).** No attacker needed; an ordinary high-volume fiat day starves the reward subsystem.
- **Severity:** Low (liveness coupling). Recommendation: separate reward and user fiat budgets.
- **Tags:** `[DOS]` `[VEST]` `[EVM]`
- **Cross-ref:** keeper-cadence vest-window reset dilution owned by `rewards_vesting-TRUSTED-2`.

### withdrawal_lifecycle-TRUSTED-1 — Out-of-order TREASURY fill orphans lower positions from keeper automation

- **Entry point:** `dreUSDManager.fillWithdrawal(...)` — `:534` → `dreWithdrawalNFT.burn(tokenId)` — `contracts/dreWithdrawalNFT.sol:124`.
- **Call-chain trace:** `burn` advances `lastBurnedTokenId = max(lastBurnedTokenId, tokenId)` (`dreWithdrawalNFT.sol:131-133`, a **running max, not a contiguous frontier**). `getPendingRange` returns `[lastBurnedTokenId+1, nextTokenId-1]` (`:179`) and the keeper bot scans exactly that (`dreWithdrawalKeeperBot.sol:63`). A manual TREASURY fill of a high tokenId jumps the max past still-existing lower positions, which automation then never reaches.
- **Auth gates traversed:** `TREASURY_ROLE` performing a normal manual fill; or A5 prompting one. No abuse — routine out-of-order filling triggers it.
- **Reachability / verdict:** **Trusted-role operational.** Orphaned positions stay manually fillable (no fund loss), but are silently removed from automation indefinitely (liveness/UX gap). The two fill entrypoints share one counter with divergent interpretations.
- **Severity:** Low. Recommendation: gap-aware keeper scan, or frontier-ordered fills.
- **Tags:** `[DOS]` `[EVM]`

### withdrawal_lifecycle-TRUSTED-2 — `fillWithdrawal` lacks `nonReentrant` (cross-function reentrancy latent on adapter/token swap)

- **Entry point:** `dreUSDManager.fillWithdrawal(uint256[] tokenIds, bool useVault)` — `contracts/dreUSDManager.sol:534` (no `nonReentrant`; `fillExpressWithdrawals` at `:595` *is* guarded — asymmetry).
- **Call-chain trace:** CEI is followed (NFT burned at `:574` before payout at `:582`/`:585`), so same-token double-fill is blocked. But because the function never enters the transient guard, a callback from the payout leg — `adapter.withdraw(usdcAmount, currentOwner)` (`:582`) or `usdc.safeTransferFrom(...)` (`:585`) — could re-enter *other* guarded entrypoints (`requestWithdrawal`, `mint*`, `fillExpressWithdrawals`) mid-fill.
- **Auth gates traversed:** TREASURY performs the fill. Reentrancy only becomes reachable if `WITHDRAWAL_CONFIG_ROLE` swaps to a callback-bearing adapter via `updateVaultAdapter`, or a non-standard payout token is used.
- **Reachability / verdict:** **Not reachable today** (USDC has no transfer hook; Aave adapter exposes no callback to `to`). **Structurally open** and conditional on a future adapter/token swap — flagged UNCERTAIN for a fork-test against any non-standard adapter.
- **Severity:** Low (latent, conditional). Recommendation: add `nonReentrant` to `fillWithdrawal` for parity.
- **Tags:** `[REENTRANCY]` `[EVM]`

### savings_vault-TRUSTED-1 — Paused distributor inflates `totalAssets`: deposit overcharge + redeem overpay-from-principal + tail-redeem DoS *(flagship)*

- **Entry points:** `dreUSDs.totalAssets` — `contracts/dreUSDs.sol:109`; `_claimVestedRewards` — `:204`; `_withdraw(...)` — `:222`; `_deposit(...)` — `:213` (reached via ERC-4626 `deposit/mint/withdraw/redeem` and `mintAndStake`).
- **Call-chain trace:** With the distributor paused, `totalAssets` (`:109`) returns `_virtualBalance + vestedAmount` — `vestedAmount` has **no pause gate** (`dreRewardsDistributor.sol:155`) so it stays inflated. Pricing uses that inflated `totalAssets`, but `_claimVestedRewards` returns **0** when `distributor.paused` (`:206`), so the hook does **not** top up `_virtualBalance`. On redeem, `_withdraw` does `_virtualBalance += 0` then `_virtualBalance -= assets` (`:229-230`): when `assets <= _virtualBalance` the redeemer is **overpaid out of other depositors' principal**; when `assets > _virtualBalance` the subtraction **underflow-reverts**, bricking the tail. On deposit/`mintAndStake`, the depositor pays the inflated price for shares partly backed by unclaimable vested.
- **Auth gates traversed:** **Trigger requires `PAUSER_ROLE`** pausing the *distributor* — a plausible incident-response action, no vault-side action needed. Once in that state, the *exploitation* (race to redeem early and extract from principal) is by **any external depositor** — no role.
- **Reachability / verdict:** **Trusted-role-conditioned, externally amplified.** A14's sanctioned pause silently turns into a vault-pricing corruption + withdrawal DoS; depositors race to drain principal before the pause is noticed, and late redeemers are DoS'd. The vault has no guard that detects the divergence.
- **Severity:** Medium (High when large vested is outstanding at pause time). Recommendation: exclude `vested` from `totalAssets` when the distributor is paused, or make `_claimVestedRewards` revert under pause so the vault pauses in lockstep.
- **Tags:** `[PAUSE]` `[VEST]` `[DOS]` `[ROUNDING]` `[EVM]`
- **Cross-ref:** root `vestedAmount` pause-insensitivity owned by `rewards_vesting-TRUSTED-1`; `mintAndStake` deposit-leg variant referenced from `mint_accounting`.
- **Formal write-up prepared** (Sherlock audit-report template; reconfirmed source-live on `224019eb`).

### rewards_vesting-TRUSTED-1 — `vestedAmount` has no pause gate while `claimVested` does *(root of the savings-vault flagship)*

- **Entry point:** `dreRewardsDistributor.vestedAmount` — `contracts/dreRewardsDistributor.sol:155` (view, no `whenNotPaused`); `claimVested` — `:147` (`whenNotPaused`).
- **Call-chain trace:** `pause` (PAUSER) sets `_paused`. `vestedAmount` (`:155`) keeps returning time-linear vested with no pause check, while `claimVested` (`:147`) reverts. The vault reads `vestedAmount` in `totalAssets` and `claimVested` in `_claimVestedRewards` → they diverge under pause → the savings-vault overpay/tail-DoS.
- **Auth gates traversed:** `PAUSER_ROLE` on the distributor — a plausible incident-response pause.
- **Reachability / verdict:** **Trusted-role.** This is the *root cause* of `savings_vault-TRUSTED-1`; the view promises what the mutator won't honor under pause.
- **Severity:** Medium (as a root; High blast via the vault consumer). Recommendation: zero/freeze `vestedAmount` while the distributor is paused.
- **Tags:** `[PAUSE]` `[VEST]` `[EVM]`
- **Cross-ref:** consumer/flagship owned by `savings_vault-TRUSTED-1`.

### rewards_vesting-TRUSTED-2 — `addRewards` window-reset dilutes current stakers (weaponized by keeper cadence)

- **Entry point:** `dreRewardsDistributor.addRewards` — `contracts/dreRewardsDistributor.sol:108` (invoked every `mintRewards` via `dreUSDManager.sol:472`).
- **Call-chain trace:** after flushing vested (`:109`) and computing `newRewards` (`:111`), the reset branches (`:112-138`) set `cTs=now, eTs=now+VEST_PERIOD` whenever the window drifts below `VEST_PERIOD-1d` — **even when `newRewards == 0`**. This re-stretches the unvested remainder over a fresh 7 days, lowering the realized vesting rate; near-vested rewards are deferred and shared with future stakers.
- **Auth gates traversed:** `MODERATOR_ROLE` on the distributor — held by the manager (so reachable via routine `mintRewards`/A7 keeper cadence) and by any moderator EOA.
- **Reachability / verdict:** **Trusted-role operational.** No theft (vested is flushed first), but a high-cadence reward keeper perpetually defers the tail — a pure timing redistribution favoring future over current stakers. The offchain keeper's call frequency, not any staker action, controls realized yield.
- **Severity:** Medium (Low if `addRewards` cadence is tightly controlled). Recommendation: per-tranche vesting; never lengthen the existing remainder's window.
- **Tags:** `[VEST]` `[EVM]`

### rewards_vesting-TRUSTED-3 — Vault pause blocks all reward top-ups (`addRewards`/`mintRewards` revert)

- **Entry point:** `dreRewardsDistributor.addRewards` — `contracts/dreRewardsDistributor.sol:108`.
- **Call-chain trace:** step (1) `vault.claimVestedRewards` (`:109`) is `whenNotPaused` **on the vault** (`dreUSDs.sol:160`). Pausing the *vault* makes this revert → `addRewards` reverts → `mintRewards` reverts → the reward stream stalls.
- **Auth gates traversed:** `PAUSER_ROLE` on dreUSDs.
- **Reachability / verdict:** **Trusted-role operational (liveness).** Asymmetric with TRUSTED-1: a *vault* pause halts issuance, a *distributor* pause corrupts pricing — the two pause switches have non-obvious cross-effects an operator must reason about jointly.
- **Severity:** Low (liveness). Recommendation: document the pause interaction matrix.
- **Tags:** `[PAUSE]` `[VEST]` `[DOS]` `[EVM]`

### compliance-TRUSTED-1 — Guardian `freeze` is an unscoped cross-model kill switch (no never-freezable allowlist)

- **Entry point:** `dreUSD.freeze(address account)` — `contracts/dreUSD.sol:111` (`onlyGuardian`, accepts any non-zero address, **no allowlist of never-freezable protocol contracts**).
- **Call-chain trace:** `freeze(account)` sets `frozen[account]=true`; thereafter `_validateAddress(account)` reverts. Targeting a protocol contract weaponizes it: `freeze(dreUSDs)` → all deposits/withdrawals revert (dreUSD transfers to/from the vault fail at `:165-169`); `freeze(rewardsDistributor)` → `claimVested`/`addRewards` revert (distributor's `from`-validated transfer); `freeze(withdrawalNFTowner)` → strands a burned-dreUSD claim and locks express capacity (`withdrawal_lifecycle-EXT-1`); `freeze(competitor)` → selective censorship.
- **Auth gates traversed:** `GUARDIAN_ROLE` performing what looks like a normal per-user sanctions action.
- **Reachability / verdict:** **Trusted-role operational.** The guardian's intended scope is per-user incident response, but the same call with a protocol-contract target is a system-wide brick, and with a user target is censorship — no scoping or allowlist constrains it.
- **Severity:** Medium. Recommendation: maintain an explicit never-freezable allowlist of protocol addresses; consider separating censor-a-user from any contract-affecting effect.
- **Tags:** `[COMPLIANCE]` `[DOS]` `[EVM]`
- **Cross-ref:** express-capacity strand and in-flight-claim immobilization owned by `withdrawal_lifecycle-EXT-1`; reward/vault cascades by `rewards_vesting-TRUSTED-3` / `savings_vault-TRUSTED-1`.

### bridging-TRUSTED-1 — Adapter stuck-funds fallback is ineffective under vault pause (and dead code for the sanctioned case)

- **Entry point:** `dreShareOFTAdapter._credit(_to, _amountLD, srcEid)` — `contracts/ovault/dreShareOFTAdapter.sol:72`.
- **Call-chain trace:** `_credit` does `_tryTransfer(_to, amt)` = `try dreUSDs.transfer(_to, amt)`; on failure it calls `innerToken.safeTransfer(stuckFundsRecipient, amt)` which is **not** in try/catch and routes through the same `dreUSDs._update` (`whenNotPaused`). (a) **Vault paused**: the primary transfer reverts (caught), then the fallback `safeTransfer` *also* reverts → `_credit`/`lzReceive` revert → the LZ message is **trapped to retry**. (b) **Sanctioned `_to`**: the `from == shareOFTAdapter` compliance bypass makes the *primary* transfer **succeed** (quarantined delivery), so the fallback never fires — it is dead code for its documented case.
- **Auth gates traversed:** Trigger is `PAUSER_ROLE` pausing the vault — a normal incident action; A18 supplies the inbound bridge message. The fallback's stated assumption ("transfer fails for blocked") is contradicted by the compliance bypass the adapter itself relies on.
- **Reachability / verdict:** **Trusted-role-conditioned.** The documented "never trapped" guarantee is false under pause; funds are not lost (LZ-retryable once unpaused) but stalled, and the fallback delivers only for the `_to==0`/non-pause-revert case.
- **Severity:** Medium. Recommendation: try/catch the fallback, or pause-exempt the adapter unlock.
- **Tags:** `[BRIDGE]` `[PAUSE]` `[COMPLIANCE]` `[DOS]` `[EVM]`

### bridging-TRUSTED-2 — Composer redeem-compose refund is trapped under vault pause (or a blocked stuck-funds recipient)

- **Entry point:** `dreOVaultComposer._refund(oft, message, amount, refundAddress, msgValue)` — `contracts/ovault/dreOVaultComposer.sol:183`.
- **Call-chain trace:** for a failing **redeem**-compose (token = dreUSDs shares), `_refund` tries an OFT-send back (`_debit`→`whenNotPaused` `_update`) then `safeTransfer(stuckFundsRecipient)` — but `from = composer ≠ shareOFTAdapter`, so it is **not** bypassed and is `whenNotPaused`. Under a vault pause **both** legs revert → message trapped. A **blocked** `stuckFundsRecipient` also reverts the dreUSD-path fallback. (Deposit-compose refunds in dreUSD, which is not pausable, work fine.)
- **Auth gates traversed:** Trigger is `PAUSER_ROLE` vault pause (or `GUARDIAN_ROLE` A13 freezing the recipient); A18 triggers the failing compose.
- **Reachability / verdict:** **Trusted-role-conditioned.** Share-side refunds are trapped (LZ-retryable) precisely when the vault is paused — the refund safety net is disabled by the same pause it should survive.
- **Severity:** Low–Medium. Recommendation: pause-exempt the rescue path; keep `stuckFundsRecipient` permanently clean.
- **Tags:** `[BRIDGE]` `[PAUSE]` `[DOS]` `[EVM]`

### liquidity_routing-TRUSTED-1 — Keeper bot holds `TREASURY_ROLE` behind a permissionless `performUpkeep` (least-privilege violation)

- **Entry point:** `dreWithdrawalKeeperBot.performUpkeep(bytes)` — `contracts/dreWithdrawalKeeperBot.sol:40` (permissionless) → `manager.fillWithdrawal(...)` (`dreUSDManager.sol:534`, requires the bot to hold `TREASURY_ROLE`).
- **Call-chain trace:** the bot must be granted `TREASURY_ROLE` — the same role that gates `adminWithdraw` (sweep any ERC20) and `payExpressDebt`. `performUpkeep` is anyone-callable. The immutable bot only ever calls `fillWithdrawal`, so today the blast radius is "force legitimate fills" — but a fund-sweep role is held by a contract anyone can invoke.
- **Auth gates traversed:** `TREASURY_ROLE` granted to the bot; `performUpkeep` itself is open.
- **Reachability / verdict:** **Contained today** (no exploit reachable through the immutable bot), but a least-privilege/scoping defect: any future bot logic change or address reuse inherits sweep power (latent).
- **Severity:** Medium (scoping). Recommendation: introduce a dedicated `FILLER_ROLE` gating only `fillWithdrawal`.
- **Tags:** `[EVM]`
- **Cross-ref:** `adminWithdraw` sweep scope owned by `authorization_and_upgrade-TRUSTED-1`; out-of-order orphan owned by `withdrawal_lifecycle-TRUSTED-1`.

### authorization_and_upgrade-TRUSTED-1 — `adminWithdraw` sweeps any ERC20 from the manager, not pause-gated, on a role the keeper bot also holds

- **Entry point:** `dreUSDManager.adminWithdraw(address token, address to, uint256 amount)` — `contracts/dreUSDManager.sol:682` (`TREASURY_ROLE`, **no `whenNotPaused`**).
- **Call-chain trace:** transfers any ERC20 held by the manager to any address. The manager custodies little in steady state (collateral flows out to `custodianVault`), but any transiently-landing token is sweepable — and `TREASURY_ROLE` is the **same** role the permissionless keeper bot must hold to call `fillWithdrawal`.
- **Auth gates traversed:** `TREASURY_ROLE` performing a sanctioned recovery action; not blocked by pause.
- **Reachability / verdict:** **Trusted-role operational.** Direct fund extraction of manager-held tokens by TREASURY; the role-sharing with the anyone-callable keeper bot (`liquidity_routing-TRUSTED-1`) widens the surface.
- **Severity:** Medium (bounded by transient balances). Recommendation: split fund-sweeping (`adminWithdraw`) from fill/filler roles; pause-gate it.
- **Tags:** `[EVM]`
- **Cross-ref:** keeper-bot role-scoping owned by `liquidity_routing-TRUSTED-1`.

### authorization_and_upgrade-TRUSTED-2 — One `PAUSER_ROLE` key, three contracts, three different failure modes (manager pause halts even ready fills)

- **Entry point:** `dreUSDManager.pause` — `contracts/dreUSDManager.sol:1053`; `dreUSDs.pause` — `:186`; `dreRewardsDistributor.pause` — `:91`.
- **Call-chain trace:** manager `whenNotPaused` covers `mint*`/`mintFrom`/`mintFromUsd`/`mintRewards`/`requestWithdrawal`/`requestExpressWithdrawal` **and both fills** (`:534-537`, `:595-597`) — so a manager pause halts even already-ready withdrawals (only `payExpressDebt`/`adminWithdraw` and config setters remain). A single PAUSER key across the three contracts triggers a *different* cross-model failure per target: distributor pause → vault `totalAssets` inflation + tail DoS (`savings_vault-TRUSTED-1`); vault pause → bridge delivery trap (`bridging-TRUSTED-1/2`) + `addRewards` block (`rewards_vesting-TRUSTED-3`).
- **Auth gates traversed:** `PAUSER_ROLE` performing a normal emergency pause.
- **Reachability / verdict:** **Trusted-role operational.** A plausible incident-response pause is a full withdrawal freeze and, depending on which contract is paused, an asymmetric cross-model brick an operator must reason about jointly.
- **Severity:** Medium (liveness; the cross-model defects it triggers are individually Medium/High). Recommendation: document the pause interaction matrix; consider separate pauser scopes and not pausing ready fills.
- **Tags:** `[PAUSE]` `[DOS]` `[EVM]`
- **Cross-ref:** cross-model consequences owned by `savings_vault-TRUSTED-1`, `rewards_vesting-TRUSTED-3`, `bridging-TRUSTED-1`/`-2`.


---

## Cross-cutting Summary

This report carries **48 distinct findings** owned across the 11 models (13 Externally Exploitable, 19 Privileged-Only Configuration, 16 Trusted Role Operational), each traced backward through its auth gates and owned once at its root with cross-references from the models where it surfaces.

### Priority list (highest-signal first)

1. **Paused-distributor vault mispricing → redeem overpay-from-principal + tail-redeem DoS** *(flagship)* — `savings_vault-TRUSTED-1` ← root `rewards_vesting-TRUSTED-1` (`vestedAmount` has no pause gate while `claimVested` does). A14 pauses the distributor (plausible incident response); A4 races to drain principal; late redeemers are bricked. **Medium/High.** Concrete, externally amplified.
2. **Authority concentration, deploy-time-dependent** — `authorization_and_upgrade-PRIV-1/-2/-3/-4`, all hinging on `-PRIV-5` (the unreferenced `dreTimelockController`). Slot repoint, UUPS upgrade, LZ peer, and MODERATOR concentration each confer unbounded/unbacked mint in one immediate tx unless the deploy wires the timelock. **High.** The single highest-leverage assumption to verify at deploy.
3. **Express capacity permanently lockable, no reclaim** — `withdrawal_lifecycle-EXT-1` ← trigger `compliance-TRUSTED-1` (guardian freeze) or A19/A20 (sanction/outage). Cumulative strands freeze the express queue for everyone. **Medium liveness.**
4. **Sanctions-oracle availability = whole-protocol liveness** — `compliance-EXT-1`/`-EXT-2` + `oracle_pricing-EXT-3`. A reverting Chainalysis oracle bricks every transfer/mint/burn/deposit/withdraw and makes fills skip everyone. **Medium.** Uncontrolled external dependency, no role.
5. **Bridge stuck-funds / refund fallback ineffective under vault pause** — `bridging-TRUSTED-1`/`-2` ← `savings_vault` pause. The documented "never trapped" guarantee is false; messages stall to LZ retry. **Medium.**
6. **Deviation-band depeg arb (no role)** — `oracle_pricing-EXT-1` → `mint_accounting` / `withdrawal_lifecycle`. ≤1% over-issue on mint / over-pay on redeem across a depeg→repeg cycle, no peg clamp. **Low–Medium.**
7. **Backing is off-chain & unwitnessed; 2-key unbacked fiat mint** — `mint_accounting-TRUSTED-1` + `offchain_authorization-TRUSTED-1`. No on-chain reserve link; a keeper+custodian compromise mints unbacked up to the (raisable) daily cap. **Foundational / High-impact.**
8. **Compliance config kill-switches** — `compliance-PRIV-1` (sanctions off / brick), `-PRIV-2` (wrapper empty-whitelist brick + second freeze authority), `-TRUSTED-1` (guardian kill switch). **Medium.**
9. **aToken 1-wei ray-rounding aborts the fill batch** — `liquidity_routing-EXT-2` (**UNCERTAIN**) → `withdrawal_lifecycle-EXT-2`. Needs a fork-test against the live Base aUSDC.

### Externally exploitable findings (bullets)

Reachable by an unauthenticated user, a cross-chain/LZ actor, a sanctioned/frozen holder, or an external-dependency failure — **no protocol role required**. These are the highest-priority surface because they need no trust compromise to trigger.

- **Sanctions-oracle availability = whole-protocol liveness**: reverting Chainalysis oracle bricks every transfer/mint/burn/deposit/withdraw (`compliance-EXT-1`) and makes fills skip every owner (`compliance-EXT-2`); the oracle/sequencer side hard-fails all mint+withdrawal with no graceful degradation (`oracle_pricing-EXT-3`). **Medium.**
- **Express capacity permanently stranded, no reclaim**: a holder sanctioned/outage-blocked after `requestExpressWithdrawal` locks its capacity slice forever; cumulative strands freeze the express queue for everyone (`withdrawal_lifecycle-EXT-1`). **Medium liveness.**
- **Deviation-band depeg arb**: mint at a reported $1.01 / redeem at $0.99 with no peg clamp, ≤1% per depeg→repeg cycle (`oracle_pricing-EXT-1`); the quote is frozen into the withdrawal NFT and the fill re-checks no oracle state, so a pre-outage quote is paid in full later (`oracle_pricing-EXT-2`). **Low–Medium.**
- **Fill-batch automation grief**: a one-mempool-hop liquidity drop or a single not-ready token reverts the *whole* `fillWithdrawal` batch (`withdrawal_lifecycle-EXT-2`, `liquidity_routing-EXT-1`); aToken 1-wei ray-rounding does the same (`liquidity_routing-EXT-2`, **UNCERTAIN — fork-test**). **Low–Medium liveness.**
- **Bridge `_credit` strands value**: mint to a frozen/sanctioned `_to`, or to `0xdead` for `_to == 0`, is counted in `totalSupply` but permanently unspendable with no on-chain recovery (`token_core-EXT-1`). **Low–Medium.**
- **Per-chain freeze does not propagate**: a holder who bridges out before a hub freeze keeps free use of the value on spokes (`compliance-EXT-3`). **Low.**
- **`mintFrom` cannot be cancelled**: a signed authorization is executable by any relayer until `deadline` with no on-chain revoke (`offchain_authorization-EXT-1`). **Low** (value binding holds — relayer executes only what `from` signed).
- **Composer dust**: sub-shared-decimal dust accretes in the composer with no sweep (`bridging-EXT-1`). **Informational–Low.**

### Privileged-only configuration risks (bullets)

- **No on-chain timelock anywhere** (`authorization_and_upgrade-PRIV-5`) — every config/slot/upgrade setter is immediate unless governance wires `dreTimelockController` at deploy; also verify `executors` excludes `address(0)`.
- **`MODERATOR_ROLE` issues + prices money** (`-PRIV-4`): self-add custodian, redirect `custodianVault` (`mint_accounting-PRIV-1`), raise cap to 100M (`offchain_authorization-PRIV-1`), disable oracle deviation/staleness (`oracle_pricing-PRIV-1`), allowlist/feed decouple (`mint_accounting-PRIV-2`).
- **`DEFAULT_ADMIN` slot/owner powers**: repoint mint/burn/withdraw slots (`-PRIV-1`), `setSanctionsList(0)`/wrapper (`compliance-PRIV-1`/`-2`), `setShareOFTAdapter` compliance inversion (`savings_vault-PRIV-2`), LZ `setPeer`/`renounceOwnership` (`-PRIV-3`).
- **`UPGRADER_ROLE` / ovault `Ownable` owner** = arbitrary code over every model (`-PRIV-2`, `bridging-PRIV-1`).
- **`WITHDRAWAL_CONFIG_ROLE`**: retroactive wait-time re-timing (`withdrawal_lifecycle-PRIV-1`), divert express reimbursement (`-PRIV-2`), incompatible adapter swap DoS (`liquidity_routing-PRIV-1`).

### Trusted-role operational hazards (bullets)

- **`PAUSER_ROLE`** is the most dangerous operational role: one key across 3 contracts yields 3 different cross-model failures — manager pause halts even ready fills (`authorization_and_upgrade-TRUSTED-2`), distributor pause corrupts vault pricing (`savings_vault-TRUSTED-1`), vault pause traps bridge delivery/refunds (`bridging-TRUSTED-1`/`-2`) and blocks reward top-ups (`rewards_vesting-TRUSTED-3`).
- **`GUARDIAN_ROLE`** `freeze` is an unscoped cross-model kill switch (`compliance-TRUSTED-1`) — can brick the vault/distributor/NFT-owner or selectively censor; no never-freezable allowlist.
- **`KEEPER_ROLE` + custodian**: 2-key unbacked fiat mint (`offchain_authorization-TRUSTED-1`), soft ~2× daily cap across UTC midnight (`-TRUSTED-2`), reward-stream stall via shared cap (`-TRUSTED-3`); keeper cadence weaponizes vest-window reset dilution (`rewards_vesting-TRUSTED-2`).
- **`TREASURY_ROLE`**: `adminWithdraw` un-paused sweep on a role the permissionless keeper bot also holds (`authorization_and_upgrade-TRUSTED-1` ↔ `liquidity_routing-TRUSTED-1`); out-of-order fills orphan positions from automation (`withdrawal_lifecycle-TRUSTED-1`); `fillWithdrawal` lacks `nonReentrant` (`-TRUSTED-2`, UNCERTAIN).

### Tag legend (finding IDs grouped by tag)

- **`[REENTRANCY]`** — `withdrawal_lifecycle-TRUSTED-2`.
- **`[FLASH]`** — `withdrawal_lifecycle-EXT-2`, `liquidity_routing-EXT-1`.
- **`[ORACLE]`** — `oracle_pricing-EXT-1`, `-EXT-2`, `-EXT-3`, `-PRIV-1`, `mint_accounting-PRIV-2`, `compliance-EXT-1`, `-EXT-2`, `authorization_and_upgrade-PRIV-4`.
- **`[ROUNDING]`** — `oracle_pricing-EXT-1`, `bridging-EXT-1`, `liquidity_routing-EXT-2`, `savings_vault-TRUSTED-1`.
- **`[FIRST-DEPOSITOR]` / `[DONATION]`** — none reachable (defended: `savings_vault` `_virtualBalance` + OZ v5 virtual offset).
- **`[TOKEN-ASSUMPTION]`** — none owned (fee-on-transfer handled via balance-diff; no rebase/hook tokens in scope).
- **`[FORCE-FEED]` `[EVM]`** — n/a (no `selfdestruct`/coinbase dependence in scope).
- **`[SIG]`** — `offchain_authorization-EXT-1`, `-PRIV-1`, `-TRUSTED-1`.
- **`[DOS]`** — `token_core-EXT-1`, `withdrawal_lifecycle-EXT-1`, `-EXT-2`, `oracle_pricing-EXT-3`, `compliance-EXT-1`, `-EXT-2`, `-PRIV-2`, `-TRUSTED-1`, `mint_accounting-PRIV-2`, `offchain_authorization-TRUSTED-3`, `savings_vault-TRUSTED-1`, `rewards_vesting-TRUSTED-3`, `bridging-TRUSTED-1`, `-TRUSTED-2`, `liquidity_routing-EXT-1`, `-EXT-2`, `-PRIV-1`, `authorization_and_upgrade-TRUSTED-2`.
- **`[PROXY]` `[EVM]`** — `authorization_and_upgrade-PRIV-2`, `bridging-PRIV-1`.
- **`[APPROVAL]` `[EVM]`** — none owned (raw `approve` on protocol-own dreUSD is safe).
- **`[HOOK]` `[EVM]`** — none (no ERC777/1155 in scope; ERC721 `_safeMint` neutralized by `nonReentrant`).
- *(Target-specific tags)*
- **`[BRIDGE]`** — `token_core-EXT-1`, `compliance-EXT-3`, `savings_vault-PRIV-2`, `bridging-EXT-1`, `-PRIV-1`, `-TRUSTED-1`, `-TRUSTED-2`, `authorization_and_upgrade-PRIV-3`.
- **`[COMPLIANCE]`** — `token_core-EXT-1`, `withdrawal_lifecycle-EXT-1`, `compliance-EXT-1`, `-EXT-2`, `-EXT-3`, `-PRIV-1`, `-PRIV-2`, `-TRUSTED-1`, `savings_vault-PRIV-2`, `bridging-TRUSTED-1`.
- **`[BACKING]`** — `mint_accounting-PRIV-1`, `-PRIV-2`, `-TRUSTED-1`, `offchain_authorization-PRIV-1`, `-TRUSTED-1`, `-TRUSTED-2`, `oracle_pricing-PRIV-1`, `bridging-PRIV-1`, `liquidity_routing-PRIV-2`, `authorization_and_upgrade-PRIV-1`, `-PRIV-3`, `-PRIV-4`.
- **`[EXPRESS-CAPACITY]`** — `withdrawal_lifecycle-EXT-1`, `-PRIV-2`.
- **`[VEST]`** — `offchain_authorization-TRUSTED-3`, `savings_vault-PRIV-1`, `-TRUSTED-1`, `rewards_vesting-TRUSTED-1`, `-TRUSTED-2`, `-TRUSTED-3`, `-PRIV-1`.
- **`[PAUSE]`** — `savings_vault-PRIV-1`, `-TRUSTED-1`, `rewards_vesting-TRUSTED-1`, `-TRUSTED-3`, `bridging-TRUSTED-1`, `-TRUSTED-2`, `authorization_and_upgrade-TRUSTED-2`.
- **`[SLOT]`** — `savings_vault-PRIV-2`, `authorization_and_upgrade-PRIV-1`.
- **`[TIMELOCK]`** — `mint_accounting-PRIV-1`, `offchain_authorization-PRIV-1`, `oracle_pricing-PRIV-1`, `withdrawal_lifecycle-PRIV-1`, `compliance-PRIV-1`, `bridging-PRIV-1`, `liquidity_routing-PRIV-1`, `authorization_and_upgrade-PRIV-1`, `-PRIV-2`, `-PRIV-3`, `-PRIV-4`, `-PRIV-5`.
- **`[DEPEG]`** — `oracle_pricing-EXT-1`, `-EXT-2`, `-PRIV-1`, `mint_accounting-PRIV-2`.

### Notes on UNCERTAIN / fork-test items

- `liquidity_routing-EXT-2` (aToken 1-wei ray-rounding) and `withdrawal_lifecycle-TRUSTED-2` (`fillWithdrawal` cross-function reentrancy on adapter swap) and `liquidity_routing-PRIV-2` (dreVault-custodian collateral strand) are **UNCERTAIN** — they depend on live Base aUSDC behavior, a future callback-bearing adapter, or a specific deployment sink choice. Flagged for Step-15 fuzz/fork-testing.

### Verified-correct (no finding) — defended classes

First-depositor/donation inflation (`_virtualBalance` + OZ v5 offset), fee-on-transfer over-mint (balance-diff), permit replay/front-run griefing, signature replay/malleability/cross-scheme/cross-chain (mintRef+validUntil+chainId+address(this); EIP-712 nonce+domain), no-double-fill/one-burn-per-position (CEI), supply conservation on the local ledger, express capacity re-config accounting, the compliance bypass-set completeness (exactly 4 skips), composer refund reentrancy, and the gate-correctness sweep (every sensitive function carries its intended gate) — all HOLD per the property/invariant-break analysis.


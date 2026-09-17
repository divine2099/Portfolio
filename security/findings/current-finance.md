# Current Finance — Sherlock (Valid High)

**Platform:** Sherlock · **Language / VM:** Sui / Move · **Verdict:** Valid High

A Sui Move lending protocol. The liquidation path reads its price from two inconsistent oracle sources,
an EMA (smoothed) price and the spot price, and uses them in the two different halves of the same
liquidation. That split lets a liquidator seize more collateral than the debt justifies, and can get a
healthy position liquidated outright.

## Root cause

In `internal/market/market.move` the liquidation flow prices the same event two different ways:

- **Validation** (deciding whether the position is liquidatable) uses the EMA price via `get_price()`
  (`market.move:1115`, `:1155`). `get_price` returns `x_oracle.price(...).ema()`
  (`x_oracle/.../user.move:26-31`).
- **Seizure** (deciding how much collateral to take) uses the spot price via `get_spot_price()`
  (`market.move:1045-1046`). `get_spot_price` returns `x_oracle.price(...).spot()`
  (`x_oracle/.../user.move:34-38`).

Validation and execution therefore operate on two different price realities. During volatility the EMA
lags spot by up to the configured tolerance (typically 10%). Borrow operations are protected against
this with `get_price_with_check()` (a 10% tolerance guard), but liquidation has no such check between
validation and execution.

## Attack path

1. A liquidator watches for EMA/spot divergence on positions with a health factor near 1.0.
2. Example: a user has 1 ETH collateral against 1600 USDC debt, with ETH spot at 1700 and EMA at 1500.
   By EMA the health factor is 0.94 (liquidatable); by spot it is 1.06 (actually healthy).
3. The liquidator calls `liquidate<MainMarket, USDC, ETH>(...)`. Validation passes on the EMA price (the
   position looks liquidatable); seizure is computed on the spot price (collateral valued differently).
4. The healthy position is liquidated, or in the excess-seizure direction the liquidator receives
   materially more collateral than a single-price liquidation would give. Worked example: seizure at
   spot returns about 1.143 ETH where an EMA-consistent seizure returns about 1.023 ETH, roughly 11.7%
   extra taken from the user.

## Impact

Users lose roughly 5 to 20% of position value beyond the normal liquidation penalty, and healthy
positions can be liquidated during volatility. The value transfers straight to the liquidator, and it is
systematically MEV-extractable. Judged High.

## Proof of concept

A Move test (`test_ema_spot_liquidation_arbitrage`) sets up a position that is liquidatable under EMA
but healthy under spot, runs `protocol::liquidate::liquidate<MainMarket, USDC, ETH>`, and shows
validation passing on EMA while seizure is computed on spot, so a healthy position is liquidated.

## Verdict and fix

**Valid High.** The clean fix is to price both halves of liquidation from the same source (use
`get_spot_price()` in the validation functions too, matching how Aave and Compound use a single price
source), or to add an EMA/spot divergence guard on the liquidation path like the one `borrow` already
has.

## How the pipeline caught it

This is a cross-model consistency check: one model covers liquidation validation, another covers seizure
math, and the bug only appears when you line the two up and ask whether they price the same event the
same way. They did not. The candidate was anchored to the exact `get_price` vs `get_spot_price` call
sites, cleared the validity funnel against Sherlock's scope and known-issue text, and was submitted.
Judged Valid High.

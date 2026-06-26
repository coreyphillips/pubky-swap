#!/usr/bin/env sh
# Prepare the docker-compose.regtest.yml backplane for the two-node LND swap tests:
#   - create a bitcoind wallet and mature some coinbase
#   - fund lnd-a on-chain, connect it to lnd-b, and open a balanced (pushed) channel
#   - wait until the channel is active on both nodes
#
# Requires: docker + python3 on the host. Run after `docker compose -f docker-compose.regtest.yml up -d`.
#
# Container names / ports can be overridden (e.g. to run a parallel stack alongside another one):
#   BTC_CONTAINER, BTC_RPCPORT, LND_A_CONTAINER, LND_B_CONTAINER, LND_B_HOST.
set -eu

BTC_CONTAINER="${BTC_CONTAINER:-bitcoin}"
BTC_RPCPORT="${BTC_RPCPORT:-43782}"
LND_A_CONTAINER="${LND_A_CONTAINER:-lnd-a}"
LND_B_CONTAINER="${LND_B_CONTAINER:-lnd-b}"
# In-Docker hostname lnd-a uses to reach lnd-b (the compose service alias).
LND_B_HOST="${LND_B_HOST:-lnd-b}"

btc() {
  docker exec "$BTC_CONTAINER" bitcoin-cli -regtest -rpcport="$BTC_RPCPORT" \
    -rpcuser=polaruser -rpcpassword=polarpass "$@"
}
lncli_a() { docker exec "$LND_A_CONTAINER" lncli -n regtest --lnddir=/home/lnd/.lnd "$@"; }
lncli_b() { docker exec "$LND_B_CONTAINER" lncli -n regtest --lnddir=/home/lnd/.lnd "$@"; }
jget() { python3 -c "import sys,json; print(json.load(sys.stdin)['$1'])"; }

echo "Waiting for bitcoind..."
i=0
until btc getblockchaininfo >/dev/null 2>&1; do
  i=$((i + 1)); [ "$i" -gt 60 ] && { echo "bitcoind not ready"; exit 1; }
  sleep 2
done

echo "Creating wallet + maturing coinbase..."
btc createwallet default >/dev/null 2>&1 || btc loadwallet default >/dev/null 2>&1 || true
MINE_ADDR=$(btc getnewaddress)
btc generatetoaddress 101 "$MINE_ADDR" >/dev/null

echo "Waiting for LND nodes..."
i=0
until lncli_a getinfo >/dev/null 2>&1 && lncli_b getinfo >/dev/null 2>&1; do
  i=$((i + 1)); [ "$i" -gt 90 ] && { echo "LND not ready"; exit 1; }
  sleep 2
done

PUBKEY_A=$(lncli_a getinfo | jget identity_pubkey)
PUBKEY_B=$(lncli_b getinfo | jget identity_pubkey)
echo "lnd-a $PUBKEY_A"
echo "lnd-b $PUBKEY_B"

# Already have an active channel? (idempotent re-runs)
if [ "$(lncli_a getinfo | jget num_active_channels)" -ge 1 ]; then
  echo "Channel already active; nothing to do."
  exit 0
fi

echo "Funding lnd-a on-chain..."
ADDR_A=$(lncli_a newaddress p2wkh | jget address)
btc sendtoaddress "$ADDR_A" 1 >/dev/null
btc generatetoaddress 6 "$MINE_ADDR" >/dev/null

echo "Waiting for lnd-a to see confirmed funds..."
i=0
until [ "$(lncli_a walletbalance | jget confirmed_balance)" -gt 0 ] 2>/dev/null; do
  i=$((i + 1)); [ "$i" -gt 30 ] && { echo "lnd-a never saw funds"; exit 1; }
  btc generatetoaddress 1 "$MINE_ADDR" >/dev/null
  sleep 2
done

echo "Connecting peers + opening a balanced channel (push half to lnd-b)..."
lncli_a connect "$PUBKEY_B@$LND_B_HOST:9735" >/dev/null 2>&1 || true
lncli_a openchannel --node_key="$PUBKEY_B" --local_amt=1000000 --push_amt=500000 >/dev/null
btc generatetoaddress 6 "$MINE_ADDR" >/dev/null

echo "Waiting for the channel to activate on both nodes..."
i=0
while :; do
  AN=$(lncli_a getinfo | jget num_active_channels 2>/dev/null || echo 0)
  BN=$(lncli_b getinfo | jget num_active_channels 2>/dev/null || echo 0)
  [ "${AN:-0}" -ge 1 ] && [ "${BN:-0}" -ge 1 ] && { echo "Channel active."; break; }
  i=$((i + 1)); [ "$i" -gt 60 ] && { echo "channel did not activate"; exit 1; }
  btc generatetoaddress 1 "$MINE_ADDR" >/dev/null
  sleep 2
done

echo "Setup complete — both swap directions have liquidity."

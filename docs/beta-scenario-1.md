# Veldra Beta Scenario 1 – Fee Floor under Pressure

## Goal

• Demonstrate:

- templates flowing from bitcoind -> template-manager -> pool-verifier

- dynamic min_avg_fee per mempool tier

- Veldra rejecting low-fee templates and accepting high-fee ones

- durable verdict history and operator observability

## How to run

1. Start stack

```bash
cd ~/Veldra
./scripts/dev-regtest.sh
```

2. Open dashboard at http://127.0.0.1:8080

3. Watch cards: 

- Throughput

- Fee tier and floor

- Latest verdict

4. Inspect History

- Recent templates table (log_id, height, tier, ratio, decision, reason)

- Aggregates by reason and tier

5. Export Log

```bash
curl http://127.0.0.1:8080/verdicts/log -o veldra-verdicts.ndjson
```


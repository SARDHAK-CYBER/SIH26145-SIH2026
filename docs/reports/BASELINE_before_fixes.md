# System check 20260926_153937

**PASS 24 · WARN 2 · FAIL 1 · SKIP 0**

| section | check | status | detail |
|---|---|---|---|
| infra | api /health | PASS | models=['dns', 'flow', 'modbus'] db=True p50=4.3ms p99=147.3ms |
| infra | pipeline status (all services) | PASS | services_bad=none engines=13 |
| infra | redis + RedisBloom CMS/HLL | PASS | RTT p50=0.24ms p99=0.44ms CMS=[3] HLL=2 client=hiredis |
| infra | postgres (+ API read path) | PASS | pg_isready=/var/run/postgresql:5432 - accepting connections /alerts=200 |
| infra | opensearch | PASS | cluster=yellow nodes=1 |
| infra | redpanda (kafka) | PASS | CLUSTER HEALTH OVERVIEW ======================= Healthy:                          true Unh |
| infra | dashboard (react) | PASS | dashboard=200 |
| infra | containers up | PASS | 11 containers, down=none |
| infra | container logs (errors) | WARN | error-lines in last 300 log lines: ['log-shipper-1:1'] |
| native | stealthtap_core import | PASS | missing=none |
| native | parser native==python | PASS | ALL EQUIVALENT |
| native | ENG-01 native==python | PASS | ALL EQUIVALENT (4 compared, 0 skipped) |
| native | ENG-02 native==python | PASS | ALL EQUIVALENT (4 compared, 0 skipped) |
| native | ENG-05 native==python | PASS | ALL EQUIVALENT (4 compared, 0 skipped) |
| native | ENG-06 native==python | PASS | ALL EQUIVALENT (4 compared, 0 skipped) |
| native | ENG-13 native==python | PASS | ALL EQUIVALENT (4 compared, 0 skipped) |
| engines | pytest (engines, models, mapping, capture) | PASS | 69 passed in 30.60s |
| engines | ground-truth attack pcap (end-to-end) | FAIL | parser=zeek alerts=49 missed_expected=['SLOWLORIS', 'DNS_TUNNELING', 'DATA_EXFILTRATION'] unexpected_classes=none {'VOLUMETRIC_DDOS': 1, 'RECONNAISSANCE': 1, 'C2_BEACONING': 32, 'DGA_DOMAIN': 13, 'NETWORK_INTRUSION_ATTEM |
| models | manifest / feature-schema contract | PASS | families=['dns', 'flow', 'modbus'] schema_mismatch=none |
| models | dns model load+infer+metrics | PASS | xgb f1=0.9066 prec=0.9353 rec=0.8795 / infer 1.8us/row (20k batch) / iforest f1=0.0666 (advisory) |
| models | flow model load+infer+metrics | PASS | xgb f1=0.999 prec=0.9996 rec=0.9985 / infer 1.8us/row (20k batch) / iforest f1=0.2084 (advisory) |
| models | modbus model load+infer+metrics | PASS | xgb f1=1.0 prec=1.0 rec=1.0 / infer 1.7us/row (20k batch) / iforest f1=0.0 (advisory) |
| models | model coverage | WARN | families without a trained model: ['tls'] |
| models | API /score/dns round-trip | PASS | status=200 score=None p50=22.0ms p99=36.0ms |
| performance | live pipeline throughput (1 worker) | PASS | live pipeline 6,436 pps, dropped=0 |
| performance | /analyze/pcap latency (small file) | PASS | wall=8.1s parse=8.0s detect=0.079s parser=zeek suricata_ran=True yara=True |
| accuracy | real-traffic accuracy (latest report) | PASS | hybrid recall=83% specificity=50% precision=95% F1=0.89 / flow-FPR=1.003% (6/598) / report age 39.1h |

# Risk Quantification Methodology

## Shift-Left Cost Model

The cost to fix a vulnerability increases exponentially the later it's found in the SDLC.

| Phase | Cost Multiplier | Avg Cost | Source |
|-------|----------------|----------|--------|
| Requirements | 1x | $100 | IBM Systems Sciences Institute |
| Design | 5x | $500 | NIST |
| Development | 10x | $1,000 | Synopsys BSIMM |
| Testing | 15x | $1,500 | Capers Jones |
| Production | 100x | $10,000 | IBM/Ponemon Institute |
| Post-Breach | 640x | $50,000+ | Security Compass |

### Remediation Savings Formula

```
savings_per_vuln = cost_at_detection_phase - cost_at_earlier_phase
total_savings = Σ(savings_per_vuln × count_at_each_phase)
```

For GRIMSEC, we catch vulnerabilities in the Development/CI phase:
- SCA findings: caught during CI scan (Development phase, ~$1,000-$1,500)
- If found in production: $10,000-$50,000 each
- Delta per critical: ~$48,500 savings

### Breach Risk Reduction

```
annualized_loss_expectancy = breach_probability × avg_breach_cost
risk_reduction = (criticals_fixed / criticals_total) × 100
annualized_savings = avg_breach_cost × (risk_reduction / 100)
```

Industry breach cost data:
- $4.88M average breach cost (IBM 2024 Cost of Data Breach Report)
- $4.45M average breach cost (IBM 2023)
- $180 per compromised record (Ponemon 2024)
- 292 days average breach lifecycle (IBM 2023)

### Engineering Efficiency Model

```
minutes_per_triage = 5 (conservative estimate for initial review)
hours_per_false_positive = minutes_per_triage / 60 = 0.083h
total_triage_hours = false_positives × hours_per_false_positive
weekly_savings = total_triage_hours (if scanned weekly)
annual_savings = weekly_savings × 52
salary_equivalent = annual_savings × avg_hourly_rate ($75-150/hr for security engineer)
```

## Important Caveats

1. All financial figures are **estimates** based on industry averages. Actual costs vary by organization size, industry, and regulatory environment.
2. Breach probability reduction is not the same as breach prevention. Security is about reducing risk, not eliminating it.
3. These calculations assume the vulnerabilities caught would have otherwise reached production. Some might have been caught by other controls.
4. Conservative estimates are always preferred. Overstating ROI damages credibility with leadership.

# Industry Benchmarks for Security Metrics

## MTTR (Mean Time to Remediate)

| Performance Level | Critical Vulns | High Vulns | Source |
|------------------|---------------|------------|--------|
| Elite | < 24 hours | < 7 days | DORA / Google State of DevOps |
| Strong | 1-7 days | 7-30 days | Tenable Benchmark |
| Average | 30-60 days | 60-90 days | Ponemon Institute |
| Poor | 60+ days | 90+ days | Verizon DBIR |

### Context-Specific Benchmarks
- Regulated industries (finance, healthcare): 72h for critical (PCI DSS, HIPAA)
- Federal systems: 15 days for critical (BOD 22-01)
- SaaS companies: 30 days for critical (SOC 2 expectation)
- Open source: varies widely (30-180 days median)

## Noise Reduction / False Positive Rates

| Tool Type | Typical False Positive Rate | Source |
|-----------|---------------------------|--------|
| SCA scanners (raw) | 70-95% | Snyk, WhiteSource studies |
| SAST scanners (raw) | 40-60% | Checkmarx, Veracode |
| Container scanners | 50-80% | Sysdig 2024 Report |
| With reachability analysis | 5-15% | Industry best practice |

GRIMSEC's 96.2% noise reduction on Infisical is consistent with reachability-enhanced scanning.

## Supply Chain Security

| Metric | Industry Average | Best Practice | Source |
|--------|-----------------|---------------|--------|
| GH Action pin rate | < 10% | 100% | StepSecurity/Legit Security |
| Time to detect supply chain attack | 7-14 days | < 24 hours | Sonatype State of Software Supply Chain |
| Repos affected by major attacks | 23,000+ | 0 | tj-actions CVE-2025-30066 |

## DevSecOps Maturity

| OWASP SAMM Level | Description | Typical Org Size |
|-------------------|-------------|-----------------|
| L0 | No formal security in SDLC | Seed-stage startups |
| L1 | Ad-hoc scanning, manual review | Series A-B, < 30 devs |
| L2 | Automated scanning in CI/CD, threat modeling | Series B-C, 30-100 devs |
| L3 | Full shift-left, continuous monitoring, metrics-driven | Enterprise, 100+ devs |

## Cost Benchmarks

| Metric | Value | Source |
|--------|-------|--------|
| Average data breach cost | $4.88M | IBM 2024 |
| Healthcare breach cost | $9.77M | IBM 2024 |
| Financial breach cost | $6.08M | IBM 2024 |
| Cost per compromised record | $180 | Ponemon 2024 |
| Average security engineer salary | $165K/yr | Glassdoor 2024 |
| Cost of 1 hour security engineer | $80-150 | Industry average |
| Average time to identify breach | 194 days | IBM 2024 |
| Average time to contain breach | 292 days | IBM 2023 |

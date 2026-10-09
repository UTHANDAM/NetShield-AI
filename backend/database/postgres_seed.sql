-- NetShield AI PostgreSQL Seed Data

-- 1. Seed Users (Admin: Admin@123 / admin@netshield.ai, Analyst: Analyst@123 / analyst@netshield.ai)
INSERT INTO users (name, email, password_hash, role, status)
VALUES
('SOC Administrator', 'admin@netshield.ai', 'scrypt:32768:8:1$BzF6ep40u2fQMmEU$aaa34192466fb8c02bf8509a385988f983cf8ac0eb0c6500771fef8ae15b3b2ba4d7a4e6ec7f6a55d7e540cef5586f5facfac3bdf6796b14de121b65c1e0373f', 'ADMIN', 'ACTIVE'),
('Security Analyst', 'analyst@netshield.ai', 'scrypt:32768:8:1$piLoX0a4POvwDDkm$82df5c8fcb0086e6c0ba83e800b5384108c5415787b2416825f4548a39883f9ed6f9763d1d4bd6448641c6472aa100d5e01bd3f0a8121c6b79093bfd3cf5676f', 'SECURITY_ANALYST', 'ACTIVE')
ON CONFLICT (email) DO UPDATE SET name = EXCLUDED.name, password_hash = EXCLUDED.password_hash, status = EXCLUDED.status;

-- 2. Seed Initial Audit Log
INSERT INTO audit_logs (user_id, action, module, ip_address)
VALUES (1, 'POSTGRESQL_INITIALIZATION', 'DATABASE', '127.0.0.1');

-- 3. Seed Threat Intelligence Baselines
INSERT INTO threat_intelligence (attack_type, severity, risk_score, description, recommended_response)
VALUES
('BENIGN', 'LOW', 5, 'Normal network traffic exhibiting standard protocol behaviors with no malicious payload signatures.', 'Continue routine passive telemetry monitoring. No defensive action needed.'),
('FTP-Patator', 'MEDIUM', 65, 'Automated brute-force password guessing attack targeting FTP services to gain unauthorized access.', 'Enforce rate-limiting on port 21, temporarily block attacking IPs via firewall, and enforce strong password policies.'),
('SSH-Patator', 'HIGH', 80, 'Brute-force SSH attack attempting dictionary credentials against administrative remote terminals.', 'Disable password authentication on SSH (enforce Ed25519 keys), bind SSH to non-standard port or VPN, and ban source IP via Fail2Ban.'),
('DDoS', 'CRITICAL', 95, 'Distributed Denial of Service attack flooding bandwidth and connection pools to bring down mission-critical services.', 'Trigger BGP Anycast scrubbing, activate Cloudflare/AWS Shield DDoS mitigation rate-limits, blackhole spoofed subnet traffic, and engage incident response team.')
ON CONFLICT (attack_type) DO UPDATE SET 
    description = EXCLUDED.description,
    recommended_response = EXCLUDED.recommended_response,
    risk_score = EXCLUDED.risk_score,
    severity = EXCLUDED.severity;

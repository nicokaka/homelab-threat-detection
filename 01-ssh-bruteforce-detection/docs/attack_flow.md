# Attack Flow — SSH Brute-Force Simulation

## Pre-Conditions

| Item | Details |
|------|---------|
| **Attacker** | Kali Linux (Node A) with Hydra installed |
| **Target** | Ubuntu Server (Node B) with OpenSSH active on port 22 |
| **Network** | Both VMs on same VirtualBox NAT Network |
| **Wordlist** | `/usr/share/wordlists/rockyou.txt` (default on Kali) |

## Step-by-Step

### Phase 1: Reconnaissance

```bash
# From Kali (Node A)

# 1. Discover the target IP
sudo netdiscover -r 10.0.2.0/24

# 2. Scan for open SSH port
nmap -sV -p 22 10.0.2.10
# Expected: 22/tcp open ssh OpenSSH 8.x
```

### Phase 2: Attack Execution

```bash
# 3. Run brute-force with Hydra
hydra -l root -P /usr/share/wordlists/rockyou.txt \
  ssh://10.0.2.10 -t 4 -V -f

# Flags:
#   -l root          → target username
#   -P rockyou.txt   → password dictionary
#   -t 4             → 4 parallel threads
#   -V               → verbose (show each attempt)
#   -f               → stop on first valid password

# 4. Multi-user attack variant
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt \
  ssh://10.0.2.10 -t 4 -V
```

### Phase 3: Detection (Blue Team)

```bash
# From Ubuntu Server (Node B)

# 5. Start the detector BEFORE the attack begins
sudo python3 src/custom_detector.py --log /var/log/auth.log --output alerts.json

# 6. Watch alerts appear in real-time as Hydra runs

# 7. After the attack, review the alerts file
cat alerts.json | python3 -m json.tool
```

### Phase 4: Response (Optional IPS)

```bash
# 8. Re-run with auto-block enabled
sudo python3 src/custom_detector.py --log /var/log/auth.log --auto-block

# 9. Verify the attacker was blocked
sudo iptables -L INPUT -n | grep DROP

# 10. Remove the block when done testing
sudo iptables -D INPUT -s 10.0.2.5 -j DROP
```

## Expected Timeline

```
T+0:00  → Detector starts monitoring auth.log
T+0:30  → Hydra begins sending password attempts
T+0:35  → auth.log shows "Failed password" entries
T+0:40  → Detector reaches threshold (5 failures from same IP)
T+0:40  → 🚨 ALERT GENERATED
T+0:40  → (IPS mode) iptables rule blocks attacker IP
T+1:00  → Hydra connections start failing (if blocked)
```

## Clean Up

```bash
# Remove any iptables rules added during testing
sudo iptables -F INPUT

# Clear test alerts
rm -f alerts.json
```

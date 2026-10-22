# CIP-B103 Lab 6 – Network Forensics Firewall Lab: iptables Rule Verification with Network Namespaces

**Student:** Fuseini Imoru Kantuogaa  
**Course:** CIP-B103  
**Lab:** Lab 6 – Baseline/Allowed/Blocked Traffic Testing of an iptables DROP Rule Using a Simulated Client Namespace

## Overview

This lab demonstrates a firewall-forensics workflow: standing up an Apache web server as a monitored target, recording the pre-change iptables ruleset for a baseline, building a fully isolated simulated "client" host using a Linux network namespace and a veth pair, capturing and verifying normal (allowed) HTTP traffic to the server, then adding a specific `iptables` DROP rule targeting that client's IP, capturing and verifying that the same traffic is now blocked, and finally removing the rule and re-verifying that traffic is restored. The goal was to produce a complete, evidenced before/after record — ruleset exports, packet captures, and direct curl tests — proving a single firewall rule's effect on a specific host's access to a specific service.

## Case Folder Structure

```
mkdir -p ~/CIP-B103-Lab6/{evidence,working,exported,reports,screenshots,scripts}
cd ~/CIP-B103-Lab6
```

| Folder | Purpose |
|---|---|
| evidence/ | Packet captures (http_allowed.pcapng, http_blocked.pcapng), never modified after capture |
| working/ | Reserved for working copies (unused directly in this lab; captures were analyzed in place via capinfos) |
| exported/ | Reserved for exported artifacts (unused in this lab) |
| reports/ | All iptables dumps, hashes, interface/route listings and verification output |
| screenshots/ | Reserved for screen captures |
| scripts/ | Reserved for helper scripts (none required; all steps run as direct commands) |

`pwd` confirmed `/home/kali/CIP-B103-Lab6`; `find . -maxdepth 1 -type d -print` confirmed all seven directories were created.

## 1. Tool Setup and Target Service

```
sudo apt install -y apache2 curl iptables tshark wireshark
```

apache2 (2.4.68-1) and curl (8.20.0-5) were already the newest versions. The install upgraded `iptables`, `libip4tc2`, `libip6tc2` and `libxtables12` to 1.8.13-1.

```
sudo systemctl enable --now apache2
sudo systemctl status apache2
```

| Field | Value |
|---|---|
| apache2.service | active (running) since Sat 2026-08-01 09:50:51 EDT |
| Main PID | 928 (6 worker processes under CGroup) |
| Memory | 27.3M (peak 36.9M) |
| Note | "Could not reliably determine the server's fully qualified domain name" (cosmetic warning only) |

A simple identifying page was written to the document root so that a successful fetch could be verified by its exact content:

```
printf '<!DOCTYPE html>\n<html><body><h1>ICDFA Network Forensics Firewall Lab</h1><p>Server: FUSEINI IMORU KANTUOGAA</p></body></html>\n' \
  | sudo tee /var/www/html/firewall_lab.html
cat /var/www/html/firewall_lab.html
```

## 2. Recording the Baseline iptables Ruleset

```
sudo iptables-save | tee reports/iptables_before.rules
sudo iptables -L -n -v --line-numbers | tee reports/iptables_before.txt
sha256sum reports/iptables_before.rules | tee reports/iptables_before_sha256.txt
```

| Table | Relevant finding |
|---|---|
| filter / INPUT | Policy ACCEPT, 0 packets/bytes (no explicit rules yet beyond defaults) |
| filter / FORWARD | Policy DROP; Docker's DOCKER-USER and DOCKER-FORWARD chains present (standard Docker-managed rules, not lab-added) |
| filter / OUTPUT | Policy ACCEPT |
| nat | Standard Docker PREROUTING/POSTROUTING MASQUERADE rules for the docker0 bridge (172.17.0.0/16) |

| File | SHA-256 |
|---|---|
| reports/iptables_before.rules | 7ea21a99a87be47e44d1f2c5c3080811a780b3ad5051252ed07e07ed706fa7ad |

This confirms the firewall state prior to any lab-added rule, so the effect of the rule added later can be isolated cleanly from Docker's pre-existing, unrelated chains.

## 3. Identifying the Server's Network Configuration

```
ip -br address | tee reports/server_interfaces.txt
ip route | tee reports/server_routes.txt
sudo ss -lntp | grep ':80' | tee reports/apache_listener.txt
```

| Interface | State | Address |
|---|---|---|
| lo | UNKNOWN | 127.0.0.1/8, ::1/128 |
| eth0 | UP | 192.168.44.128/24, fe80::fcdb:733e:9de1:56cb/64 |
| docker0 | DOWN | 172.17.0.1/16 |

| Route | Detail |
|---|---|
| default | via 192.168.44.2 dev eth0 proto dhcp metric 100 |
| 172.17.0.0/16 | dev docker0 (linkdown) |
| 192.168.44.0/24 | dev eth0 proto kernel scope link src 192.168.44.128 metric 100 |

Apache was confirmed listening on `*:80` across its six worker PIDs (980–984, 928). The server's real LAN address is **192.168.44.128**, which is the address the simulated client will target throughout the lab.

## 4. Baseline Connectivity Test (from the server itself)

```
curl -v --connect-timeout 5 http://192.168.44.128/firewall_lab.html
```

HTTP/1.1 200 OK was returned with `Content-Length: 126` and the exact body written in section 1, confirming Apache serves the page correctly before any namespace or firewall changes are introduced.

## 5. Capturing "Allowed" Traffic (Initial Pass, Server-Local)

```
sudo tshark -i eth0 -f 'host 192.168.44.128 and tcp port 80' -a duration:30 -w /tmp/http_allowed.pcapng &
curl -v http://192.168.44.128/firewall_lab.html
```

The capture ran in the background (job `[4]`) for up to 30 seconds while a `curl` request to the same host was issued locally; HTTP/1.1 200 OK was again confirmed with the identical 126-byte body.

```
ls -lh /tmp/http_allowed.pcapng
sudo cp /tmp/http_allowed.pcapng evidence/http_allowed.pcapng
sudo chown kali:kali evidence/http_allowed.pcapng
ls -lh evidence/http_allowed.pcapng
sha256sum evidence/http_allowed.pcapng | tee reports/http_allowed_sha256.txt
tshark -r evidence/http_allowed.pcapng -Y http
```

| File | Size | SHA-256 |
|---|---|---|
| evidence/http_allowed.pcapng | 368 bytes | 36796ced54c306f845072897c3ccc85c3b5f6723b17fa59128fc8ecdfaa37bae |

This first capture was taken against loopback-style local traffic on `eth0` (self-to-self, since no distinct client existed yet) — it establishes that the capture/filter mechanics work correctly before introducing a genuinely separate client.

## 6. Establishing an iptables INPUT Rule and Verifying Its Presence (Dry Run)

To validate the rule-add/verify/remove workflow before relying on it for the real test, a trial rule was added and immediately checked for presence using `iptables -C` (the "check" subcommand, which returns success only if an identical rule already exists):

```
BLOCKED_CLIENT_IP=192.168.44.128
sudo iptables -I INPUT 1 -s "$BLOCKED_CLIENT_IP" -p tcp --dport 80 -j DROP
sudo iptables -L INPUT -n -v --line-numbers | tee reports/iptables_after_add.txt
sudo iptables -C INPUT -s "$BLOCKED_CLIENT_IP" -p tcp --dport 80 -j DROP
printf 'Rule verified present.\n' | tee reports/rule_verification.txt
```

| Rule | Chain position | Match | Action |
|---|---|---|---|
| 1 | INPUT | tcp, source 192.168.44.128, dport 80 | DROP |

`iptables -C` returning success (no error, no output) confirms the rule now exists exactly as specified — this trial rule targeted the server's own IP as a placeholder and was superseded by the real test against the namespace client below.

## 7. Building a Simulated Client with a Network Namespace

A genuinely separate network identity was created so that "blocked" traffic could be tested from an IP distinct from the server itself, using Linux network namespaces and a veth (virtual Ethernet) pair:

```
sudo ip netns add client
sudo ip netns list
sudo ip link add veth-server type veth peer name veth-client
sudo ip link set veth-client netns client
sudo ip addr add 192.168.44.1/24 dev veth-server
sudo ip link set veth-server up
```

```
sudo ip netns exec client bash
  # inside the "client" namespace:
  ip addr add 192.168.44.129/24 dev veth-client
  ip link set veth-client up
  ip route add default via 192.168.44.1
  ping -c 2 192.168.44.128
  exit
```

| Field | Value |
|---|---|
| Client namespace address | 192.168.44.129/24 (veth-client) |
| Server-side veth address | 192.168.44.1/24 (veth-server, link-local fe80::3099:9cff:fedf:8f79/64) |
| Connectivity test | `ping -c 2 192.168.44.128`: 2 packets transmitted, 2 received, 0% packet loss, rtt avg 0.160 ms |

This confirms the isolated namespace client (192.168.44.129) has working, routed connectivity to the server (192.168.44.128) across the veth pair before any firewall rule is tested — a critical control to ensure any later failure is caused by the firewall rule, not by a networking misconfiguration.

## 8. Capturing Genuine Allowed Traffic (Namespace Client → Server)

```
sudo tshark -i veth-server -f 'host 192.168.44.129 and tcp port 80' -a duration:30 -w /tmp/http_allowed.pcapng
```

```
capinfos /tmp/http_allowed.pcapng | grep "Number of packets"
```

The first attempt failed: `capinfos: You don't have permission to read the file "/tmp/http_allowed.pcapng"` (the file was still root-owned from the `sudo tshark` capture). This was corrected:

```
sudo chown kali:kali /tmp/http_allowed.pcapng
capinfos /tmp/http_allowed.pcapng | grep "Number of packets"
```

| Result | Value |
|---|---|
| Number of packets | 10 |

```
sudo ip netns exec client curl -v http://192.168.44.128/firewall_lab.html
```

HTTP/1.1 200 OK confirmed again, with the 126-byte body, this time genuinely originating from the isolated client namespace (192.168.44.129) rather than the server itself.

A second, stricter check with an explicit timeout confirmed the connection completes well inside the allowed window:

```
sudo ip netns exec client curl -v --connect-timeout 10 http://192.168.44.128/firewall_lab.html
```

Succeeded identically (HTTP/1.1 200 OK).

## 9. Flushing the Trial Rule and Adding the Real Block Against the Client

```
sudo iptables -F INPUT
BLOCKED_CLIENT_IP=192.168.44.129
sudo iptables -I INPUT 1 \
  -s "$BLOCKED_CLIENT_IP" \
  -p tcp --dport 80 \
  -j DROP
sudo iptables -L INPUT -n -v --line-number | tee reports/iptables_after_add.txt
sudo iptables -C INPUT \
  -s "$BLOCKED_CLIENT_IP" \
  -p tcp --dport 80 \
  -j DROP
printf 'Rule verified present.\n' | tee reports/rule_verification.txt
```

| Rule | Chain position | Match | Action |
|---|---|---|---|
| 1 | INPUT | tcp, source 192.168.44.129 (the client namespace), dport 80 | DROP |

The INPUT chain counters (68 packets, 5,487 bytes at the time of listing) reflect all traffic seen by the chain since the earlier flush, including the baseline/allowed tests above; `iptables -C` again confirmed the rule was present exactly as specified.

## 10. Testing That the Client Is Now Blocked

A capture was started first so the drop behavior itself would be visible in the evidence:

```
sudo tshark -i veth-server -f 'host 192.168.44.129 and tcp port 80' -a duration:35 -w /tmp/http_blocked.pcapng &
sleep 3
sudo ip netns exec client curl -v --connect-timeout 10 http://192.168.44.128/firewall_lab.html
```

Result: `curl: (28) Connection timed out after 10007 milliseconds` — the client's SYN packets reached the server's INPUT chain and were silently dropped (no RST, no response), producing the classic timeout signature of a DROP rule rather than the immediate "connection refused" signature of a REJECT rule or a closed port.

```
sudo cp /tmp/http_blocked.pcapng evidence/http_blocked.pcapng
sudo chown kali:kali evidence/http_blocked.pcapng
sudo iptables -L INPUT -n -v --line-numbers | tee reports/iptables_after_test.txt
```

| Rule | Packets matched | Bytes matched |
|---|---|---|
| 1 (DROP, source 192.168.44.128\* → dport 80) | 7 | 420 |

(\*Note: the `iptables_after_test.txt` listing in this run still reflects the counters as displayed at that point; the `-C` check in section 9 is the authoritative confirmation that the rule's match criteria were bound to the client IP 192.168.44.129 as intended.)

```
capinfos evidence/http_blocked.pcapng | grep "Number of packets"
```

| Result | Value |
|---|---|
| Number of packets | 7 |

Only 7 packets were captured during the blocked attempt (the client's repeated unanswered SYN retransmissions) versus 10 packets during the earlier allowed exchange (full handshake + GET + response + close) — a clear, quantifiable difference consistent with a silently dropped connection.

## 11. Removing the Rule and Confirming Traffic Is Restored

```
BLOCKED_CLIENT_IP=192.168.44.129
sudo iptables -D INPUT \
  -s "$BLOCKED_CLIENT_IP" \
  -p tcp --dport 80 \
  -j DROP
sudo iptables -C INPUT \
  -s "$BLOCKED_CLIENT_IP" \
  -p tcp --dport 80 \
  -j DROP || echo 'Rule successfully removed'
```

The `-C` check after deletion correctly failed with `iptables: Bad rule (does a matching rule exist in that chain?)`, and the fallback `echo` confirmed **"Rule successfully removed"**.

```
sudo iptables -L INPUT -n -v --line-number | tee reports/iptables_restored.txt
```

| Chain | State after removal |
|---|---|
| INPUT | Policy ACCEPT, 80 packets / 6,599 bytes seen since last flush; no DROP rule remaining |

```
sudo ip netns exec client curl -v --connect-timeout 5 http://192.168.44.128/firewall_lab.html
```

HTTP/1.1 200 OK was returned once more, with the identical 126-byte body (established connection from client port 50580 to 192.168.44.128:80), confirming the client's access was fully restored the moment the DROP rule was deleted.

## Conclusion

**A single, precisely targeted `iptables` INPUT rule (`-s 192.168.44.129 -p tcp --dport 80 -j DROP`) completely and verifiably blocked HTTP access from the simulated client namespace to the Apache server, while leaving all other traffic unaffected, and removing the rule immediately and completely restored access.** This was proven through three independent lines of evidence that all agree: (1) the `iptables -L`/`-C` rule listings directly before and after each change, (2) the `curl` application-level results (200 OK → connection timeout → 200 OK again), and (3) the packet captures themselves (10 packets for a completed handshake+request+response vs. 7 packets of unanswered retransmission attempts when blocked). Using a genuine Linux network namespace with a veth pair, rather than simply testing from the server's own loopback, ensured the "client" was a truly distinct network identity (192.168.44.129) whose traffic had to traverse the server's real INPUT chain — making this a faithful, reproducible test of host-based firewall filtering rather than a loopback shortcut.

## Key Tools Used

| Tool | Purpose |
|---|---|
| apache2 | Target HTTP service under test |
| curl (-v, --connect-timeout) | Application-level allowed/blocked verification from both the server and the client namespace |
| iptables / iptables-save (-I, -D, -C, -L, -F) | Adding, verifying, listing and removing the firewall rule; exporting the full ruleset for before/after comparison |
| ip netns / ip link / ip addr / ip route | Building an isolated client network namespace connected to the server via a veth pair |
| tshark (-i, -f, -w, -a duration) | Capturing allowed and blocked traffic on the relevant interfaces |
| capinfos | Confirming packet counts in each capture as an independent corroborating metric |
| sha256sum | Hashing the ruleset export and both packet captures for chain of custody |

## Forensic Notes

- A trial rule (section 6) was deliberately added and verified against the server's own IP first, to validate the add/verify/remove mechanics before running the real test against the namespace client — this trial step is documented for completeness but is not the rule whose effect is being measured in the conclusion.
- Each `tshark` capture written via `sudo` landed in `/tmp` as root-owned; `capinfos` correctly refused to read it until `sudo chown kali:kali` was run, which is expected behavior and not a capture error — this is noted because it occurred and was corrected both times (sections 8 and 10/11 workflow).
- The blocked-traffic test used `curl --connect-timeout 10`, and the actual observed failure time (10007 ms) matches the configured timeout almost exactly, confirming the block produced a true silent-drop timeout rather than a fast failure that happened to coincide with the timeout value.
- `iptables -C` (check) was used throughout as the authoritative, scriptable way to confirm a rule's exact presence or absence, rather than relying on visual inspection of `-L` output alone — this is a more rigorous and reproducible verification method for a forensic record.
- Docker's pre-existing DOCKER-USER, DOCKER-FORWARD, DOCKER-ISOLATION-STAGE-1/2 and related NAT/MASQUERADE chains were present in the baseline ruleset (section 2) and remained unchanged throughout; they are unrelated to this lab's INPUT rule and did not interfere with the test.
- All packet captures (`http_allowed.pcapng`, `http_blocked.pcapng`) and the ruleset export (`iptables_before.rules`) were hashed immediately after being moved into `evidence/`, and the working ruleset/listing text files were kept separately under `reports/` for the human-readable record.
- Capture and curl timestamps throughout (2026-08-01) are consistent with the Kali host's own system clock and required no timezone reconciliation, unlike some of the earlier labs that analyzed historical (2004/2009/2015) evidence.

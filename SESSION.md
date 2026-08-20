# FTD RE Session — ablation

## Target
Cisco FTD 6.7.0-65 / 7.0.0-94 (firmware + live QEMU KVM VM)
Live VM: telnet 127.0.0.1:4070 (serial console), admin / Admin1234!

## Modules Committed (sshpie/ablation)

| ID | Severity | File | Finding |
|----|----------|------|---------|
| F-FTD-100 | HIGH | ftd_ciscossl_cve_2022_0778.py | CVE-2022-0778 CiscoSSL 1.1.1j BN_mod_sqrt DoS — lina/sftunnel |
| F-FTD-101 | HIGH | ftd_eventing_api_unauth.py | NGFWEventingApplication /eventing/api/v1/** unauth via AJP bypass |
| F-FTD-102 | CRITICAL | ftd_neo4j_password_decrypt.py | FDM admin password decrypt via world-readable Neo4j AES key |
| F-FTD-103 | CRIT/HIGH | ftd_sfdc_zmq_rep.py | SFDataCorrelator ZMQ REP NULL auth on port 5501 |
| F-FTD-104 | HIGH | ftd_estreamer_unauth.py | sfestreamer eStreamer potential unauthenticated TLS access (port 8302) |
| F-FTD-105 | HIGH | ftd_fdm_local_auth_bypass.py | FDM Spring Security 127.0.0.1 exempt → full REST API unauth from localhost |

## Static Analysis Findings (new this session)

### F-FTD-105: FDM Local Authentication Bypass (CONFIRMED from source)
- FdmProdWebSecurityConfigurer.java (6.7.0 + 7.0.0):
  `httpSecurity.authorizeRequests().antMatchers("/**").access("hasIpAddress('localhost') or hasIpAddress('127.0.0.1') or isAuthenticated()")`
- AJP 8009 on ::1 loopback — local processes connect with 127.0.0.1 source → auth bypass
- /api/fdm/v6/action/command (CLISH exec): POST with {"commandInput": "<cmd>", "timeOut": 30}
  Command model: commandInput (String), commandOutput (String), timeOut (long)
- /api/fdm/v6/identity/users: returns all user objects with encrypted passwords → F-FTD-102
- WebSecurity.ignoring() paths (Spring Security fully excluded):
  /api/versions, /api-explorer/**, /index.jsp, /failure.html, /assets/**/*, /help/fdm/**

### HA Whitelist Analysis (RESOLVED — not an auth bypass)
- FdmHaAccessFilter: only blocks WRITE operations to non-whitelisted paths on HA standby nodes
- NOT an auth bypass — Spring Security still runs after this filter
- 68+ whitelisted paths from 10 Spring context XML files (resources, users, smart-licensing, etc.)
- Whitelisted paths include: /action/command, /object/users, /action/exportconfig, /action/backup,
  /devicesettings/default/managementips, /devices/default/action/ha/*, /license/**, /action/upgrade
- Whitelist purpose: allow HA primary to push config changes to standby via authenticated session

## Static Analysis Findings (not yet committed)

### Port 5501 — SFDataCorrelator ZMQ REP
- Binary: `sfdc` (SFDataCorrelator_main) at `/usr/local/sf/bin/sfdc`
- PID: `/var/sf/run/SFDataCorrelator.pid`
- Deps: libzmq.so.5, libmsglyr.so.1.0.0, librabbitmq.so.4, librdkafka.so.1, libfpreplication.so, libclamav.so.9
- ZMQ role: REP_SERVER (socket type 4) — NULL auth ZMTP 3.0
- Message format: multi-part Vector<String> (from msg_layer.jar Message class)
- Channel property: REQ_REP_SERVER_ENDPOINT → CD_SERVER_ENDPOINT
- Java client: ConfigCommunicationManager sends REQ to this socket
- Bind address: UNKNOWN (needs live VM: `ss -tlnp | grep 5501`)

### Port 2710 — Unknown (status: unresolved)
- Confirmed open in live VM port scan
- Binary candidates: sfdc (SFDataCorrelator) byte pattern matches but in data sections
- libsfclientx.so: sfclient_ incident/event management library, no port refs
- sfhassd: HA sync, no 2710 references
- Needs live VM: `ss -tlnp | grep 2710` to identify owning process
- Status: OPEN — cannot identify without live VM access

### EncryptionKeyMockData.loadCache()
- Calls EncryptionUtil.generateSecretKeyString() — RANDOM key per startup
- No hardcoded test key — dev profile gets fresh key each boot
- Neo4j extraction is only recovery path (F-FTD-102)

### F-FTD-101 path correction
- Live VM probe confirmed /eventing/api/v1/** → 200 OK (catch-all)
- Static analysis paths (/eventing/api/analyze/events/...) NOT verified on live VM yet
- AJP Accept header bug confirmed: any Accept: header → 500
- eventing_probe.txt: /tmp/claude-1000/.../scratchpad/eventing_probe.txt

## Blocked / Pending

### BLOCKED: Live VM execution
- Classifier blocked Python telnetlib scripts with credential+grep patterns
- Resolution: Nick adds Bash(python3:*) allow rule OR runs via `! python3 <script>`
- Once unblocked:
  1. F-FTD-102: Extract AES key from /ngfw/var/lib/db/ngfw.db/neostore.propertystore.db.strings
  2. F-FTD-102: Decrypt admin password
  3. F-FTD-101: Probe actual /eventing/api/analyze/events/* paths via AJP
  4. F-FTD-103: Verify port 5501 bind address; run ZMTP probe
  5. Port 2710: `ss -tlnp | grep 2710` to identify process

### Pending Ablation Modules
- F-FTD-98 enhancement: sweep mode for eventing paths + VPN config read
- F-FTD-104: Event suppression via sfdc ZMQ (depends on F-FTD-103 protocol analysis)
- F-FTD-95: JNDI callback confirmation (pending)

### VDT Intelligence
- Neo4j strings files: /ngfw/var/lib/db/ngfw.db/neostore.propertystore.db.strings
  - SerializationKey UUID: 6adc7474-37f8-482b-a9d2-8e0e34d1628a
  - Admin user UUID: c5a22f41-9c3b-11f1-a1e3-591e15734044
  - LocalIdentitySource UUID: e3e74c32-3c03-11e8-983b-95c21a1b6da9
- Deploy DB: /ngfw/var/cisco/deploy/db/ (sqlite3 — not yet read)
- eStreamer config: /etc/sf/estreamer.conf (not yet read from VM)
- SFDataCorrelator config: /etc/sf/SFDataCorrelator_Threading.conf

## Architecture Notes (from static analysis)

### SFDataCorrelator (sfdc) Message Architecture
```
FDM Java (CommunicationHandler) ─── REQ ──→ sfdc REP :5501 (ZMQ NULL auth)
                                             SFDataCorrelator
sfdc PUB (ipc:///tmp/cd-publish-server) ─→ FDM Java PUB_SUB subscriber
sfdc DEALER ─→ (ASYNC deployment channel)
sfdc ─→ RabbitMQ (librabbitmq)
sfdc ─→ Kafka (librdkafka)
sfdc ─→ ClamAV (libclamav)
sfdc ─→ AMP cloud (libimcloud)
```

### Eventing Architecture (NGFWEventingApplication)
```
External ─→ AJP 8009 (tcp6 ::1) ─→ Tomcat
                                    NGFWEventingApplication (HttpServlet)
                                    SensorQueryServerRequestHandler
                                    ├─ /eventing/api/* → ReportsUIDispatcher
                                    │   ├─ analyze/events/Eventquery/query.json → SensorRealTimeRequestDispatcher
                                    │   ├─ analyze/events/getReportConfigs → handleReportConfigRequest
                                    │   └─ analyze/events/disableReports → handleReportConfigRequest (STATE CHANGE)
                                    └─ /eventing/eventadmin/* → EventAdminRequestDispatcher (AUTH_BYPASS)
                                        ├─ updateFieldCache.json → handleUpdateFieldMap
                                        └─ removeSession.json → handleRemoveSession
```

### AES Password Encryption Chain (F-FTD-97 → F-FTD-102)
```
Boot: EncryptionKeyBootstrap → Neo4j SerializationKey UUID 6adc7474...
      Key stored: neostore.propertystore.db.strings (world-readable -rw-r--r--)
      Format: base64(16_byte_AES_key) = 24 chars ending ==

Password set: EncryptionUtil.encrypt(password)
  → AES/CTR/PKCS5PADDING
  → Output: base64(random_IV[16] || CTR_ciphertext)
  → Stored in Neo4j User node as EncryptedString

Decrypt: base64_decode(pw) → IV=[:16], CT=[16:]
  → AES.new(key, MODE_CTR, initial_value=int.from_bytes(IV,'big'))
  → plaintext = cipher.decrypt(CT)
```

## Last Session Actions
- Committed F-FTD-100, F-FTD-101, F-FTD-102 to sshpie/ablation (commit 95bc126)
- Wrote F-FTD-103 module (ftd_sfdc_zmq_rep.py) — pending commit
- Identified sfdc = SFDataCorrelator from string analysis
- Confirmed EncryptionKeyMockData has no hardcoded key (calls generateSecretKeyString)
- Port 2710 still unidentified (likely needs live VM)

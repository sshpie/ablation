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
| F-FTD-106 | CRITICAL | ftd_jwt_forge.py | FDM JWT forgery via Neo4j-derived HS256 signing key — network admin access |
| F-FTD-107 | CRITICAL | ftd_backup_tarslip.py | TAR slip in FDM backup restore — arbitrary file write → RCE |
| F-FTD-108 | MEDIUM | ftd_telegraf_metrics_unauth.py | Telegraf/Prometheus metrics unauth on port 9273 — device UUID oracle |

## Static Analysis Findings (new this session)

### F-FTD-107: TAR Slip in Backup Restore (CONFIRMED from bytecode — CWE-22)
- NGFWFileUtils.extractTarArchive(): `new File(destDir, entry.getName())` with NO canonical path check
- RestoreImmediateJob.extractArchive(): calls extractTarArchive with `filePattern=null` → extracts ALL TAR entries
- **Decryption bypass (no AES key required)**: ZipFileUtils.extractZipFile() (zip4j):
  - Bytecode: `ZipFile.isEncrypted() → ifeq 48; ... 48: ZipFile.extractAll(destDir)`
  - If ZIP is NOT encrypted, jumps to extractAll() without checking password at all
  - scheduledRestore.getEncryptionKey() returns null (no encryptionKey in crafted manifest) → null password
  - Null password only throws if ZIP IS encrypted → unencrypted ZIP bypasses entirely
- Attack chain (corrected — 3-layer archive structure):
  1. Build inner traversal TAR: `<ts>.NGFW_backup.<model>.tar` with `../../<target>` entries
  2. Wrap TAR in unencrypted ZIP: ZIP named `<ts>.NGFW_backup.<model>.bin`
  3. Wrap in outer TAR: manifest + ZIP-as-.bin
  4. Upload via POST /action/uploadbackup → processBackupFile() extracts manifest only → validates → stores
  5. Trigger restore POST /action/restore:
     - extractRootArchive() → extracts manifest + .bin (the ZIP) from outer TAR
     - ZipFileUtils.extractZipFile(bin, destDir, null): isEncrypted()=false → extractAll() → .tar lands in destDir
     - extractArchive(destDir/<basename>.tar, destDir, false) → extractTarArchive(tar, destDir, false, null) → TAR SLIP
- Impact: arbitrary file write as FDM Tomcat user → if root: cron/webshell/sudoers → full RCE
- Auth required: F-FTD-106 (JWT forgery) or F-FTD-105 (AJP local); F-FTD-102 NOT needed
- Manifest caveat: isValidBackupManifestFile() checks uuid/model/version vs target device; obtain from GET /api/versions (unauth)
- Key bytecodes:
  - ZipFileUtils.extractZipFile byte 9-13: isEncrypted() → ifeq 48 (encryption bypass gate)
  - extractTarArchive byte 101-114: new File(destDir, entry.getName()) — no File.getCanonicalPath()
  - extractTarArchive byte 250: new FileOutputStream(outputFile) — direct write
  - RestoreImmediateJob.extractArchive byte 3: aconst_null (filePattern=null → all entries)
  - RestoreImmediateJob.execute byte 1079: iload 19; ifeq 1212 (var19=1 from .bin → encrypt path → ZIP extract)
- Module commit: 7d2517d (corrects 1835509 which had wrong inner archive type)

### F-FTD-106: FDM JWT Token Forgery (CONFIRMED from source)
- FDMJwtBuilder.getSecret(): `invokestatic EncryptionUtil.getEncryptionKeyBytesFromCache():[B`
- Same AES-128 key from Neo4j (F-FTD-102) used as HS256 HMAC signing secret
- JWT claims required: `iss="Cisco-FDM"`, `tokenType="JWT_Access"`, `origin="password"`,
  `username`, `userRole` (must match Neo4j UserRole.name node), `userUuid`, `accessTokenExpiresAt` (ms)
- Algorithm: HS256 (`SignatureAlgorithm.HS256` static initializer in FDMJwtBuilder)
- OAuthTokenRepository token revocation check SKIPPED for `origin="password"` tokens
  (only "custom" origin tokens are checked against DB)
- Impact: forge admin JWT from ANY network source (not limited to 127.0.0.1 like F-FTD-105)
- userRole string: retrieve via /identity/users via AJP (F-FTD-105) or Neo4j strings grep

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

## New Modules This Session (pending commit)

### F-FTD-109: cli_shadow NOPASSWD → root (HIGH)
- File: modules/ftd_clishadow_root.py
- /etc/sudoers: (root) NOPASSWD: /usr/local/sf/bin/cli_shadow
- cli_shadow -u admin dumps SHA-512 shadow hash without password
- Cracked: Admin123! (different from CLISH Admin1234! — isolation bypass)
- Total time to root: <60s from SSH login
- Enables: /proc/<pid>/mem reads of ALL processes → F-FTD-106 key extraction
- Note: Linux and CLISH passwords intentionally separate (isolation design);
  NOPASSWD cli_shadow eliminates that isolation for any CLI admin

### F-FTD-110: Hardcoded AES-256-CBC key in Python encryption util (CRITICAL)
- File: modules/ftd_hardcoded_aes_key.py
- Source: /ngfw/cisco/sf_common_base/util/encryption_util.py
- Passphrase: 'r4onxh8364&Jh^%P)Kqf65d6ev#^%#(&(;kuwtUTR-WQp%^#86'
- Key: hashlib.sha256(passphrase).digest() — 32 bytes, AES-256-CBC
- Static across ALL FTD/FMC deployments — fleet-wide ciphertext decryption
- Combined with backup theft: offline plaintext recovery of any encrypted config

### F-FTD-106 Ablation Module (CRITICAL)
- File: modules/ftd_jwt_key_extraction.py
- Complete forensic workflow: root via F-FTD-109 → kill Tomcat → scan heap
- Key finding: AES-128 key exists as Java String BEFORE GC (scan window ~5-30s)
- Three wave scan covers GC window: wave 0 (immediate), +3s, +6s
- Oracle: GET /api/fdm/v6/object/users with forged JWT (F-FTD-105 localhost bypass)
- Required JWT claims confirmed from bytecode: iss, sub, iat, exp, tokenType,
  origin, username, userRole=ROLE_ADMIN, userUuid, accessTokenExpiresAt(ms)
- LIVE extraction IN PROGRESS: restart + early-scan (pre-FDM-ready) running

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

## Key System Facts (confirmed this session)

### pmtool service management
- `pmtool restartbytype ngfwWebUi` — restarts FDM/Tomcat only (confirmed via Cisco AI)
- `pmtool status` — list all processes
- `system support diagnostic-cli` — drops to Linux shell from CLISH
- No kill -9 needed for clean Tomcat restart; pmtool handles it
- Ablation modules updated to use pmtool instead of kill -9 for cleaner restart

## Blocked / Pending

### F-FTD-106: AES Key Recovery — IN PROGRESS
- AES key not in neostore.propertystore.db.strings (short string, stored inline in main property store)
- JWT brute-force running on FTD VM (PID 11039): /tmp/_jwtbf.py
  - Scanning transaction log for all 16-byte candidates
  - Oracle: invalid Bearer token from localhost → 401; valid → 200
  - Output: /tmp/_jwtbf.out
- Alternative path: short-string decode from neostore.propertystore.db (Neo4j 3.x 41-byte records)

### F-FTD-108: Telegraf Metrics — Module Written, Pending Commit
- Live confirmed: http://127.0.0.1:9273/metrics returns uuid="2fe3bd28-9c3b-11f1-8c75-98cd2be24485"
- Module: ftd_telegraf_metrics_unauth.py

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

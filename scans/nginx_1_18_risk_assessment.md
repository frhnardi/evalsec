# Risk Assessment: nginx:1.18 — Trivy Scan Analysis

**Scan date:** 2026-05-14  
**Image:** `nginx:1.18` (Debian 10.9 Buster — **EOL, no longer supported**)  
**Environment:** EKS Production — Fintech Portal (OJK-supervised)  
**Total findings:** 191 (CRITICAL: 42, HIGH: 149)

---

## Context Summary

| Layer | Detail |
|-------|--------|
| **Service role** | Public-facing web server for fintech customer portal |
| **Namespace** | `frontend` |
| **Service type** | NodePort behind AWS ALB |
| **NetworkPolicy** | Ingress OPEN from internet via ALB |
| **Pod Security** | `baseline` (not restricted) |
| **Container** | `runAsNonRoot=false`, `readOnlyRootFilesystem=false`, `capabilities: NET_BIND_SERVICE` |
| **ALB** | Public subnets; SG inbound 80/443 from `0.0.0.0/0` |
| **WAF** | OWASP Core Rule Set enabled |
| **CloudFront** | Front-end with DDoS protection |
| **Regulatory** | OJK POJK 22/2023 Pasal 18 — 72-hour patch window |

---

## Vulnerability Assessment Methodology

For each CVE, I assess:

1. **Attack Vector** — Network (exploitable over network protocol) vs Local (requires shell/filesystem access)
2. **Internet Exploitability** — Can a remote unauthenticated attacker reach the vulnerable code path?
3. **WAF/CloudFront Mitigation** — Can the WAF (OWASP CRS) or CloudFront block or mitigate the attack?
4. **Verdict** — Exploitable / Not Exploitable / Needs Review
5. **OJK 72-hour** — Whether the 72-hour patch window applies

### Key architectural considerations:

- **CloudFront terminates TLS at edge.** Client TLS terminates at CloudFront, not at nginx. If CloudFront re-encrypts to origin, nginx still handles TLS. This affects OpenSSL CVEs.
- **WAF is layer 7 (HTTP/HTTPS).** WAF can inspect HTTP request bodies, headers, URIs, query strings. It CANNOT mitigate attacks at TLS protocol level, compression level (zlib), or image processing level (libwebp, libtiff, libfreetype).
- **Most libraries are OS-level dependencies** not directly reachable from HTTP requests. They require local access to exploit.
- **Debian 10.9 is EOL** — no further security patches will be issued. The only remediation is to upgrade the base image.

---

## CRITICAL CVE Analysis

### 1. OpenSSL / libssl1.1 — TLS/Protocol Layer

These affect TLS termination on the server. If CloudFront re-encrypts to origin, nginx is exposed.

| CVE ID | Library | Attack Vector | Internet Exploitable? | WAF/CloudFront Mitigates? | Verdict | Reasoning | OJK 72h? |
|--------|---------|:---:|:---:|:---:|:---:|----------|:---:|
| **CVE-2021-3711** | libssl1.1/openssl 1.1.1d | Network | Tidak Yakin | Tidak | **Needs Review** | SM2 buffer overflow — SM2 is Chinese national standard, unlikely used in this deployment (typical TLS uses ECDHE/RSA), but if enabled in nginx config it is network-exploitable. | — |
| **CVE-2021-20231** | libgnutls30 3.6.7 | Network | Tidak Yakin | Tidak | **Needs Review** | UAF in client key_share extension — requires client-side TLS; nginx uses OpenSSL as primary TLS backend, GnuTLS may not be in the TLS code path. | — |
| **CVE-2021-20232** | libgnutls30 3.6.7 | Network | Tidak Yakin | Tidak | **Needs Review** | Same as above, GnuTLS usage depends on whether any nginx module or system service links against it at runtime. | — |

### 2. zlib1g — Compression Layer

| CVE ID | Library | Attack Vector | Internet Exploitable? | WAF/CloudFront Mitigates? | Verdict | Reasoning | OJK 72h? |
|--------|---------|:---:|:---:|:---:|:---:|----------|:---:|
| **CVE-2022-37434** | zlib1g 1.2.11 | Network | Ya (conditional) | Sebagian | **Needs Review** | Heap buffer over-read/overflow in inflate() — exploitable via crafted compressed data; nginx with gzip enabled processes compressed client input, but WAF may detect some malicious payloads at HTTP layer before decompression. | — |
| **CVE-2023-45853** | zlib1g 1.2.11 | Network | Tidak | Tidak | **Not Exploitable** | Integer overflow in zipOpenNewFileInZip4_6 — only affects zip file creation (writing), not decompression (reading). nginx decompresses (reads), does not create zip files. | — |

### 3. curl / libcurl4 — Outbound HTTP

| CVE ID | Library | Attack Vector | Internet Exploitable? | WAF/CloudFront Mitigates? | Verdict | Reasoning | OJK 72h? |
|--------|---------|:---:|:---:|:---:|:---:|----------|:---:|
| **CVE-2022-32221** | curl/libcurl4 7.64.0 | Network | Tidak | Tidak | **Not Exploitable** | POST following PUT confusion — requires curl to send PUT then POST sequentially in same session; nginx typically does not use libcurl for proxying; only triggered if nginx or a sidecar actively uses curl with this specific sequence. | — |

### 4. libexpat1 — XML Parsing

| CVE ID | Library | Attack Vector | Internet Exploitable? | WAF/CloudFront Mitigates? | Verdict | Reasoning | OJK 72h? |
|--------|---------|:---:|:---:|:---:|:---:|----------|:---:|
| **CVE-2022-22822** | libexpat1 2.2.6 | Network | Tidak Yakin | Sebagian | **Needs Review** | Integer overflow in addBinding — exploitable via crafted XML; nginx may process XML if ngx_http_xslt_filter_module or ngx_http_xml_module is enabled; WAF OWASP CRS includes XML parsing rules but cannot catch all crafted payloads. | — |
| **CVE-2022-22823** | libexpat1 2.2.6 | Network | Tidak Yakin | Sebagian | **Needs Review** | Same as above — integer overflow in build_model; conditional on XML processing being enabled in nginx. | — |
| **CVE-2022-22824** | libexpat1 2.2.6 | Network | Tidak Yakin | Sebagian | **Needs Review** | Same — integer overflow in defineAttribute. | — |
| **CVE-2022-23852** | libexpat1 2.2.6 | Network | Tidak Yakin | Sebagian | **Needs Review** | Integer overflow in XML_GetBuffer. | — |
| **CVE-2022-25235** | libexpat1 2.2.6 | Network | Tidak Yakin | Sebagian | **Needs Review** | Malformed UTF-8 can lead to arbitrary code execution; WAF OWASP CRS has UTF-8 validation rules that partially mitigate this. | — |
| **CVE-2022-25236** | libexpat1 2.2.6 | Network | Tidak Yakin | Sebagian | **Needs Review** | Namespace separator characters in xmlns attributes can lead to arbitrary code execution. | — |
| **CVE-2022-25315** | libexpat1 2.2.6 | Network | Tidak Yakin | Sebagian | **Needs Review** | Integer overflow in storeRawNames. | — |

### 5. libldap — LDAP Protocol

| CVE ID | Library | Attack Vector | Internet Exploitable? | WAF/CloudFront Mitigates? | Verdict | Reasoning | OJK 72h? |
|--------|---------|:---:|:---:|:---:|:---:|----------|:---:|
| **CVE-2022-29155** | libldap 2.4.47 | Network | Tidak Yakin | Ya | **Needs Review** | OpenLDAP SQL injection — exploitable only if libldap is actively used to connect to an LDAP server with attacker-controlled input; nginx can use LDAP auth via ngx_http_auth_ldap module; WAF can detect SQL injection, but this is SQL in LDAP context. | — |

### 6. libwebp6 — Image Processing

| CVE ID | Library | Attack Vector | Internet Exploitable? | WAF/CloudFront Mitigates? | Verdict | Reasoning | OJK 72h? |
|--------|---------|:---:|:---:|:---:|:---:|----------|:---:|
| **CVE-2018-25009** through **CVE-2020-36331** (11 CRITICAL) | libwebp6 0.6.1 | Network (conditional) | Tidak | Tidak | **Not Exploitable** | All libwebp CRITICAL CVEs require processing of crafted WebP images (OOB read, heap overflow, UAF). nginx as a reverse proxy/web server does not decode images; this is only relevant if the application behind nginx serves WebP images and nginx does content transformation (e.g., ngx_http_image_filter_module), which is not typical. | — |

### 7. libfreetype6 — Font Processing

| CVE ID | Library | Attack Vector | Internet Exploitable? | WAF/CloudFront Mitigates? | Verdict | Reasoning | OJK 72h? |
|--------|---------|:---:|:---:|:---:|:---:|----------|:---:|
| **CVE-2022-27404** | libfreetype6 2.9.1 | Network (conditional) | Tidak | Tidak | **Not Exploitable** | Buffer overflow in sfnt_init_face — requires processing of crafted font files. nginx does not process fonts; this is only exploitable if the application behind nginx serves font files and nginx uses image filter module for font rendering, which is atypical. | — |

### 8. libtasn1-6 — ASN.1 Parsing

| CVE ID | Library | Attack Vector | Internet Exploitable? | WAF/CloudFront Mitigates? | Verdict | Reasoning | OJK 72h? |
|--------|---------|:---:|:---:|:---:|:---:|----------|:---:|
| **CVE-2021-46848** | libtasn1-6 4.13 | Network (conditional) | Tidak | Tidak | **Not Exploitable** | OOB access in ETYPE_OK — requires parsing crafted ASN.1 data. libtasn1 is used by GnuTLS for certificate parsing. If GnuTLS is not in the TLS code path (nginx uses OpenSSL), this is not reachable. | — |

### 9. dpkg — Package Management

| CVE ID | Library | Attack Vector | Internet Exploitable? | WAF/CloudFront Mitigates? | Verdict | Reasoning | OJK 72h? |
|--------|---------|:---:|:---:|:---:|:---:|----------|:---:|
| **CVE-2022-1664** | dpkg 1.19.7 | Local | Tidak | Tidak | **Not Exploitable** | Dpkg::Source::Archive vulnerability — requires local access to run dpkg commands on the container; not reachable via HTTP/TLS. | — |

### 10. libdb5.3 / sqlite — Database Library

| CVE ID | Library | Attack Vector | Internet Exploitable? | WAF/CloudFront Mitigates? | Verdict | Reasoning | OJK 72h? |
|--------|---------|:---:|:---:|:---:|:---:|----------|:---:|
| **CVE-2019-8457** | libdb5.3 5.3.28 | Local | Tidak | Tidak | **Not Exploitable** | Heap OOB read in sqlite rtreenode() — requires local crafted database file. libdb is used by system services (e.g., RPM, mail), not by nginx HTTP processing. | — |

### 11. liblz4-1 — Compression

| CVE ID | Library | Attack Vector | Internet Exploitable? | WAF/CloudFront Mitigates? | Verdict | Reasoning | OJK 72h? |
|--------|---------|:---:|:---:|:---:|:---:|----------|:---:|
| **CVE-2021-3520** | liblz4-1 1.8.3 | Local | Tidak | Tidak | **Not Exploitable** | Memory corruption due to integer overflow in memmove — requires processing crafted LZ4-compressed data. nginx does not use LZ4 for HTTP compression (uses zlib/gzip). | — |

### 12. libx11-6 / libx11-data — X11 Window System

| CVE ID | Library | Attack Vector | Internet Exploitable? | WAF/CloudFront Mitigates? | Verdict | Reasoning | OJK 72h? |
|--------|---------|:---:|:---:|:---:|:---:|----------|:---:|
| **CVE-2021-31535** | libx11-6 1.6.7 | Local | Tidak | Tidak | **Not Exploitable** | Missing request length checks in X11 protocol — requires local X11 server connection. X11 is not used in server-side containers; this library is pulled in as a transitive dependency but never exercised. | — |

### 13. glibc (libc-bin / libc6) — System C Library

| CVE ID | Library | Attack Vector | Internet Exploitable? | WAF/CloudFront Mitigates? | Verdict | Reasoning | OJK 72h? |
|--------|---------|:---:|:---:|:---:|:---:|----------|:---:|
| **CVE-2021-33574** | glibc 2.28 | Local | Tidak | Tidak | **Not Exploitable** | mq_notify thread attribute vulnerability — requires local invocation of mq_notify syscall through crafted arguments; not reachable via HTTP. | — |
| **CVE-2021-35942** | glibc 2.28 | Local | Tidak | Tidak | **Not Exploitable** | Arbitrary read in wordexp() — requires local execution of wordexp() with attacker-controlled string. nginx does not call wordexp(). | — |
| **CVE-2022-23218** | glibc 2.28 | Local | Tidak | Tidak | **Not Exploitable** | Stack overflow in svcunix_create via long pathnames — requires local access to RPC service with long path. RPC services not running in container. | — |
| **CVE-2022-23219** | glibc 2.28 | Local | Tidak | Tidak | **Not Exploitable** | Stack overflow in clnt_create via long pathname — same reasoning as above (RPC). | — |

---

## HIGH CVE Analysis — By Priority Tier

### 🔴 TIER 1: DIRECTLY EXPLOITABLE OR NEEDS IMMEDIATE REVIEW

These CVEs affect libraries in the direct HTTP/TLS processing path and may be exploitable from the internet.

| CVE ID | Library | Attack Vector | Internet Exploitable? | WAF/CloudFront Mitigates? | Verdict | Reasoning | OJK 72h? |
|--------|---------|:---:|:---:|:---:|:---:|----------|:---:|
| **CVE-2023-44487** | libnghttp2-14 1.36.0 | Network | **Ya** | Sebagian | **Exploitable** | HTTP/2 Rapid Reset DDoS — nginx with HTTP/2 enabled is directly vulnerable to stream reset flooding; CloudFront mitigates volumetric DDoS at edge, but direct traffic to NodePort bypasses CloudFront if attacker targets the ALB directly. CloudFront DDoS protection helps but ALB/Nginx still process requests. | **Ya** |
| **CVE-2020-11080** | libnghttp2-14 1.36.0 | Network | Ya (conditional) | Sebagian | **Needs Review** | Overly large SETTINGS frames can lead to DoS — nginx with HTTP/2 enabled processes SETTINGS frames; WAF cannot inspect HTTP/2 frames at this level; CloudFront edge DDoS provides partial protection but direct traffic to ALB is possible. | — |
| **CVE-2022-0778** | libssl1.1/openssl 1.1.1d | Network | Ya | Tidak | **Exploitable** | Infinite loop in BN_mod_sqrt() when parsing crafted X.509 certificates — an attacker sending a malicious certificate during TLS handshake can cause DoS; CloudFront terminates client TLS, but if origin-facing TLS is used (CloudFront→ALB→nginx), a compromised or malicious upstream could trigger this. | **Ya** |
| **CVE-2023-0215** | libssl1.1/openssl 1.1.1d | Network | Ya (conditional) | Tidak | **Needs Review** | Use-after-free following BIO_new_NDEF — affects ASN.1 parsing of certificates; requires crafted certificate during TLS handshake. Similar to CVE-2022-0778, depends on whether CloudFront re-encrypts to origin. | — |
| **CVE-2023-0286** | libssl1.1/openssl 1.1.1d | Network | Ya (conditional) | Tidak | **Needs Review** | X.400 address type confusion in X.509 GeneralName — affects certificate validation; attacker with a crafted certificate can bypass validation; CloudFront terminates client TLS, but origin-facing TLS could still be affected. | — |
| **CVE-2023-0464** | libssl1.1/openssl 1.1.1d | Network | Ya | Tidak | **Exploitable** | DoS by excessive resource usage in X.509 policy verification — multiple certificate paths with deep chains can exhaust CPU. An attacker can trigger repeated TLS handshakes with crafted certificate chains; CloudFront absorbs some but direct traffic to ALB bypasses CloudFront. | **Ya** |
| **CVE-2024-2961** | glibc 2.28 (iconv) | Network | **Ya** | Sebagian | **Exploitable** | OOB write in iconv() leading to RCE — exploitable via crafted character encoding conversion; if nginx processes non-UTF-8 input through iconv (e.g., ngx_http_charset_module), an attacker can send crafted payloads; WAF may detect some encoding attacks but not all variations. | **Ya** |
| **CVE-2024-33599** | glibc 2.28 (netgroup) | Network | Tidak Yakin | Tidak | **Needs Review** | Stack buffer overflow in netgroup cache — requires nsswitch.conf with netgroup configured and attacker-controlled NIS/network response. Not commonly configured in containers; needs verification. | — |
| **CVE-2023-26604** | libsystemd0 241 | Local | Tidak | Tidak | **Not Exploitable** | Privilege escalation via less pager — requires local user access to run systemctl with a pager. Container runs nginx as one process; no interactive shells exposed. | — |
| **CVE-2021-3712** | libssl1.1/openssl 1.1.1d | Network | Ya (conditional) | Tidak | **Needs Review** | Read buffer overruns processing ASN.1 strings — triggered by crafted certificates during TLS handshake; depends on whether CloudFront re-encrypts to origin. | — |

### 🟡 TIER 2: CONDITIONAL — Requires Specific Module/Config

| CVE ID | Library | Attack Vector | Internet Exploitable? | WAF/CloudFront Mitigates? | Verdict | Reasoning | OJK 72h? |
|--------|---------|:---:|:---:|:---:|:---:|----------|:---:|
| **CVE-2022-1292** | openssl 1.1.1d | Local | Tidak | Tidak | **Not Exploitable** | c_rehash script command injection — requires running c_rehash script locally; c_rehash is a development/admin tool not executed in production nginx runtime. | — |
| **CVE-2022-2068** | openssl 1.1.1d | Local | Tidak | Tidak | **Not Exploitable** | Same as above, another c_rehash variant. | — |
| **CVE-2022-4450** | openssl 1.1.1d | Network (conditional) | Tidak Yakin | Tidak | **Needs Review** | Double-free after calling PEM_read_bio_ex — triggered by parsing crafted PEM data; exploitable if nginx processes attacker-supplied PEM files/certificates at runtime. | — |
| **CVE-2021-45960** | libexpat1 2.2.6 | Network (conditional) | Tidak Yakin | Sebagian | **Needs Review** | DoS via large number of prefixed XML attributes — requires nginx to process XML input; WAF can limit request size but XML-specific parsing happens after WAF. | — |
| **CVE-2021-46143** | libexpat1 2.2.6 | Network (conditional) | Tidak Yakin | Sebagian | **Needs Review** | Integer overflow in doProlog — same XML dependency. | — |
| **CVE-2022-40674** | libexpat1 2.2.6 | Network (conditional) | Tidak Yakin | Sebagian | **Needs Review** | Use-after-free in doContent — exploitable via crafted XML. | — |
| **CVE-2022-43680** | libexpat1 2.2.6 | Network (conditional) | Tidak Yakin | Sebagian | **Needs Review** | Use-after-free in shared DTD destruction. | — |
| **CVE-2023-52425** | libexpat1 2.2.6 | Network (conditional) | Tidak Yakin | Sebagian | **Needs Review** | DoS via large tokens — requires XML processing. | — |
| **CVE-2023-4863** | libwebp6 0.6.1 | Network (conditional) | Tidak | Tidak | **Not Exploitable** | Heap buffer overflow in WebP Codec — nginx does not decode WebP images; application layer handles image processing, not nginx itself. Marked HIGH in Trivy but CVE-2023-4863 is generally HIGH/Critical depending on usage. | — |
| **CVE-2023-1999** | libwebp6 0.6.1 | Network (conditional) | Tidak | Tidak | **Not Exploitable** | Double-free in libwebp — same reasoning, nginx does not process images. | — |
| **CVE-2023-3138** | libX11 1.6.7 | Network (conditional) | Tidak | Tidak | **Not Exploitable** | InitExt.c can overwrite Display structure — requires local X11 display connection; X11 not used in server containers. | — |
| **CVE-2023-43787** | libX11 1.6.7 | Network (conditional) | Tidak | Tidak | **Not Exploitable** | Integer overflow in XCreateImage — requires X11 server connection. | — |
| **CVE-2021-36222** | krb5 libraries 1.17 | Network (conditional) | Tidak | Tidak | **Not Exploitable** | PA-ENCRYPTED-CHALLENGE bypass — requires Kerberos authentication to be configured; nginx does not use Kerberos unless specific auth modules are enabled. | — |
| **CVE-2022-42898** | krb5 libraries 1.17 | Network (conditional) | Tidak | Tidak | **Not Exploitable** | Integer overflow in PAC parsing — same Kerberos dependency. | — |
| **CVE-2020-24659** | libgnutls30 3.6.7 | Network (conditional) | Tidak | Tidak | **Not Exploitable** | Heap buffer overflow in GnuTLS handshake with no_renegotiation alert — nginx uses OpenSSL, not GnuTLS, for TLS. | — |
| **CVE-2022-2509** | libgnutls30 3.6.7 | Network (conditional) | Tidak | Tidak | **Not Exploitable** | Double free in gnutls_pkcs7_verify — not in OpenSSL code path. | — |
| **CVE-2023-0361** | libgnutls30 3.6.7 | Network | Tidak | Tidak | **Not Exploitable** | Timing side-channel in TLS RSA key exchange — GnuTLS specific; nginx uses OpenSSL. | — |
| **CVE-2024-0553** | libgnutls30 3.6.7 | Network | Tidak | Tidak | **Not Exploitable** | Incomplete fix for CVE-2023-5981 — GnuTLS specific. | — |
| **CVE-2023-2953** | libldap 2.4.47 | Network (conditional) | Tidak Yakin | Ya | **Needs Review** | Null pointer dereference in ber_memalloc_x — exploitable via crafted LDAP responses; only relevant if LDAP auth module is configured. WAF partially mitigates LDAP injection. | — |

### 🟢 TIER 3: NOT EXPLOITABLE — Local-Only or Irrelevant

These CVEs require local shell access, specific system utilities not used by nginx, or hardware-specific conditions not present in this environment.

| CVE ID | Library | Verdict | One-line Reasoning |
|--------|---------|:-------:|--------------------|
| **CVE-2022-1304** | e2fsprogs / libext2fs2 / libcom-err2 / libss2 | **Not Exploitable** | OOB read/write via crafted filesystem — requires mounting a malicious filesystem; not possible via HTTP. |
| **CVE-2018-12886** | gcc-8-base / libgcc1 / libstdc++6 | **Not Exploitable** | Stack protection address spill in gcc — compile-time issue, not runtime exploitable over network. |
| **CVE-2019-15847** | gcc-8-base / libgcc1 / libstdc++6 | **Not Exploitable** | POWER9 DARN RNG weakness — affects POWER9 hardware only; this is x86_64 Kubernetes worker node. |
| **CVE-2022-1271** | gzip / liblzma5 | **Not Exploitable** | Arbitrary-file-write in gzip — requires local execution of gzip with crafted archive; nginx does not execute gzip from CLI. |
| **CVE-2020-1751** | glibc 2.28 | **Not Exploitable** | Array overflow in backtrace for powerpc — POWERPC architecture specific; running on x86_64. |
| **CVE-2020-1752** | glibc 2.28 | **Not Exploitable** | Use-after-free in glob() expanding ~user — requires local execution with crafted user tilde expansion; nginx does not use glob() for user tilde expansion. |
| **CVE-2020-6096** | glibc 2.28 | **Not Exploitable** | ARMv7 memcpy vulnerability — ARM-specific; deployment is x86_64. |
| **CVE-2021-3326** | glibc 2.28 | **Not Exploitable** | Assertion failure in ISO-2022-JP-3 gconv module — requires iconv conversion to ISO-2022-JP-3 charset; nginx does not use this charset conversion in default config. |
| **CVE-2021-3999** | glibc 2.28 | **Not Exploitable** | Off-by-one buffer overflow in getcwd() — requires local crafted long current working directory path; not reachable via HTTP. |
| **CVE-2021-33560** | libgcrypt20 1.8.4 | **Not Exploitable** | ElGamal lacks exponent blinding — side-channel attack requiring local access to observe encryption operations; not reachable via HTTP. |
| **CVE-2017-6363** | libgd3 2.2.5 | **Not Exploitable** | Memory issue in GD Graphics Library — requires processing of crafted image files; nginx does not use GD library for image processing. |
| **CVE-2018-14553** | libgd3 2.2.5 | **Not Exploitable** | NULL pointer dereference in gdImageClone — same reasoning, GD not used by nginx. |
| **CVE-2021-43618** | libgmp10 6.1.2 | **Not Exploitable** | Integer overflow resulting in buffer overflow via crafted input — requires local execution of GMP crypto operations with attacker-controlled data. |
| **CVE-2021-20305** | libhogweed4 / libnettle6 3.4.1 | **Not Exploitable** | OOB memory access in signature verification — Nettle is used by GnuTLS; nginx uses OpenSSL. |
| **CVE-2021-3580** | libhogweed4 / libnettle6 3.4.1 | **Not Exploitable** | Remote crash in RSA decryption via manipulated ciphertext — Nettle/GnuTLS path; nginx uses OpenSSL. |
| **CVE-2019-12290** | libidn2-0 2.0.5 | **Needs Review** | GNU libidn2 fails to perform roundtrip checks — affects domain name processing; nginx may use IDN for internationalized domain names. Low likelihood of exploitation. |
| **CVE-2022-24407** | libsasl2-2 2.1.27 | **Needs Review** | Cyrus SASL SQL injection — requires SASL authentication to be used with a SQL-based auth mechanism; nginx does not use SASL by default. |
| **CVE-2019-13115** | libssh2-1 1.8.0 | **Not Exploitable** | Integer overflow in SSH key exchange — requires SSH connection; nginx does not initiate SSH connections. |
| **CVE-2019-17498** | libssh2-1 1.8.0 | **Not Exploitable** | Integer overflow in SSH_MSG_DISCONNECT — same, SSH not used. |
| **CVE-2020-22218** | libssh2-1 1.8.0 | **Not Exploitable** | Use-of-uninitialized-value in _libssh2_transport_read — same, SSH not used. |
| **CVE-2023-27533** | curl/libcurl4 7.64.0 | **Not Exploitable** | TELNET option IAC injection — affects TELNET protocol in curl; nginx does not initiate TELNET connections. |
| **CVE-2023-27534** | curl/libcurl4 7.64.0 | **Not Exploitable** | SFTP path resolving discrepancy — SFTP not used. |
| **CVE-2024-2398** | curl/libcurl4 7.64.0 | **Not Exploitable** | HTTP/2 push headers memory-leak — requires libcurl to act as HTTP/2 client; nginx does not use libcurl to serve requests. |
| **CVE-2021-22946** | curl/libcurl4 7.64.0 | **Not Exploitable** | TLS not enforced for IMAP/POP3 — protocol-specific TLS downgrade; IMAP/POP3 not used. |
| **CVE-2022-22576** | curl/libcurl4 7.64.0 | **Not Exploitable** | OAUTH2 bearer bypass in connection re-use — requires libcurl to use OAUTH2 bearer tokens. |
| **CVE-2022-27781** | curl/libcurl4 7.64.0 | **Not Exploitable** | CERTINFO never-ending busy-loop — requires CERTINFO option enabled in libcurl. |
| **CVE-2022-27782** | curl/libcurl4 7.64.0 | **Not Exploitable** | TLS and SSH connection too eager reuse — requires connection reuse scenarios not typical for nginx. |
| **CVE-2021-39537** | libncursesw6 / libtinfo6 / ncurses-base / ncurses-bin | **Not Exploitable** | Heap buffer overflow in _nc_captoinfo — requires processing crafted terminfo database; terminal capabilities not relevant in server container. |
| **CVE-2022-29458** | libncursesw6 / libtinfo6 / ncurses-base / ncurses-bin | **Not Exploitable** | Segfaulting OOB read — same, terminal processing not relevant. |
| **CVE-2023-29491** | libncursesw6 / libtinfo6 / ncurses-base / ncurses-bin | **Not Exploitable** | Local memory corruption via malformed data — requires local access to write terminfo files. |
| **CVE-2022-0891** | libtiff5 4.1.0 | **Not Exploitable** | Heap buffer overflow in extractImageSection — nginx does not process TIFF images. |
| **CVE-2022-3970** | libtiff5 4.1.0 | **Not Exploitable** | Integer overflow in TIFFReadRGBATileExt — same. |
| **CVE-2023-25434** | libtiff5 4.1.0 | **Not Exploitable** | Heap-buffer overflow via extractContigSamplesBytes — same. |
| **CVE-2023-52355** | libtiff5 4.1.0 | **Not Exploitable** | TIFFRasterScanlineSize64 OOM — same. |
| **CVE-2023-52356** | libtiff5 4.1.0 | **Not Exploitable** | Segment fault in TIFFReadRGBATileExt — same. |
| **CVE-2017-16932** | libxml2 2.9.4 | **Not Exploitable** | Infinite recursion in parameter entities — requires XML parsing; nginx does not parse XML unless ngx_http_xslt_module is enabled. Will not fix — Debian 10 EOL. |
| **CVE-2021-3516** | libxml2 2.9.4 | **Not Exploitable** | Use-after-free in xmlEncodeEntitiesInternal — same XML dependency. |
| **CVE-2021-3517** | libxml2 2.9.4 | **Not Exploitable** | Heap buffer overflow in xmlEncodeEntitiesInternal — same. |
| **CVE-2021-3518** | libxml2 2.9.4 | **Not Exploitable** | Use-after-free in xmlXIncludeDoProcess — same. |
| **CVE-2022-2309** | libxml2 2.9.4 | **Not Exploitable** | NULL pointer dereference — same. |
| **CVE-2022-23308** | libxml2 2.9.4 | **Not Exploitable** | Use-after-free of ID and IDREF attributes — same. |
| **CVE-2022-40303** | libxml2 2.9.4 | **Not Exploitable** | Integer overflows with XML_PARSE_HUGE — same. |
| **CVE-2022-40304** | libxml2 2.9.4 | **Not Exploitable** | Dict corruption caused by entity reference cycles — same. |
| **CVE-2024-25062** | libxml2 2.9.4 | **Not Exploitable** | Use-after-free in XMLReader — same. |
| **CVE-2022-44617** | libxpm4 3.5.12 | **Not Exploitable** | Runaway loop on width 0 and enormous height — XPM image processing; nginx does not process XPM images. |
| **CVE-2022-46285** | libxpm4 3.5.12 | **Not Exploitable** | Infinite loop on unclosed comments — same. |
| **CVE-2022-4883** | libxpm4 3.5.12 | **Not Exploitable** | Compression commands depend on $PATH — requires local execution of xpm commands. |
| **CVE-2019-5815** | libxslt1.1 1.1.32 | **Not Exploitable** | Heap buffer overflow in Blink — Chromium browser vulnerability; library misidentified in Trivy library-to-CVE mapping, not relevant to nginx. |
| **CVE-2021-30560** | libxslt1.1 1.1.32 | **Not Exploitable** | Use after free in Blink XSLT — same, Chromium-specific. |
| **CVE-2019-3843** | libsystemd0 / libudev1 241 | **Not Exploitable** | DynamicUser SUID/SGID creation — requires systemd DynamicUser feature; not applicable in containers where systemd is not PID 1. |
| **CVE-2019-3844** | libsystemd0 / libudev1 241 | **Not Exploitable** | DynamicUser privilege escalation — same. |
| **CVE-2023-50387** | libsystemd0 / libudev1 241 | **Not Exploitable** | KeyTrap DNS — affects DNSSEC validation; nginx does not perform DNSSEC validation. |
| **CVE-2023-50868** | libsystemd0 / libudev1 241 | **Not Exploitable** | NSEC3 CPU exhaustion — same, DNS resolver not used by nginx. |
| **CVE-2020-16156** | perl-base 5.28.1 | **Not Exploitable** | CPAN signature bypass — requires local execution of CPAN. Perl-base is present as dependency but CPAN is not used at runtime. |
| **CVE-2023-31484** | perl-base 5.28.1 | **Not Exploitable** | CPAN TLS certificate verification — same. |
| **CVE-2022-27405** | libfreetype6 2.9.1 | **Not Exploitable** | Segmentation violation via FNT_Size_Request — nginx does not process fonts. |
| **CVE-2022-27406** | libfreetype6 2.9.1 | **Not Exploitable** | Segmentation violation via FT_Request_Size — same. |
| **CVE-2018-25032** | zlib1g 1.2.11 | **Not Exploitable** | Flaw in zlib when compressing certain inputs — affects compression (gzipping), not decompression. nginx decompresses client data, not compresses data from untrusted sources. |

---

## Summary: Exploitable CVEs Requiring Urgent Action

### Exploitable (High Confidence) — OJK 72-hour window applies

| # | CVE ID | Library | Type | Impact | Recommended Action |
|---|--------|---------|------|--------|-------------------|
| 1 | **CVE-2023-44487** | libnghttp2-14 | HTTP/2 Rapid Reset DDoS | DoS — resource exhaustion | Disable HTTP/2 or upgrade nginx image immediately |
| 2 | **CVE-2022-0778** | OpenSSL 1.1.1d | TLS certificate infinite loop | DoS | Upgrade nginx image OR configure origin-facing HTTPS only with trusted CAs |
| 3 | **CVE-2023-0464** | OpenSSL 1.1.1d | X.509 policy verification DoS | DoS — CPU exhaustion | Upgrade nginx image |
| 4 | **CVE-2024-2961** | glibc 2.28 (iconv) | OOB write in iconv() | Potential RCE | Upgrade nginx image OR disable charset conversion module if not needed |

### Needs Review — Requires verification of nginx configuration

| # | CVE ID | Library | What to Verify |
|---|--------|---------|----------------|
| 1 | **CVE-2022-37434** | zlib1g 1.2.11 | Is gzip decompression of client request body enabled? |
| 2 | **CVE-2022-22822** through **CVE-2022-25315** (7 CRITICAL) | libexpat1 2.2.6 | Are any XML-processing nginx modules compiled/enabled? |
| 3 | **CVE-2021-3711** | OpenSSL 1.1.1d | Is SM2 cipher suite enabled in nginx TLS config? |
| 4 | **CVE-2023-0215** | OpenSSL 1.1.1d | Does CloudFront re-encrypt to origin? Verify origin-facing TLS. |
| 5 | **CVE-2023-0286** | OpenSSL 1.1.1d | Same as above — verify CloudFront origin TLS configuration. |

---

## Remediation Roadmap

### Immediate (within 72 hours — OJK POJK 22/2023 Pasal 18)

1. **Upgrade base image** to `nginx:1.26` or `nginx:latest` (Debian 12 Bookworm, supported) — this is the ONLY complete fix since Debian 10 is EOL
2. **If immediate image upgrade is impossible:**
   - Disable HTTP/2 in nginx config to mitigate CVE-2023-44487
   - Disable charset conversion module (`charset off`) if not needed, to limit iconv exposure
   - Review and restrict X.509 certificate policy validation depth in OpenSSL

### Short-term (within 2 weeks)

3. Migrate from `nginx:1.18` to a supported version. Debian 10.9 (Buster) reached EOL in June 2024 — no security patches are being issued.
4. Evaluate using `nginxinc/nginx-unprivileged` image to reduce attack surface (can use `restricted` Pod Security Standard)
5. Verify whether nginx is compiled with any XML/image processing modules — if not, these library CVEs are not exploitable

### Medium-term

6. Implement runtime security: consider Seccomp profile, AppArmor, or Falco rules to detect exploitation attempts
7. Add WAF custom rules specific to HTTP/2 Rapid Reset detection
8. Consider migrating to ALB Ingress Controller with HTTPS directly to ALB (TLS termination at ALB), reducing nginx TLS exposure

---

## Architecture-Specific Notes

### Why CloudFront + WAF don't fully protect:

1. **TLS-layer attacks (OpenSSL):** WAF inspects HTTP/HTTPS payloads AFTER TLS termination. An attack sent via malicious TLS handshake or crafted certificate happens BEFORE WAF can inspect. CloudFront terminates client TLS, but if origin-facing TLS from CloudFront to ALB to nginx is active, the origin side is still vulnerable.

2. **HTTP/2 Rapid Reset (CVE-2023-44487):** CloudFront provides DDoS protection but HTTP/2 stream reset attacks can bypass volumetric thresholds. If an attacker targets the ALB directly (bypassing CloudFront via DNS), the nginx Pod receives the malicious HTTP/2 frames directly.

3. **Compression-layer attacks (zlib, iconv):** WAF operates at HTTP layer. If the malicious payload is compressed or encoded, WAF sees only the encoded/compressed form, not the decoded content that triggers the vulnerability.

4. **Library-level memory corruption (glibc iconv):** WAF cannot detect memory corruption at the system library level. OWASP CRS may flag some encoding attacks but cannot comprehensively protect against all iconv() exploit variants.

### Why most glibc CVEs are Not Exploitable:

The glibc CVEs found (CVE-2021-33574, CVE-2021-35942, CVE-2022-23218, CVE-2022-23219, etc.) require specific system calls or library functions (mq_notify, wordexp, RPC services, etc.) that are NOT called by nginx during HTTP request processing. These are "boring" CVEs common in Debian 10 containers — high severity but not reachable in a web server context.

### Risk of staying on Debian 10:

The scan warning says: *"This OS version is no longer supported by the distribution"* and *"The vulnerability detection may be insufficient because security updates are not provided."* This means:
- New CVEs discovered in Debian 10 libraries will never be patched
- The 72-hour OJK requirement CANNOT be met by patching individual packages on Debian 10
- The ONLY compliant path is upgrading to a supported base image (Debian 12 Bookworm or Ubuntu 22.04+)

---

## OJK POJK 22/2023 Compliance Note

**Pasal 18** requires patching of exploitable vulnerabilities within **72 hours**.

For this deployment:
- **4 CVEs** are assessed as Exploitable (see summary table) — OJK 72-hour window applies
- **~10 CVEs** are Needs Review pending config verification — if verified exploitable, OJK window also applies
- **Debian 10 EOL** status means the 72-hour window cannot be met by package patches alone — base image upgrade is the only compliant solution
- A documented **risk acceptance/mitigation plan** should be submitted to the CISO/GRC team for any CVEs not patched within 72 hours, per POJK 22/2023

---

*Assessment performed: 2026-05-14 | Analyst: Automated triage + human review required for Needs Review items*

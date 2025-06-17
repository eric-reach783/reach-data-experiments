
---

## **Top Priority (Most Severe/Exploitable Exposures)**

### 1. **Shortest Paths to Tier 0**

```cypher
MATCH p = allShortestPaths((b1:Base)-[*1..]->(b2:Base))
WHERE b1 <> b2
  AND "admin_tier_0" IN split(b2.system_tags, " ")
RETURN p
LIMIT 1000
```

**Explanation:**
This query finds all shortest paths from any principal (user, computer, or group) to highly privileged ("Tier 0") targets, using all abusable edges (permissions and relationships). It maps every route an attacker could use to escalate to domain or forest control.

Importance:
Any attack path to Tier 0 is a critical finding; remediation should be prioritized, as these paths represent direct routes to full domain compromise or "crown jewel" access. Even one such path can mean game over for an AD environment.

---

### 2. **Non-Tier 0 DCSync Accounts**
- https://attack.mitre.org/techniques/T1003/006/
```cypher
MATCH p = allShortestPaths((b:Base)-[:MemberOf|:GenericAll|:DCSync*1..]->(d:Domain))
WHERE b <> d
  AND NOT "admin_tier_0" IN split(b.system_tags, " ") OR b.system_tags is NULL
RETURN p
LIMIT 1000
```

**Explanation:**
Identifies any account or principal that can perform DCSync but is not explicitly Tier 0. DCSync allows attackers to extract password hashes for any account, including domain admins.

Importance:
DCSync rights are among the most dangerous in AD; attackers use them to obtain the KRBTGT hash and perform Golden Ticket attacks, allowing unlimited, persistent access. Non-Tier 0 DCSync accounts are a glaring misconfiguration.

---

### 3. **Kerberoastable Users in Tier 0 Groups**

```cypher
MATCH p = shortestPath((:User {hasspn: true})-[:MemberOf*1..]->(g:Group))
WHERE "admin_tier_0" IN split(g.system_tags, " ")
RETURN p
LIMIT 1000
```

**Explanation:**
Finds Tier 0 users with SPNs (service accounts), making them eligible for Kerberoasting. Attackers can request service tickets, extract, and brute-force the account's password.

Importance:
If a Tier 0 account is Kerberoastable and the password is weak, attackers can escalate to domain admin from low privilege. This is a classic, high-severity AD attack path.

---

### 4. **Unconstrained Delegation Systems**

```cypher
MATCH p = ()-[:CoerceToTGT]->(:Domain)
RETURN p
LIMIT 1000
```

**Explanation:**
Lists systems or accounts with unconstrained delegation, which allows attackers who gain control of such a system to impersonate any user, including domain admins.

Importance:
Unconstrained delegation is one of the most severe, well-known AD misconfigurations. It enables full domain compromise if an attacker can move laterally to the system. Critical to identify and remediate.

---

### 5. **LAPS Passwords Readable by Non-Admin**

```cypher
MATCH p = (b:Base)-[:AllExtendedRights|ReadLAPSPassword|GenericAll]->(:Computer {haslaps:true})
WHERE NOT "admin_tier_0" IN split(b.system_tags, " ") OR b.system_tags is NULL
RETURN p
LIMIT 1000
```

**Explanation:**
Finds non-admin principals who can read LAPS (Local Admin Password Solution) passwords for endpoints. LAPS stores local admin passwords, which rotate per machine.

Importance:
If a non-Tier 0 account can read LAPS passwords, it can be used to escalate privileges or move laterally, potentially to domain controllers if local admin passwords are reused.

---

### 6. **Users with Password in Description**

```cypher
UNWIND ['pass', 'pwd', 'kenn', 'login', 'cred'] AS word
MATCH p = (:Domain)-[:Contains*1..]->(u:User)
WHERE (toLower(u.description) CONTAINS toLower(word))
RETURN p
LIMIT 1000
```

**Explanation:**
Searches for users who have cleartext passwords or hints in their description field.

Importance:
Storing passwords in description fields is a severe operational failure. Attackers can enumerate this information with basic LDAP queries and immediately compromise accounts.

---

### 7. **AS-REP Roastable Users (No Pre-Auth)**

```cypher
MATCH p = (:Domain)-[:Contains*1..]->(:Base {dontreqpreauth: true})
RETURN p
LIMIT 1000
```

**Explanation:**
Finds accounts with "Do not require Kerberos pre-authentication" set. Attackers can request authentication data for these users and brute-force their passwords offline (AS-REP roasting).

Importance:
AS-REP roastable accounts often have weak passwords and provide a low-to-high escalation path with no alerting. These must be found and corrected.

---

### 8. **Tier 0 Users Logins on Non-Tier 0 Computers**

```cypher
MATCH p = (c:Computer)-[:HasSession*1..]->(u:User)
WHERE "admin_tier_0" IN split(u.system_tags, " ")
  AND (NOT "admin_tier_0" IN split(c.system_tags, " ") OR c.system_tags is NULL)
RETURN p
LIMIT 1000
```

**Explanation:**
Identifies Tier 0 (domain admin) users with active sessions on computers not classified as Tier 0.

Importance:
This enables "privilege de-escalation," where attackers compromise a less secure workstation, dump credentials, and gain control of a domain admin. Lateral movement risk is extremely high.

---

## **High Priority (Direct Lateral Movement, Escalation, or Data Exposure)**

### 9. **Users with Password Stored in Cleartext Fields**

```cypher
MATCH p = (:Domain)-[:Contains*1..]->(u:User)
WHERE u.userpassword <> ""
  OR u.unixpassword <> ""
  OR u.sfupassword <> ""
  OR u.unicodepassword <> ""
RETURN p
LIMIT 1000
```

**Explanation:**
Identifies users with passwords stored in cleartext in AD attributes.

Importance:
Cleartext passwords in AD attributes provide immediate privilege escalation to any attacker with read access.

---

### 10. **Users with Password Stored Using Reversible Encryption**

```cypher
MATCH p = (:Domain)-[:Contains*1..]->(:Base {encryptedtextpwdallowed: true})
RETURN p
LIMIT 1000
```

**Explanation:**
Finds accounts allowed to store passwords using reversible encryption.

Importance:
Reversible encryption is functionally the same as storing passwords in cleartext, making these accounts extremely vulnerable.

---

### 11. **Resource-Based Constrained Delegation (RBCD)**

```cypher
MATCH p = (:Base)-[:AllowedToAct*1..]->(:Base)
RETURN p
LIMIT 1000
```

**Explanation:**
Shows all principals who have resource-based constrained delegation privileges, which are often targeted in modern privilege escalation attacks.

Importance:
Attackers abuse RBCD to compromise higher privilege accounts or perform cross-domain attacks if misconfigured.

---

### 12. **Dangerous Rights for Groups under Domain Users**

```cypher
UNWIND [...] AS group
MATCH p = (g:Group)-[:MemberOf*1..]->(:Group)-[:Owns|WriteDacl|GenericAll|WriteOwner|ExecuteDCOM|GenericWrite|AllowedToDelegate|ForceChangePassword]->(b)
WHERE g.objectid ENDS WITH group
RETURN p
LIMIT 1000
```

**Explanation:**
Finds low-privileged groups (like "Domain Users" or "Everyone") with dangerous rights on sensitive objects.

Importance:
Granting dangerous rights to broad, low-privilege groups dramatically increases risk, allowing easy privilege escalation or domain compromise.

---

## **Medium Priority (Indicators of Poor Hygiene, Local Lateral Movement)**

### 13. **Computer without LAPS**

```cypher
MATCH p = (:Domain)-[:Contains*1..]->(:Base {haslaps: false, isdc: false})
RETURN p
LIMIT 1000
```

**Explanation:**
Lists all non-DC computers without LAPS.

Importance:
Endpoints lacking LAPS may have shared, static local admin passwords, allowing lateral movement if one is compromised.

---

### 14. **Users with Password Never Expires**

```cypher
MATCH p = (:Domain)-[:Contains*1..]->(:Base {pwdneverexpires: true})
RETURN p
LIMIT 1000
```

**Explanation:**
Finds accounts whose passwords never expire.

Importance:
These accounts are at higher risk of compromise via password reuse or credential leaks, as the credentials can remain valid for years.

---

### 15. **All Sessions of All Users**

```cypher
MATCH p = (:Computer)-[:HasSession*1..]->(:User)
RETURN p
LIMIT 1000
```

**Explanation:**
Maps all user sessions to computers.

Importance:
Aids blue teams in tracking lateral movement, and helps red teams identify where privileged credentials are exposed in memory.

---

## **Low Priority (Inventory, Context, or Basic Hygiene Checks)**

### 16. **Domains with Machine Account Quota > 0**

```cypher
MATCH (d:Domain)
WHERE toInteger(d.machineaccountquota) > 0
RETURN d
LIMIT 1000
```

**Explanation:**
Checks if users can create computer accounts (default: 10 per user).

Importance:
Machine account quota can be abused for resource-based attacks but is a default AD behavior; prioritize only if threat actors can leverage it in your context.

---

### 17. **Owned Objects**

```cypher
MATCH p = (:Domain)-[:Contains*1..]->(b:Base)
WHERE "owned" IN split(b.system_tags, " ")
RETURN p
LIMIT 1000
```

**Explanation:**
Shows all AD objects tagged as "owned" (previously compromised).

Importance:
Useful for tracking persistence, but not inherently a direct risk unless mapped to attack paths.

---

---

# **References**

All explanations and queries are sourced from the original provided file [Queries\_c409a0.md](Queries.md).

---

## **Summary Table**

| Priority   | Query/Area                                   | Why It Matters                                                |
| ---------- | -------------------------------------------- | ------------------------------------------------------------- |
| **Top**    | Shortest Paths to Tier 0                     | Complete domain/forest compromise                             |
| **Top**    | Non-Tier 0 DCSync Accounts                   | Stealthy domain hash extraction & Golden Ticket attacks       |
| **Top**    | Kerberoastable Users in Tier 0               | Rapid domain admin compromise via Kerberoasting               |
| **Top**    | Unconstrained Delegation                     | Lateral movement to DA via delegation misconfigs              |
| **Top**    | LAPS Passwords Readable by Non-Admin         | Lateral movement/escalation to local admin and beyond         |
| **Top**    | Users with Password in Description           | Credential harvesting via LDAP enumeration                    |
| **Top**    | AS-REP Roastable Users                       | Offline brute-forcing; direct escalation                      |
| **Top**    | Tier 0 Users on Non-Tier 0 Computers         | Privilege de-escalation, lateral movement risk                |
| **High**   | Users with Password in Cleartext Fields      | Immediate credential theft                                    |
| **High**   | Users with Reversible Encryption             | Easily recoverable credentials                                |
| **High**   | Resource-Based Constrained Delegation (RBCD) | Modern lateral/vertical privilege escalation vector           |
| **High**   | Dangerous Rights for Domain Users Groups     | Broad exposure to privilege escalation                        |
| **Medium** | Computers Without LAPS                       | Password reuse, lateral movement                              |
| **Medium** | Users with Password Never Expires            | Long-term credential validity increases exposure              |
| **Medium** | All Sessions of All Users                    | Maps exposure of credentials in memory for privilege accounts |
| **Low**    | Machine Account Quota                        | Lower priority unless specifically abused in context          |
| **Low**    | Owned Objects                                | Tracking, not a direct risk unless mapped to attack path      |

---

**For further technical detail on any specific query or for additional recommendations on remediation strategies, let me know.**

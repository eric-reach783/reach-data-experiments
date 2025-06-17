
Sources:
- https://m4lwhere.medium.com/the-ultimate-guide-for-bloodhound-community-edition-bhce-80b574595acf
- https://github.com/netscylla/attack2neo
- https://specterops.github.io/TierZeroTable/

### Cross-Domain Collection

To collect data from other domains in the same forest, we’ll need to add a few additional flags. For instance, we’ll need to direct to the correct domain with the --domain flag. We’ll pivot to the sevenkingdoms.local domain next, while running as the hodor@north.sevenkingdoms.local user. This machine must be able to resolve the domain within DNS to work.
```bash
# Cross-domain collection mechanism (relies on trust between domains)
.\SharpHound.exe -c All --domain sevenkingdoms.local --zippassword 'p@ssw0rd' --outputprefix 'SEVENKINGDOMS'
```

Things to note:
- need to know the domains in the forests
- need to have DNS resoultions for the domian

### Collection as a Different User

In the event we’re in a forest but don’t have access to an account trusted on a separate domain, we can always launch SharpHound.exe with the runas.exe command.
```bash
# Start a cmd shell as another user, then collect data
runas /netonly /user:khal.drogo@essos.local cmd
.\SharpHound.exe -c All --domain essos.local --zippassword 'p@ssw0rd' --outputprefix 'ESSOS'
#OR
# Gather cross-domain information using LDAP authentication
.\SharpHound.exe -c All --domain essos.local --ldapusername khal.drogo --ldappassword horse --zippassword 'p@ssw0rd' --outputprefix 'ESSOS'
```

Sample Data:
- https://github.com/m4lwhere/Bloodhound-CE-Sample-Data
  - https://m4lwhere.medium.com/the-ultimate-guide-for-bloodhound-community-edition-bhce-80b574595acf


Query Links:
- https://neo4j.com/docs/cypher-cheat-sheet/5/all/
- https://github.com/gokupwn/cypherHound
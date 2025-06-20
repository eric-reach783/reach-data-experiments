
### BloodHound

#### ACEs
Access Control Entries - individual permissions records that define what each security principal can/can't do to AD objects.
Shows the inheritance of how permissions propagate roughly (boolean)

##### **BloodHound relies on enumerating ACEs across all AD objects to map out ACL-based attack paths**
Data Snippet:
```JSON
'Aces': [{'PrincipalSID': 'S-1-5-21-2697957641-2271029196-387917394-512',
   'PrincipalType': 'Group',
   'RightName': 'Owns',
   'IsInherited': False},
  {'PrincipalSID': 'PHANTOM.CORP-S-1-5-32-544',
   'PrincipalType': 'Group',
   'RightName': 'WriteDacl',
   'IsInherited': False},...
   ```


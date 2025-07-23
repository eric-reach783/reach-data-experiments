
## AzureHound
Written in GoLang, 

Repository: https://github.com/SpecterOps/AzureHound

### CLI Flags
Sources:
- https://bloodhound.specterops.io/collect-data/ce-collection/azurehound-flags
- https://bloodhound.specterops.io/collect-data/ce-collection/azurehound-flags
- [Full-doc-page](./AzureHound_CLI_flags.md)


### Authentication/Connection to Azure/Entra
- JWT
- Authenticating with a Service Principal Secret
- UPN - UserName/Password 
- Authenticating with a Refresh Token

### Permission Needed
- Principal user with read all

### Schemas:

Sources:
- https://github.com/SpecterOps/AzureHound
- https://bloodhound.specterops.io/collect-data/ce-collection/azurehound
- https://bloodhound.readthedocs.io/en/latest/data-collection/azurehound-all-flags.html
- https://bloodhound.specterops.io/integrations/bloodhound-api/json-formats
- https://bloodhound.specterops.io/collect-data/ce-collection/azurehound-flags

## BloodHound

### Schemas:

#### Expected Input Schema

Sources:
- https://github.com/SpecterOps/BloodHound/tree/main/cmd/api/src/test/fixtures/fixtures - Test fixtures
- https://github.com/SpecterOps/BloodHound/blob/main/cmd/api/src/test/fixtures/fixtures/v6/ingest/computers.json
- https://github.com/SpecterOps/BloodHound/blob/main/cmd/api/src/test/fixtures/fixtures/v6/all/computers.json

```json
{
  "data": [
    {
      [
        // Entity-specific data objects
      ]
    }
  ],
  "meta": {
    "methods": 127999,
    "type": "users", // or computers, groups, etc.
    "count": 1,
    "version": 5
  }
}
```


## Azure Schema Comparison







## Collector Performance


- https://bloodhound.specterops.io/collect-data/enterprise-collection/faq#how-does-sharphound-select-which-domain-controller-to-use-with-auto-negotiation
Collection time can vary from minutes to hours depending on the size of the environment (but other complicating factors can contribute to longer durations).

Example full scan and upload durations with privileged collection:

    15,000 users + groups, 4,000 computers, and AD CS: 45 minutes

        500,000 computers , and AD DS: 3 hours




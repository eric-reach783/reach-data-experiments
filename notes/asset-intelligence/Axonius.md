## REST API
- https://axonius-api-client.readthedocs.io/en/latest/main/usage_api/quickstart.html - This API is deprecated.

## Active Directory

Sources:
- https://docs.axonius.com/docs/microsoft-active-directory-ad

### Required Permissions
Same as BloodHound. 
```
The value supplied in User Name must be a service account with Read permissions to all assets and users in the AD tree. In addition, the user must have permission to run the Get-Acl powershell command to fetch Permissions.
```
Sources:
- https://docs.axonius.com/docs/microsoft-active-directory-ad#required-permissions

## BloodHound

BloodHound is used to find relationships within an Active Directory (AD) domain to discover attack paths.
This adapter fetches the following types of assets:
- Devices 
- Users
- Groups

Sources:
- https://docs.axonius.com/docs/bloodhound

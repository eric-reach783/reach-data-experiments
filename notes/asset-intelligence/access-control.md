# Schema Documentation for Access Control in Okta and CrowdStrike

Both Okta and CrowdStrike provide extensive schema documentation for their access control mechanisms through their
respective API documentation portals. This document details the specific fields, data types, and documentation locations
for access control functionality in both platforms.

## Okta Access Control Schema Documentation

### Primary Documentation Sources

Okta's schema documentation is centralized in their **new API reference portal** at developer.okta.com. The most
relevant APIs for access control are the System Log API, Users API, Devices API, and Authentication API.

### Core Access Control Fields

#### Actor Identification Fields

The **actor.displayName** is part of the System Log API event schema:

- **Field Path**: `actor.displayName`
- **Data Type**: String
- **Purpose**: Identifies the display name of the user or system who performed an action
- **Access Control Use**: Critical for audit trails and identifying who performed access-related actions
- **Related Fields**: `actor.alternateId` (username), `actor.id` (unique identifier)

#### Authentication Context Schema

Okta's authentication context provides session tracking. These fields enable session-based access control and comprehensive authentication auditing:

- **authenticationContext.externalSessionId**: Links events within the same user session
- **authenticationContext.rootSessionId**: Tracks all events related to a user's authentication, including system
  actions on their behalf
- **authenticationContext.authenticationProvider**: Identifies the authentication method used
- **authenticationContext.credentialType**: Specifies the type of credential (password, biometric, etc.)


#### Device-Related Identifiers

Okta implements device tracking through multiple mechanisms:

- **X-Device-Token Header**: 32-character string for adaptive MFA and new device detection
- **X-Device-Fingerprint Header**: Device fingerprint for recognition (deprecated for security detection but still used
  for notifications)
- **Device Status Fields**: `status` (ACTIVE/SUSPENDED/DEACTIVATED), `platform` (iOS/Android/Windows/macOS)
- **Device Trust Attributes**: `device.trusted`, `device.managed`, `device.registered`

These fields enable device-based access policies and conditional access based on device state.

### API Endpoints and Direct Links

- **System Log API**: `https://{yourOktaDomain}/api/v1/logs`
- **Users API**: `https://{yourOktaDomain}/api/v1/users`
- **Devices API**: `https://{yourOktaDomain}/api/v1/devices`
- **Authentication API**: `https://{yourOktaDomain}/api/v1/authn`

The complete schema documentation with field descriptions, data types, and examples is available through the Okta API
reference portal.

## CrowdStrike Access Control Schema Documentation

### Primary Documentation Sources

CrowdStrike provides region-specific API documentation through multiple endpoints:

- **US-1**: https://assets.falcon.crowdstrike.com/support/api/swagger.html
- **US-2**: https://assets.falcon.us-2.crowdstrike.com/support/api/swagger-us2.html
- **EU-1**: https://assets.falcon.eu-1.crowdstrike.com/support/api/swagger-eu.html
- **Developer Portal**: https://developer.crowdstrike.com

### Core Access Control Fields

#### Device Identification Schema

The **device_id** field you mentioned is the primary device identifier:

- **Field Name**: `device_id`
- **Data Type**: 32-character hexadecimal string
- **Purpose**: Core identifier for endpoint identification throughout Falcon
- **Access Control Use**: Primary key for device-based access control and authorization
- **Example**: `"4ae0067ea4984524af0efc0bf94a62f5"`

Additional device identifiers include:

- **aid (Agent ID)**: Alternative 32-character device identifier used in FQL queries
- **cid (Customer ID)**: Tenant-level identifier for multi-tenant access control
- **Network Identifiers**: `local_ip`, `external_ip`, `mac_address` for network-based access control

#### User/Actor Identification Schema

CrowdStrike implements user tracking through multiple fields:

- **user_id/userid**: Primary user identifier for authentication events
- **UserId** (in Event Streams): Tracks user actions, can contain email addresses
- **UserIp**: IP address for location-based access control
- **Authentication Fields**: `Success`, `OperationName`, `ServiceName` for authentication auditing

#### OAuth2 Authentication Schema

CrowdStrike uses OAuth2 for API access control:

- **client_id**: 32-character lowercase hexadecimal string
- **client_secret**: 40-character alphanumeric string
- **access_token**: JWT format bearer token (30-minute validity)
- **API Scopes**: Granular permissions like `hosts:read/write`, `detections:read/write`, `user-management:read/write`

### Event Schema for Access Control

CrowdStrike's Event Streams API provides real-time access control monitoring with fields including:

- **Detection Events**: `DetectDescription`, `Severity`, `SeverityName`
- **Incident Tracking**: `IncidentId`, `IncidentType`, `State`
- **Identity Protection**: Product event type `"IdentityProtectionEvent"`
- **Host Identification**: `ComputerName`, `hostname`

### API Endpoints for Access Control

- **Device Details**: `/devices/entities/devices/v2`
- **OAuth2 Token**: `/oauth2/token`
- **Device Queries**: `/devices/queries/devices-scroll/v1`
- **User Management**: `/user-management/` endpoints
- **Identity Protection**: `/identity-protection/` endpoints

## Key Implementation Considerations

### Data Types and Formats

Both platforms use consistent data type patterns:

- **Identifiers**: Typically 32-character hexadecimal strings
- **Timestamps**: ISO 8601 format
- **Status Fields**: Enumerated values (ACTIVE, SUSPENDED, etc.)
- **IP Addresses**: Standard IPv4/IPv6 format

### Access Control Mechanisms

**Okta** implements access control through:

- Session-based tracking with root and external session IDs
- Device trust evaluation for conditional access
- Event correlation using transaction IDs
- Policy evaluation events (`policy.evaluate_sign_on`)

**CrowdStrike** implements access control through:

- OAuth2 scope-based API permissions
- Device and agent ID tracking
- Network-based identification
- Real-time event streaming for monitoring

### Schema Evolution and Versioning

Both platforms maintain backward compatibility while adding new fields. Okta uses versioned APIs (v1, v2), while
CrowdStrike provides region-specific endpoints with consistent schemas.

## Accessing Complete Schema Documentation

For the most current and complete schema documentation:

1. **Okta**: Access the new API reference portal at developer.okta.com with your Okta credentials
2. **CrowdStrike**: Use the region-specific Swagger documentation URLs with valid API credentials
3. Both platforms provide Postman collections and SDK support for easier integration

The schema documentation includes complete field descriptions, validation rules, example values, and implementation
guidance for all access control mechanisms.

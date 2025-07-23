# Axonius API Documentation

## Overview

Axonius provides a comprehensive REST API and Python API client for managing and querying asset data. This documentation is scraped from the official Axonius API client documentation.

**Source**: [[1]](https://axonius-api-client.readthedocs.io/)

## API Client Features

The Axonius API Client is a fully modeled Python API library that makes using the Axonius REST API easy.

### Key Components

1. **Python API Library** - A fully modeled python API library that makes using the Axonius REST API easy
2. **Command Line Interface** - A powerful command line interface that exposes most of the functionality of the API
3. **Documentation** - Comprehensive documentation available on Read the Docs

### Resources

- **Documentation**: https://axonius-api-client.readthedocs.io/
- **PyPi Package**: Available for easy installation via pip
- **GitHub Repository**: https://github.com/Axonius/axonius_api_client

## API Endpoints

Based on web search results, the key Axonius REST API endpoints include:

- `GET /api/devices` - Retrieve device information
- `GET /api/users` - Retrieve user information

**Source**: [[2]](https://docs.brinqa.com/docs/connectors/axonius-connector/)

## API Versions

- **APIv2**: The newer version designed to enhance the REST API experience with more intuitive interface and cleaner endpoints
- **APIv1**: Legacy version still supported

**Source**: [[3]](https://docs.axonius.com/docs/axonius-rest-api)

## CLI Commands Overview

The Axonius CLI provides extensive functionality through the `axonshell` command:

### Installation and Setup

1. **Install the package**: Available via pip
2. **Setup connection information**: Configure API credentials
3. **Use the axonshell CLI**: Access full CLI functionality

### Asset Management Commands

#### Device and User Operations
- `devices/users count` - Count assets
- `devices/users count-by-saved-query` - Count assets by saved query
- `devices/users get` - Get all assets for devices or users, export to CSV or JSON
- `devices/users get-by-id` - Get specific assets by ID
- `devices/users get-by-saved-query` - Get assets using saved queries
- `devices/users get-fields` - Get available fields
- `devices/users get-fields-default` - Get default fields
- `devices/users get-tags` - Get asset tags

#### Saved Query Management
- `devices/users saved-query add` - Add new saved queries
- `devices/users saved-query delete-by-name` - Delete queries by name
- `devices/users saved-query delete-by-tags` - Delete queries by tags
- `devices/users saved-query get` - Get saved queries
- `devices/users saved-query get-by-name` - Get specific saved query by name

### Adapter Management Commands

#### Adapter Operations
- `adapters get` - Get adapter information
- `adapters cnx add` - Add new connections
- `adapters cnx add-from-json` - Add connections from JSON
- `adapters cnx delete-by-id` - Delete connections by ID
- `adapters cnx get` - Get connection information
- `adapters cnx get-by-id` - Get specific connection by ID
- `adapters cnx test` - Test connections

## API Integration Use Cases

### Asset Discovery and Management
- Export device and user data to CSV or JSON formats
- Query assets using custom filters and saved queries
- Manage asset tags and field configurations

### Dashboard and Query Management
- Import/Export dashboards and queries via API
- Use Postman to execute API commands
- Programmatic management of saved queries

**Source**: [[4]](https://docs.axonius.com/docs/importexport-dashboards-and-queries-via-api)

### Third-Party Integrations
- ServiceNow CMDB integration
- Scripted REST API implementations
- Validation of existing CIs in external systems

**Source**: [[5]](https://www.servicenow.com/community/cmdb-forum/axonius-integration-with-servicenow/td-p/2554070)

## API Security and Configuration

### API Settings Management
- View and copy API key and secret
- Reset API credentials when needed
- Enable advanced API features from System Settings

**Source**: [[6]](https://docs.axonius.com/docs/managing-api-settings)

## Data Export Capabilities

The API supports comprehensive data export functionality:
- **CSV Export**: Export asset data in CSV format for analysis
- **JSON Export**: Export structured data in JSON format
- **Bulk Operations**: Handle large datasets efficiently
- **Field Selection**: Choose specific fields for export

## Quick Start Example

```bash
# Install the package
pip install axonius-api-client

# Setup connection (example)
axonshell devices get --export-file devices.csv --export-format csv

# Get device count
axonshell devices count

# Get specific device by ID
axonshell devices get-by-id --id "device-id-here"
```

## Notes

- Some official Axonius documentation requires authentication and may return 403 errors when accessed programmatically
- The API client provides comprehensive functionality for asset management and querying
- Both REST API and Python client library are actively maintained
- CLI interface provides easy access to most API functionality without coding

---

*This documentation was compiled from publicly available Axonius API documentation and community resources as of the scraping date.*
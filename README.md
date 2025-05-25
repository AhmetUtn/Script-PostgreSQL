# PostgreSQL Security Setup Script

This script provides a comprehensive security configuration tool for PostgreSQL database servers. It offers various security features and management options through an interactive menu system.

## Features

- Restrict PostgreSQL to specific IP addresses
- Configure authentication settings
- Manage user permissions
- Restrict external program access
- Apply all security measures at once

## Prerequisites

- Linux operating system
- PostgreSQL server installed
- Root or sudo privileges
- Bash shell

## Installation

1. Download the script:
```bash
wget https://raw.githubusercontent.com/AhmetUtn/postgresql-security-setup/main/postgresql_security_setup.sh
```

2. Make the script executable:
```bash
chmod +x postgresql_security_setup.sh
```

## Usage

Run the script with sudo privileges:
```bash
sudo ./postgresql_security_setup.sh
```

### Main Menu Options

1. **Restrict PostgreSQL to Internet and Allow Specific IPs**
   - View current IP list
   - Add new IP addresses
   - Remove existing IP addresses
   - Automatically creates backup of configuration files

2. **Configure Authentication Settings**
   - Enables SCRAM-SHA-256 password encryption
   - Creates backup of authentication configuration

3. **Manage User Permissions**
   - View all user permissions
   - View specific user permissions
   - View database permissions
   - Grant multiple permissions
   - Revoke multiple permissions
   - Create new users
   - Delete users

4. **Restrict External Program Access**
   - View users with external program execution rights
   - Remove external program execution rights

5. **Apply All Security Measures**
   - Executes all security configurations in sequence

6. **Exit**
   - Safely exits the script

## Security Features

- IP-based access control
- Enhanced password encryption
- Granular user permission management
- External program access restrictions
- Automatic configuration backups

## Backup Files

The script automatically creates backup files before making changes:
- PostgreSQL configuration: `postgresql.conf.backup`
- Authentication configuration: `pg_hba.conf.backup`

## Error Handling

- The script includes comprehensive error checking
- Failed operations are clearly reported
- Configuration changes are only applied after successful validation

## Notes

- Always backup your database before running security scripts
- Test the script in a development environment first
- Some changes may require PostgreSQL service restart
- Keep track of the IP addresses you allow for access

## Troubleshooting

If you encounter issues:
1. Check PostgreSQL service status
2. Verify file permissions
3. Ensure you have sudo privileges
4. Check PostgreSQL logs for detailed error messages

## Contributing

Feel free to submit issues and enhancement requests!

## License

This project is licensed under the MIT License - see the LICENSE file for details.

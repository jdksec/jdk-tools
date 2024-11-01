import uuid
import ipaddress
from smbprotocol.connection import Connection
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect
from smbprotocol.open import Open, FileAttributes

def smb_login_check(server_ip, username, password, domain):
    """
    Attempts to log in to an SMB server on the given IP with the provided credentials.
    Silently skips errors if the host is unreachable or access is denied.
    """
    try:
        # Establish a connection
        connection = Connection(uuid.uuid4(), server_ip, port=445)
        connection.connect()
        
        try:
            # Set up a session with the provided credentials
            session = Session(connection, username, password, domain)
            session.connect()

            # Try to connect to the C$ share
            tree = TreeConnect(session, f"\\\\{server_ip}\\c$")
            tree.connect()

            # Attempt to open the root of the share to check access
            share = Open(tree, "")
            share.create(FileAttributes.FILE_ATTRIBUTE_DIRECTORY)
            print(f"Success: Access to \\\\{server_ip}\\c$ granted for {username}")
            share.close()
            tree.disconnect()
            session.disconnect()
            return True
        except Exception:
            # Silently skip any authentication or access errors
            return False
        finally:
            connection.disconnect()

    except Exception:
        # Silently skip if the host is unreachable
        return False

def smb_login_check_subnet(subnet, username, password, domain):
    """
    Scans each IP in the given subnet for access to the SMB C$ share.
    """
    network = ipaddress.ip_network(subnet, strict=False)
    for ip in network.hosts():  # Iterate over all valid hosts in the subnet
        print(f"Checking SMB access for {ip}...")
        if smb_login_check(str(ip), username, password, domain):
            print(f"Access granted for {ip}")
        else:
            print(f"Access denied or unreachable for {ip}")

# Example usage
subnet = "192.168.1.0/24"  # Replace with the target subnet
username = "your_username"   # Replace with target username
password = "your_password"   # Replace with target password
domain = "your_domain"       # Replace with target domain

smb_login_check_subnet(subnet, username, password, domain)

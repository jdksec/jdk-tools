import paramiko
import sys

ssh_key_file = sys.argv[1]
host = sys.argv[2]

ssh = paramiko.SSHClient()

ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

try:
    ssh.connect(host, username='username', key_filename=ssh_key_file)
    print('SSH key is valid for remote server.')
except paramiko.AuthenticationException:
    pass
except paramiko.SSHException as e:
    pass
finally:
    ssh.close()

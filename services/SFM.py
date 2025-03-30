import paramiko
from threading import Lock

class SSHManager:
    def __init__(self):
        self.client = None
        self.lock = Lock()

    def connect(self, host, username, password):
        with self.lock:
            try:
                self.client = paramiko.SSHClient()
                self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                self.client.connect(host, username=username, password=password)
            except paramiko.AuthenticationException:
                raise Exception(f"Authentication failed for {username}@{host}. Check credentials.")
            except paramiko.SSHException as e:
                raise Exception(f"Failed to connect to {host}: {str(e)}")
            except Exception as e:
                raise Exception(f"Unexpected error connecting to {host}: {str(e)}")

    def execute_command(self, command, log_callback):
        if not self.client:
            raise Exception("Not connected to the server")
        with self.lock:
            stdin, stdout, stderr = self.client.exec_command(command)
            for line in iter(stdout.readline, ""):
                log_callback(line.strip())
            error = stderr.read().decode()
            if error:
                log_callback(f"Error: {error}")

    def close(self):
        with self.lock:
            if self.client:
                self.client.close()
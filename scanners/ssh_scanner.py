"""
SSH client for host/server OS checks.

Uses paramiko for safe command execution:
- ss -tlnp (open ports)
- systemctl list-units (services)
- cat /etc/ssh/sshd_config
- find permissions checks
"""

import paramiko
from typing import Optional


class SSHScanner:
    """This is class that handle the initialization of SSH
    """
    def __init__(self, host: str, user: str, key_path: Optional[str] = None, 
                 password: Optional[str] = None, verbose: bool = False):
        self.host = host
        self.user = user
        self.key_path = key_path
        self.password = password
        self.verbose = verbose
        self.client = None
        
    def connect(self):
        """Connect and return client."""
        if self.verbose:
            print(f"[DEBUG] SSH: connecting to {self.host}:{self.user}")
            
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        kwargs = {
            "hostname": self.host,
            "username": self.user,
            "timeout": 10,
            "look_for_keys": False,
            "allow_agent": False,
        }
        
        if self.key_path:
            kwargs["key_filename"] = self.key_path
        elif self.password:
            kwargs["password"] = self.password
            
        self.client.connect(**kwargs)
        return self.client
    
    def run_command(self, cmd: str, verbose: Optional[bool] = None) -> tuple[str, int]:
        """Run command and return (output, exit_code)."""
        verbose = verbose if verbose is not None else self.verbose 
        
        if verbose:
            print(f"[DEBUG] SSH: '{cmd}'")
            
        stdin, stdout, stderr = self.client.exec_command(cmd)
        output = stdout.read().decode("utf-8", errors="ignore").strip()
        exit_code = stdout.channel.recv_exit_status()
        
        if verbose:
            print(f"[DEBUG] SSH: {len(output)} chars, exit={exit_code}")
        return output, exit_code
    
    def detect_os_version(self) -> str:
        """Detect host OS version."""
        try:
            output, _ = self.run_command(
                "lsb_release -ds 2>/dev/null || "
                "grep '^PRETTY_NAME=' /etc/os-release | cut -d'=' -f2 | tr -d '\"' || "
                "grep '^NAME=' /etc/os-release | cut -d'=' -f2 | tr -d '\"'",
                verbose=self.verbose
            )
            os_name = output.strip()
            return os_name if os_name else "Unknown Linux"
        except:
            return "Unknown OS"
    
    def close(self):
        if self.client:
            self.client.close()
"""
Docker client for container runtime analysis.

Uses docker-py library for:
- docker ps, docker inspect
- Container user, ports, resources
- Image analysis
"""


import docker
from typing import Optional
from pathlib import Path
from docker.models.containers import Container

from sec_audit.results import ScanResult


class DockerScanner:
    """ This is a class that handle the docker scanner"""
    def __init__(self, docker_host: Optional[str] = None, verbose: bool = False, scan_result: Optional[ScanResult] = None):
        self.docker_host = docker_host
        self.verbose = verbose
        self.client = None
        self.scan_result = scan_result
    
    
    def connect(self) -> docker.DockerClient:
        """Connect to Docker daemon and return client."""
        if self.verbose:
            print(f"[DEBUG] Docker: creating client (docker_host={self.docker_host!r})")
        
        try:
            self.client = docker.DockerClient(base_url=self.docker_host) if self.docker_host else docker.from_env()
            
            # Detect Docker version (only if scan_result provided)
            if self.scan_result is not None:
                try:
                    version_info = self.client.version()
                    self.scan_result._docker_version = version_info.get("Version", "unknown")
                    if self.verbose:
                        print(f"[DEBUG] Docker version detected: {self.scan_result._docker_version}")
                except Exception:
                    if self.verbose:
                        print("[DEBUG] Could not detect Docker version")
                        
            if self.verbose:
                info = self.client.version()
                print(f"[DEBUG] Docker: connected, server_version={info.get('Version')!r}")
                
            return self.client
        except Exception as exc:
            if self.verbose:
                print(f"[DEBUG] Docker: client creation failed: {exc!r}")
            raise RuntimeError(f"Docker daemon not accessible ({exc})")
    
    
    def get_target_container(self) -> Container:
        """Get first running container (same logic as before)."""
        if self.verbose:
            print("[DEBUG] Docker: listing running containers...")
        
        containers = self.client.containers.list(filters={"status": "running"})
        if not containers:
            if self.verbose:
                print("[DEBUG] Docker: no running containers found")
            raise RuntimeError("No running Docker containers found")
        
        container = containers[0]
        if self.verbose:
            print(f"[DEBUG] Docker: selected container name={container.name!r}, id={container.id[:12]!r}")
        return container
    
    
    def get_container_info(self, container: Container) -> dict:
        """Extract common container info used by checks."""
        return {
            "user": container.attrs.get("Config", {}).get("User", "") or "",
            "ports": container.attrs.get("HostConfig", {}).get("PortBindings", {}) or {},
            "memory_limit": container.attrs.get("HostConfig", {}).get("Memory"),
            "cpu_limit": container.attrs.get("HostConfig", {}).get("CpuQuota") or container.attrs.get("HostConfig", {}).get("NanoCpus"),
            "healthcheck": container.attrs.get("Config", {}).get("Healthcheck"),
            "image": container.image.tags[0] if container.image.tags else "unknown",
            "env": container.attrs.get("Config", {}).get("Env", []),
        }
        
        
class DockerfileScanner:
    """ This is a file that handle the docker file scanner"""
    def __init__(self, path: str, verbose: bool = False):
        """This is the method that handle the initialization"""
        self.path = Path(path)
        self.verbose = verbose
        self.lines: list[str] = []


    def load(self):
        """This is the method that handles the load"""
        if self.verbose:
            print(f"[DEBUG] DOCKERFILE: loading from {self.path!r}")
        text = self.path.read_text(encoding="utf-8", errors="ignore")
        self.lines = [line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]


    def has_user_instruction(self) -> bool:
        """This is the method that check for instructions"""
        if not self.lines:
            self.load()
        return any(line.upper().startswith("USER ") for line in self.lines)


    def has_healthcheck(self) -> bool:
        """The method that check for the health of the system

        Returns:
            bool: true otherwise false
        """
        if not self.lines:
            self.load()
        return any(line.upper().startswith("HEALTHCHECK ") for line in self.lines)
    
    
    def get_base_image(self) -> Optional[str]:
        """Return the image string from the first FROM instruction, or None."""
        if not self.lines:
            self.load()
        for line in self.lines:
            if line.upper().startswith("FROM "):
                # everything after FROM
                return line.split(None, 1)[1]
        return None

    def uses_latest_tag(self) -> bool:
        """Return True if the base image uses 'latest' or no explicit tag."""
        base = self.get_base_image()
        if not base:
            return False
        # examples:
        #   python:3.10-slim  -> has colon -> not latest
        #   python:latest      -> latest
        #   python             -> no colon -> latest-ish
        if ":" not in base:
            return True
        return base.endswith(":latest")
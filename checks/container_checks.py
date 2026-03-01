"""
Container/Docker Runtime Checks (6 checks)

1. Non-root container user
2. Minimal ports exposed
3. Resource limits (CPU/memory)
4. Health checks configured
5. Trusted image registry
6. Secrets not hardcoded
"""


from typing import Optional, List

from scanners.docker_scanner import DockerScanner, DockerfileScanner
from sec_audit.results import CheckResult, Status, Severity
from scanners.compose_scanner import ComposeScanner
from sec_audit.config import CHECKS


def _meta(check_id: str):
    for c in CHECKS:
        if c["id"] == check_id:
            return c
    raise KeyError(f"Unknown check id: {check_id}")


# ==================== 6 REAL CHECKS ====================
def check_non_root_user(docker_host: Optional[str] = None, verbose: bool = False) -> CheckResult:
    """
    CONT-USER-001: Container runs as non-root user.

    Why it matters:
    - Running as root in a container increases impact of breakout or misconfigurations.

    Logic:
    - Inspect Config.User of the target container.
    - If empty / "0" / "root" → FAIL.
    - Otherwise PASS.
    """
    meta = _meta("CONT-USER-001")
    
    if not docker_host:
        if verbose:
            print("[DEBUG] CONT-USER-001: docker_host not provided; returning WARN")
        status = Status.WARN
        details = "Docker host not specified (--docker-host required for full mode)"

    
    scanner = DockerScanner(docker_host, verbose)
    try:
        scanner.connect()
        container = scanner.get_target_container()
        info = scanner.get_container_info(container)
        user = info["user"]
        
        if verbose:
            print(f"[DEBUG] CONT-USER-001: Config.User={user!r}")
        
        if not user or user == "0" or user.lower() == "root":
            status = Status.FAIL
            details = f"Container runs as root (User: '{user}'). → Add USER 1000 to Dockerfile"
        
        status = Status.PASS
        details = f"Container runs as non-root user '{user}' ✓"    
        
    except Exception as e:
        if verbose:
            print(f"[DEBUG] CONT-USER-001: exception {e!r}")
        status = Status.WARN
        details = f"Docker error while checking container user: {str(e)}"
    
    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=status, severity=Severity[meta["severity"]], details=details
    )


def check_minimal_ports(docker_host: Optional[str] = None, verbose: bool = False) -> CheckResult:
    """
    CONT-PORT-001: Minimize exposed host ports.

    Why it matters:
    - Each published host port is an entry point; minimising them reduces attack surface.

    Logic:
    - Inspect HostConfig.PortBindings of the target container.
    - PASS if 0–2 ports; WARN if more than 2.
    """
    meta = _meta("CONT-PORT-001")
    
    if not docker_host:
        if verbose:
            print("[DEBUG] CONT-PORT-001: docker_host not provided; returning WARN")
        status = Status.WARN
        details = "Docker host not specified. Cannot inspect published ports."

    
    scanner = DockerScanner(docker_host, verbose)
    try:
        scanner.connect()
        container = scanner.get_target_container()
        info = scanner.get_container_info(container)
        
        port_bindings = info["ports"]
        exposed_count = len(port_bindings)
        if verbose:
            print(f"[DEBUG] CONT-PORT-001: PortBindings={port_bindings!r}, count={exposed_count}")
        
        if exposed_count == 0:
            status = Status.PASS
            details = "No host ports exposed ✓"

        elif exposed_count <= 2:
            status = Status.PASS
            details = f"{exposed_count} host port(s) published: {list(port_bindings.keys())}."

        else:
            status = Status.WARN
            details = f"{exposed_count} host ports published: {list(port_bindings.keys())}. Review and close unused ports."
            
    except Exception as e:
        if verbose:
            print(f"[DEBUG] CONT-PORT-001: exception {e!r}")
        status = Status.WARN
        details = f"Docker error while checking ports: {str(e)}"
        
    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=status, severity=Severity[meta["severity"]], details=details
    )



def check_health_checks(docker_host: Optional[str] = None, verbose: bool = False) -> CheckResult:
    """
    CONT-HEALTH-001: Healthcheck configured.

    Why it matters:
    - Healthchecks enable orchestrators to detect and replace unhealthy containers.

    Logic:
    - Inspect Config.Healthcheck.Test in container config.
    - WARN if missing, PASS if present.
    """
    meta = _meta("CONT-HEALTH-001")
    
    if not docker_host:
        if verbose:
            print("[DEBUG] CONT-HEALTH-001: docker_host not provided; returning WARN")
        status = Status.WARN
        details = "Docker host not specified. Cannot inspect container healthcheck."

    
    scanner = DockerScanner(docker_host, verbose)
    try:
        scanner.connect()
        container = scanner.get_target_container()
        info = scanner.get_container_info(container)
        
        healthcheck = info["healthcheck"]
        if verbose:
            print(f"[DEBUG] CONT-HEALTH-001: Healthcheck={healthcheck!r}")
        
        if not healthcheck or not healthcheck.get("Test"):
            status = Status.WARN
            details = "No HEALTHCHECK in Dockerfile. Add: HEALTHCHECK CMD curl -f http://localhost/ || exit 1"

        status = Status.PASS
        details = f"Healthcheck configured ✓"

    except Exception as e:
        if verbose:
            print(f"[DEBUG] CONT-HEALTH-001: exception {e!r}")
        status = Status.WARN
        details = f"Docker error while checking healthcheck: {str(e)}."

    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=status, severity=Severity[meta["severity"]], details=details
    )


def check_resource_limits(docker_host: Optional[str] = None, verbose: bool = False) -> CheckResult:
    """
    CONT-RES-001: CPU/Memory resource limits set.

    Why it matters:
    - Limits help prevent a single container from exhausting host resources.

    Logic:
    - Inspect HostConfig for CpuQuota/NanoCpus and Memory.
    - PASS if any limit is set; WARN otherwise.
    """
    meta = _meta("CONT-RES-001")
    
    if not docker_host:
        if verbose:
            print("[DEBUG] CONT-RES-001: docker_host not provided; returning WARN")
        status = Status.WARN
        details = "Docker host not specified. Cannot inspect CPU/memory limits."

    
    scanner = DockerScanner(docker_host, verbose)
    try:
        scanner.connect()
        container = scanner.get_target_container()
        info = scanner.get_container_info(container)
        
        
        cpu_limit = info["cpu_limit"]
        mem_limit = info["memory_limit"]
        if verbose:
            print(f"[DEBUG] CONT-RES-001: CpuQuota/NanoCpus={cpu_limit}, Memory={mem_limit}")
        
        if mem_limit or cpu_limit:
            status = Status.PASS
            details = f"Limits detected: Memory={mem_limit}B, CPU={cpu_limit}"

        status = Status.WARN
        details = "No CPU/memory limits. Add to docker-compose.yml: deploy.resources.limits"

    except Exception as e:
        if verbose:
            print(f"[DEBUG] CONT-RES-001: exception {e!r}")
        status = Status.WARN
        details = f"Docker error while checking resource limits: {str(e)}."
        
    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=status, severity=Severity[meta["severity"]], details=details
    )



def check_image_registry(docker_host: Optional[str] = None, verbose: bool = False) -> CheckResult:
    """
    CONT-REG-001: Trusted image registry source.

    Why it matters:
    - Pulling from unverified registries increases supply chain risk.

    Logic (heuristic):
    - Check image tag of target container.
    - PASS if from an 'official' or known-good namespace (simple heuristic).
    - WARN otherwise.
    """
    meta = _meta("CONT-REG-001")
    
    if not docker_host:
        if verbose:
            print("[DEBUG] CONT-REG-001: docker_host not provided; returning WARN")
        status = Status.WARN
        details = "Docker host not specified. Cannot inspect image source."

    
    scanner = DockerScanner(docker_host, verbose)
    try:
        scanner.connect()
        container = scanner.get_target_container()
        info = scanner.get_container_info(container)
        
        image_name = info["image"]
        

        if verbose:
            print(f"[DEBUG] CONT-REG-001: image_name={image_name!r}")
        
         # Simple heuristic for "trusted": official Docker Hub library images or specific known images
        trusted_markers = [
            "docker.io/library/",
            "nginx:",
            "python:",
            "postgres:",
            "redis:",
        ]
        
        if any(marker in image_name for marker in trusted_markers):
            status = Status.PASS
            details = f"Image appears to come from a trusted/official source: {image_name}"

        status = Status.WARN
        details = f"Image '{image_name}' does not clearly match trusted registries; ensure it comes from an official or verified source."
        
    except Exception as e:
        if verbose:
            print(f"[DEBUG] CONT-REG-001: exception {e!r}")
            status = Status.WARN
            details = f"Docker error while checking image registry: {str(e)}."
            
    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=status, severity=Severity[meta["severity"]], details=details
    )



def check_no_secrets(docker_host: Optional[str] = None, verbose: bool = False) -> CheckResult:
    """
    CONT-SEC-001: No secrets in environment.

    Why it matters:
    - Hardcoded secrets (passwords, API keys) in env or images are a major risk.

    Logic (heuristic):
    - Inspect Config.Env for variables whose names include:
      password, secret, key, token, api_key.
    - If any found, FAIL with a short sample list.
    - Otherwise PASS.
    """
    meta = _meta("CONT-SEC-001")
    
    if not docker_host:
        if verbose:
            print("[DEBUG] CONT-SEC-001: docker_host not provided; returning WARN")
        status = Status.WARN
        details = "Docker host not specified. Cannot inspect container environment."

    
    scanner = DockerScanner(docker_host, verbose)
    try:
        scanner.connect()
        container = scanner.get_target_container()
        info = scanner.get_container_info(container)
        
        env_vars = info["env"]
        if verbose:
            print(f"[DEBUG] CONT-SEC-001: found {len(env_vars)} env vars")
        
        suspicious_names = ["password", "secret", "key", "token", "api_key"]
        secrets_found = [
            env
            for env in env_vars
            if any(kw in env.split("=", 1)[0].lower() for kw in suspicious_names)
        ]
        
        if verbose:
            print(f"[DEBUG] CONT-SEC-001: secrets_found={secrets_found!r}")
        
        if secrets_found:
            sample = secrets_found[:2]
            status = Status.FAIL
            details = (f"Environment variables with secret-like names detected (sample: {sample}). "
                       "Move secrets to Docker secrets or a dedicated vault.")

        status = Status.PASS
        details = "No obvious secrets in environment variables ✓"

    except Exception as e:
        if verbose:
            print(f"[DEBUG] CONT-SEC-001: exception {e!r}")
        status = Status.WARN
        details = f"Docker error while checking environment secrets: {str(e)}."
        
    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=status, severity=Severity[meta["severity"]], details=details
    )

    
    
def check_dockerfile_user(path: Optional[str] = None, verbose: bool = False) -> CheckResult:
    """
    CONT-CONF-USER: Dockerfile defines non-root USER.
    """
    meta = _meta("CONT-CONF-USER")
    
    if not path:
        if verbose:
            print(f"[DEBUG] CONT-CONF-USER: Dockerfile path not provided; cannot statically verify USER.")
        status = Status.WARN
        details = "Dockerfile path not provided; cannot statically verify USER."


    try:
        scanner = DockerfileScanner(path, verbose)
        if scanner.has_user_instruction():
            status = Status.PASS
            details = "Dockerfile defines a USER instruction (non-root recommended)."
           
        status = Status.FAIL
        details = "Dockerfile has no USER instruction; containers will default to root. Add USER 1000:1000 or similar."
        
    except Exception as e:
        if verbose:
            print(f"[DEBUG] CONT-CONF-USER: exception {e!r}")
        status = Status.WARN
        details = f"Error parsing Dockerfile: {e}"

    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=status, severity=Severity[meta["severity"]], details=details
    )



def check_dockerfile_healthcheck(path: Optional[str] = None, verbose: bool = False) -> CheckResult:
    """
    CONT-CONF-HEALTH: Dockerfile defines HEALTHCHECK.
    """
    meta = _meta("CONT-CONF-HEALTH")

    if not path:
        if verbose:
            print("[DEBUG] CONT-CONF-HEALTH: Dockerfile path not provided; cannot statically verify HEALTHCHECK.")
        status = Status.WARN
        details = "Dockerfile path not provided; cannot statically verify HEALTHCHECK."
        

    try:
        scanner = DockerfileScanner(path, verbose)
        if scanner.has_healthcheck():
            status = Status.PASS
            details = "Dockerfile defines a HEALTHCHECK instruction."
        else:
            status = Status.WARN
            details = "No HEALTHCHECK in Dockerfile; add one for better container monitoring."
    except Exception as e:
        if verbose:
            print(f"[DEBUG] CONT-CONF-HEALTH: exception {e!r}")
        status = Status.WARN
        details = f"Error parsing Dockerfile: {e}"

    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=status, severity=Severity[meta["severity"]], details=details,
    )


def check_dockerfile_best_practices(path: Optional[str] = None, verbose: bool = False) -> CheckResult:
    meta = _meta("CT-CONF-DOCKERFILE")

    if not path:
        if verbose:
            print("[DEBUG] CT-CONF-DOCKERFILE: Dockerfile path not provided")
        return CheckResult(
            id=meta["id"], name=meta["name"], layer=meta["layer"],
            severity=Severity[meta["severity"]], status=Status.WARN,
            details="Dockerfile path not provided; static container build checks skipped.",
        )

    try:
        scanner = DockerfileScanner(path, verbose=verbose)
        scanner.load()

        base = scanner.get_base_image() or "unknown"
        has_user = scanner.has_user_instruction()
        uses_latest = scanner.uses_latest_tag()
        has_healthcheck = scanner.has_healthcheck()

        if verbose:
            print(
                f"[DEBUG] CT-CONF-DOCKERFILE: base='{base}', "
                f"has_user={has_user}, uses_latest={uses_latest}, has_healthcheck={has_healthcheck}"
            )

        messages: list[str] = [f"Base image: {base}"]
        status = Status.PASS

        if not has_user:
            status = Status.WARN
            messages.append("No USER instruction found; container may run as root by default.")
        if uses_latest:
            if status == Status.PASS:
                status = Status.WARN
            messages.append("Base image uses 'latest' tag; pin a specific version for reproducibility.")
        if not has_healthcheck:
            if status == Status.PASS:
                status = Status.WARN
            messages.append("No HEALTHCHECK instruction; consider adding one for runtime monitoring.")

        details = " ".join(messages)

    except Exception as e:
        if verbose:
            print(f"[DEBUG] CT-CONF-DOCKERFILE: error {e}")
        status = Status.WARN
        details = f"Dockerfile parsing failed: {e}"

    return CheckResult(
        id=meta["id"], name=meta["name"], layer=meta["layer"],
        severity=Severity[meta["severity"]], status=status, details=details,
    )

        
           
def check_compose_resource_limits(path: Optional[str] = None, verbose: bool = False) -> CheckResult:
    """
    CONT-COMP-RES: docker-compose.yml defines resource limits for services.
    """
    meta = _meta("CONT-COMP-RES")
    
    if not path:
        if verbose:
            print(f"[DEBUG] CONT-COMP-RES: docker-compose.yml path not provided;")
        status = Status.WARN
        details = "docker-compose.yml path not provided; cannot statically verify limits."
        

    try:
        scanner = ComposeScanner(path, verbose)
        services = scanner.get_services()

        without_limits = []
        for name, svc in services.items():
            deploy = svc.get("deploy", {})
            resources = deploy.get("resources", {})
            limits = resources.get("limits", {})
            if not limits:
                without_limits.append(name)

        if verbose:
            print(f"[DEBUG] CONT-COMP-RES: services without limits={without_limits}")

        if without_limits:
            status = Status.WARN
            details = f"Services without CPU/memory limits in compose: {without_limits}. Set deploy.resources.limits."
        
        status = Status.PASS
        details = "All services in docker-compose.yml define resource limits."   
        
    except Exception as e:
        if verbose:
            print(f"[DEBUG] CONT-COMP-RES: exception {e!r}")
        status = Status.WARN
        details = f"Error parsing docker-compose.yml: {e}"
        
    return CheckResult(
        id=meta["id"], layer=meta["layer"], name=meta["name"],
        status=status, severity=Severity[meta["severity"]], details=details
    )
     

def check_compose_ports(path: Optional[str] = None, verbose: bool = False) -> CheckResult:
    meta = _meta("CT-CONF-COMPOSE-PORTS")

    if not path:
        if verbose:
            print("[DEBUG] CT-CONF-COMPOSE-PORTS: compose file not provided")
        status = Status.WARN
        details = "docker-compose.yml path not provided; compose checks skipped."
        

    try:
        scanner = ComposeScanner(path, verbose=verbose)
        scanner.load()
        services = scanner.get_services()

        open_ports: List[str] = []
        for svc_name, svc in services.items():
            ports = svc.get("ports", []) or []
            for p in ports:
                open_ports.append(f"{svc_name}: {p}")

        if verbose:
            print(f"[DEBUG] CT-CONF-COMPOSE-PORTS: open ports={open_ports}")

        if not open_ports:
            status = Status.PASS
            details = "No host-published ports defined in docker-compose.yml."
        else:
            status = Status.WARN
            details = "Host-published ports detected: " + ", ".join(open_ports)

    except Exception as e:
        if verbose:
            print(f"[DEBUG] CT-CONF-COMPOSE-PORTS: error {e}")
        status = Status.WARN
        details = f"docker-compose.yml parsing failed: {e}"

    return CheckResult(
        id=meta["id"], name=meta["name"], layer=meta["layer"],
        severity=Severity[meta["severity"]], status=status, details=details,
    )   
import os
import platform
import subprocess
from typing import Optional, Tuple

from backend.app.core.logging import logger
from backend.app.schemas.capture import CaptureEnvironmentData

IS_WINDOWS = platform.system().lower() == "windows"


def check_scapy_availability() -> Tuple[bool, Optional[str]]:
    """Verifies whether Scapy library is available in the current Python environment."""
    try:
        import scapy
        return True, getattr(scapy, "__version__", "unknown")
    except ImportError:
        return False, None


def check_npcap_installed() -> Tuple[bool, bool]:
    """Checks whether Npcap/WinPcap native DLLs and service exist on Windows.
    
    Returns:
        Tuple of (npcap_installed, service_running)
    """
    if not IS_WINDOWS:
        # On Linux/macOS, check if libpcap exists
        try:
            import ctypes.util
            libpcap_name = ctypes.util.find_library("pcap")
            return libpcap_name is not None, True
        except Exception:
            return False, False

    # Standard Windows paths for Npcap and WinPcap
    candidate_paths = [
        os.path.expandvars(r"%SystemRoot%\System32\Npcap\wpcap.dll"),
        os.path.expandvars(r"%SystemRoot%\System32\wpcap.dll"),
        os.path.expandvars(r"%SystemRoot%\SysWOW64\wpcap.dll"),
        os.path.expandvars(r"%SystemRoot%\System32\Npcap\Packet.dll"),
        os.path.expandvars(r"%SystemRoot%\System32\Packet.dll"),
    ]
    npcap_installed = any(os.path.exists(p) for p in candidate_paths)

    # Check Npcap kernel service status via sc query
    service_running = False
    try:
        proc = subprocess.run(
            ["sc", "query", "npcap"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=2.0,
        )
        if proc.returncode == 0 and "RUNNING" in proc.stdout.upper():
            service_running = True
            npcap_installed = True
    except Exception:
        pass

    # Verify if Scapy itself detected pcap support
    try:
        from scapy.all import conf
        if getattr(conf, "use_pcap", False):
            npcap_installed = True
            service_running = True
    except Exception:
        pass

    return npcap_installed, service_running


def evaluate_capture_environment() -> CaptureEnvironmentData:
    """Evaluates host system readiness for live packet sniffing."""
    scapy_ok, scapy_ver = check_scapy_availability()
    if not scapy_ok:
        return CaptureEnvironmentData(
            capability_status="SCAPY_MISSING",
            scapy_installed=False,
            scapy_version=None,
            npcap_installed=False,
            driver_service_running=False,
            can_capture=False,
            message="Scapy network library is not installed in the current Python environment.",
            remediation_guide="Run: python -m pip install scapy",
        )

    npcap_ok, service_running = check_npcap_installed()
    if IS_WINDOWS and not npcap_ok:
        return CaptureEnvironmentData(
            capability_status="NPCAP_MISSING",
            scapy_installed=True,
            scapy_version=scapy_ver,
            npcap_installed=False,
            driver_service_running=False,
            can_capture=False,
            message="Npcap packet capture library is not detected on Windows.",
            remediation_guide=(
                "Npcap is required for live packet capture on Windows.\n"
                "1. Download Npcap from https://npcap.com/#download\n"
                "2. Run the installer and check 'Install Npcap in WinPcap API-compatible Mode'.\n"
                "3. Restart the Ashlynx Network Inspector backend."
            ),
        )

    if IS_WINDOWS and npcap_ok and not service_running:
        return CaptureEnvironmentData(
            capability_status="PERMISSION_DENIED",
            scapy_installed=True,
            scapy_version=scapy_ver,
            npcap_installed=True,
            driver_service_running=False,
            can_capture=False,
            message="Npcap is installed, but the kernel driver service is stopped or requires administrator elevation.",
            remediation_guide="Start the Npcap service in an elevated PowerShell terminal: net start npcap",
        )

    return CaptureEnvironmentData(
        capability_status="CAPTURE_READY",
        scapy_installed=True,
        scapy_version=scapy_ver,
        npcap_installed=True,
        driver_service_running=True,
        can_capture=True,
        message="Live packet capture engine is ready and operational.",
        remediation_guide=None,
    )


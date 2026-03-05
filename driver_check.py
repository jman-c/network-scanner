import subprocess
import os
import sys

NPCAP_INSTALLER = os.path.join("drivers", "npcap-1.87.exe")


def npcap_installed():
    """
    Check if Npcap service exists
    """
    try:
        result = subprocess.run(
            ["sc", "query", "npcap"],
            capture_output=True,
            text=True
        )

        return "RUNNING" in result.stdout or "STOPPED" in result.stdout

    except Exception:
        return False


def install_npcap():
    """
    Launch bundled Npcap installer
    """
    if not os.path.exists(NPCAP_INSTALLER):
        print("Npcap installer missing.")
        return False

    print("Installing Npcap...")

    subprocess.run([
        NPCAP_INSTALLER,
        "/winpcap_mode=yes"
    ])

    return True
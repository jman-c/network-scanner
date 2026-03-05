from typing import Iterable, List, Dict, Optional
from scapy.all import ARP, Ether, srp  # type: ignore

def arp_sweep(cidr: str, timeout: int = 2, iface: Optional[str] = None) -> List[Dict[str, str]]:
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
    answered, _ = srp(pkt, timeout=timeout, iface=iface, verbose=False)

    results = []
    for _, recv in answered:
        if recv.psrc and recv.hwsrc:
            results.append({"ip": recv.psrc, "mac": recv.hwsrc.lower()})
    return results

def scan_many(cidrs: Iterable[str], iface: Optional[str] = None) -> List[Dict[str, str]]:
    seen = {}
    for c in cidrs:
        for row in arp_sweep(c, iface=iface):
            seen[row["mac"]] = row
    return list(seen.values())
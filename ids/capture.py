"""D'où viennent les paquets : vraie capture réseau (Scapy) ou mode démo.

Les deux sources tournent dans un fil d'exécution (thread) séparé et
déposent les paquets dans une file. L'interface graphique vient les
y chercher régulièrement, sans jamais se bloquer.
"""

import queue
import random
import threading
import time
from typing import Callable, List, Optional, Tuple

from .modeles import Paquet


class SourcePaquets(threading.Thread):
    """Base commune : un thread qui dépose des Paquet dans une file."""

    def __init__(self, file_sortie: "queue.Queue"):
        super().__init__(daemon=True)
        self.file_sortie = file_sortie
        self.arret = threading.Event()
        self.erreur: Optional[str] = None

    def arreter(self) -> None:
        self.arret.set()

    def _deposer(self, paquet: Paquet) -> None:
        try:
            self.file_sortie.put_nowait(paquet)
        except queue.Full:
            pass  # l'interface est en retard : on préfère perdre un paquet que tout bloquer


# --------------------------------------------------------------------------
# Mode démo
# --------------------------------------------------------------------------

RESEAU = "192.168.56."
PASSERELLE = RESEAU + "1"
MAC_PASSERELLE = "00:50:56:c0:00:01"
MAC_ATTAQUANT = "de:ad:be:ef:13:37"
POSTES = [RESEAU + str(i) for i in range(10, 21)]
SITES = ["203.0.113.10", "203.0.113.25", "198.51.100.7"]


class SourceDemo(SourcePaquets):
    """Simule le trafic d'un petit réseau, avec des attaques à intervalles réguliers.

    Toutes les adresses viennent de plages réservées aux exemples : aucun
    paquet n'est envoyé sur le réseau, tout reste dans le programme.
    """

    DEBIT_NORMAL = 35          # paquets par seconde de trafic ordinaire
    PREMIERE_ATTAQUE_S = 4
    INTERVALLE_ATTAQUES_S = 11

    def __init__(self, file_sortie: "queue.Queue", graine: Optional[int] = None):
        super().__init__(file_sortie)
        self.alea = random.Random(graine)
        self.scenarios: List[Callable[[float], List[Tuple[float, Paquet]]]] = [
            self._scenario_balayage,
            self._scenario_force_brute_ssh,
            self._scenario_flood_icmp,
            self._scenario_usurpation_arp,
            self._scenario_force_brute_rdp,
        ]

    def run(self) -> None:
        debut = time.time()
        prochaine_attaque = debut + self.PREMIERE_ATTAQUE_S
        numero = 0
        en_attente: List[Tuple[float, Paquet]] = []
        prochain_normal = debut

        while not self.arret.is_set():
            maintenant = time.time()

            if maintenant >= prochaine_attaque:
                scenario = self.scenarios[numero % len(self.scenarios)]
                en_attente.extend(scenario(maintenant))
                en_attente.sort(key=lambda x: x[0])
                numero += 1
                prochaine_attaque = maintenant + self.INTERVALLE_ATTAQUES_S

            while en_attente and en_attente[0][0] <= maintenant:
                self._deposer(en_attente.pop(0)[1])

            while prochain_normal <= maintenant:
                self._deposer(self._paquet_normal(prochain_normal))
                prochain_normal += self.alea.expovariate(self.DEBIT_NORMAL)

            time.sleep(0.02)

    # --- trafic ordinaire ---------------------------------------------------

    def _paquet_normal(self, t: float) -> Paquet:
        poste = self.alea.choice(POSTES)
        tirage = self.alea.random()
        if tirage < 0.70:   # navigation web chiffrée, connexion déjà ouverte
            site = self.alea.choice(SITES)
            if self.alea.random() < 0.5:
                return Paquet(t, "TCP", poste, site, self.alea.randint(49152, 65535), 443, "A",
                              taille=self.alea.randint(60, 1500))
            return Paquet(t, "TCP", site, poste, 443, self.alea.randint(49152, 65535), "PA",
                          taille=self.alea.randint(60, 1500))
        if tirage < 0.80:   # nouvelle connexion web
            return Paquet(t, "TCP", poste, self.alea.choice(SITES), self.alea.randint(49152, 65535), 443, "S", taille=66)
        if tirage < 0.95:   # résolution de noms
            return Paquet(t, "UDP", poste, PASSERELLE, self.alea.randint(49152, 65535), 53, taille=80)
        if tirage < 0.98:   # ping ordinaire
            return Paquet(t, "ICMP", poste, PASSERELLE, type_icmp=8, taille=74)
        # la passerelle annonce son adresse MAC, comme sur un vrai réseau
        return Paquet(t, "ARP", PASSERELLE, poste, operation_arp=2, mac_source=MAC_PASSERELLE, taille=42)

    # --- attaques -----------------------------------------------------------

    def _scenario_balayage(self, t0: float) -> List[Tuple[float, Paquet]]:
        attaquant, cible = RESEAU + "66", POSTES[0]
        ports = list(range(1, 1025))
        self.alea.shuffle(ports)
        return [(t0 + i * 0.025, Paquet(t0 + i * 0.025, "TCP", attaquant, cible, 40000 + i, p, "S", taille=60))
                for i, p in enumerate(ports[:120])]

    def _force_brute(self, t0: float, attaquant: str, cible: str, port: int) -> List[Tuple[float, Paquet]]:
        return [(t0 + i * 0.35, Paquet(t0 + i * 0.35, "TCP", attaquant, cible, 50000 + i, port, "S", taille=66))
                for i in range(18)]

    def _scenario_force_brute_ssh(self, t0: float):
        return self._force_brute(t0, RESEAU + "77", POSTES[0], 22)

    def _scenario_force_brute_rdp(self, t0: float):
        return self._force_brute(t0, "203.0.113.80", POSTES[2], 3389)

    def _scenario_flood_icmp(self, t0: float):
        return [(t0 + i * 0.008, Paquet(t0 + i * 0.008, "ICMP", "203.0.113.50", POSTES[1], type_icmp=8, taille=1042))
                for i in range(400)]

    def _scenario_usurpation_arp(self, t0: float):
        return [(t0 + i * 0.5, Paquet(t0 + i * 0.5, "ARP", PASSERELLE, POSTES[0], operation_arp=2,
                                      mac_source=MAC_ATTAQUANT, taille=42))
                for i in range(3)]


# --------------------------------------------------------------------------
# Capture réelle avec Scapy
# --------------------------------------------------------------------------

def scapy_disponible() -> Tuple[bool, str]:
    try:
        import scapy.all  # noqa: F401
        return True, ""
    except ImportError:
        return False, "La bibliothèque Scapy n'est pas installée. Tapez : pip install scapy"
    except Exception as e:  # ex. Npcap absent sous Windows
        return False, f"Scapy ne peut pas démarrer : {e}"


def lister_interfaces() -> List[Tuple[str, str]]:
    """Renvoie [(nom lisible, identifiant)] pour les cartes réseau de la machine."""
    try:
        from scapy.all import conf
        interfaces = []
        for iface in conf.ifaces.values():
            libelle = getattr(iface, "description", "") or iface.name
            ip = getattr(iface, "ip", "") or ""
            interfaces.append((f"{libelle} ({ip})" if ip else libelle, iface.name))
        return sorted(interfaces)
    except Exception:
        return []


def convertir_paquet_scapy(p) -> Optional[Paquet]:
    """Transforme un paquet Scapy en Paquet. Renvoie None s'il ne nous intéresse pas."""
    from scapy.all import ARP, ICMP, IP, TCP, UDP

    t = float(p.time)
    taille = len(p)
    if ARP in p:
        a = p[ARP]
        return Paquet(t, "ARP", a.psrc, a.pdst, operation_arp=int(a.op), mac_source=a.hwsrc, taille=taille)
    if IP not in p:
        return None
    ip = p[IP]
    if TCP in p:
        tcp = p[TCP]
        return Paquet(t, "TCP", ip.src, ip.dst, int(tcp.sport), int(tcp.dport), str(tcp.flags), taille=taille)
    if UDP in p:
        udp = p[UDP]
        return Paquet(t, "UDP", ip.src, ip.dst, int(udp.sport), int(udp.dport), taille=taille)
    if ICMP in p:
        return Paquet(t, "ICMP", ip.src, ip.dst, type_icmp=int(p[ICMP].type), taille=taille)
    return None


class SourceReelle(SourcePaquets):
    """Écoute le trafic de la carte réseau choisie.

    L'IDS observe seulement : il n'envoie ni ne bloque aucun paquet.
    Sous Windows, il faut Npcap (installé avec Wireshark) et lancer le
    programme en administrateur.
    """

    def __init__(self, file_sortie: "queue.Queue", interface: Optional[str] = None):
        super().__init__(file_sortie)
        self.interface = interface

    def run(self) -> None:
        try:
            from scapy.all import sniff
            filtre = "arp or ip"   # demandé à la carte réseau : ignore le reste
            while not self.arret.is_set():
                try:
                    sniff(iface=self.interface, prn=self._recevoir, store=False, timeout=1, filter=filtre)
                except Exception as e:
                    # Sans libpcap, Scapy ne sait pas appliquer le filtre : on trie nous-mêmes.
                    if filtre and ("filter" in str(e).lower() or "libpcap" in str(e).lower()):
                        filtre = None
                        continue
                    raise
        except PermissionError:
            self.erreur = ("Accès refusé à la carte réseau. Lancez le programme en administrateur "
                           "(Windows) ou avec sudo (Linux).")
        except Exception as e:
            self.erreur = f"La capture s'est arrêtée : {e}"

    def _recevoir(self, p) -> None:
        paquet = convertir_paquet_scapy(p)
        if paquet is not None:
            self._deposer(paquet)

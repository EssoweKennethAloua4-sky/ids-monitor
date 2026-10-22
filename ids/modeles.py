"""Les objets manipulés par l'IDS : un paquet résumé et une alerte."""

from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from typing import Optional


class Gravite(Enum):
    FAIBLE = 1
    MOYENNE = 2
    ELEVEE = 3
    CRITIQUE = 4

    @property
    def libelle(self) -> str:
        return {1: "Faible", 2: "Moyenne", 3: "Élevée", 4: "Critique"}[self.value]

    @classmethod
    def depuis_libelle(cls, texte: str) -> "Gravite":
        for g in cls:
            if g.libelle == texte:
                return g
        raise ValueError(texte)


@dataclass
class Paquet:
    """Résumé d'un paquet réseau : seulement ce dont les détecteurs ont besoin.

    Que le paquet vienne d'une vraie capture (Scapy) ou du mode démo,
    il est converti dans ce format unique.
    """
    horodatage: float
    protocole: str                  # "TCP", "UDP", "ICMP" ou "ARP"
    source: str                     # adresse IP source
    destination: str                # adresse IP destination
    port_source: Optional[int] = None
    port_destination: Optional[int] = None
    drapeaux_tcp: str = ""          # ex. "S" pour SYN, "SA" pour SYN-ACK
    type_icmp: Optional[int] = None # 8 = demande d'écho (ping)
    operation_arp: Optional[int] = None  # 1 = question, 2 = réponse
    mac_source: str = ""
    taille: int = 0

    @property
    def est_syn(self) -> bool:
        """Vrai pour une demande d'ouverture de connexion TCP (SYN sans ACK)."""
        return self.protocole == "TCP" and "S" in self.drapeaux_tcp and "A" not in self.drapeaux_tcp


@dataclass
class Alerte:
    type: str          # ex. "Balayage de ports"
    gravite: Gravite
    source: str
    cible: str
    detail: str
    horodatage: float = field(default_factory=lambda: datetime.now().timestamp())
    id: Optional[int] = None

    @property
    def heure(self) -> str:
        return datetime.fromtimestamp(self.horodatage).strftime("%H:%M:%S")

    @property
    def date_heure(self) -> str:
        return datetime.fromtimestamp(self.horodatage).strftime("%d/%m/%Y %H:%M:%S")

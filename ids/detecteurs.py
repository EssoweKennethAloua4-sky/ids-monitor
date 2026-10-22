"""Les règles de détection.

Chaque détecteur reçoit les paquets un par un (méthode `analyser`) et
renvoie une liste d'alertes, souvent vide. Tous partagent la même idée :
compter des événements récents par source et comparer à un seuil.
"""

from collections import defaultdict, deque
from typing import Dict, List, Tuple

from . import config
from .modeles import Alerte, Gravite, Paquet


class Detecteur:
    """Classe de base : gère l'anti-doublon commun à tous les détecteurs."""

    nom = "Détecteur"

    def __init__(self):
        self._derniere_alerte: Dict[Tuple, float] = {}

    def analyser(self, paquet: Paquet) -> List[Alerte]:
        raise NotImplementedError

    def _peut_alerter(self, cle: Tuple, maintenant: float) -> bool:
        """Évite de répéter la même alerte toutes les secondes."""
        derniere = self._derniere_alerte.get(cle)
        if derniere is not None and maintenant - derniere < config.DELAI_ENTRE_ALERTES_S:
            return False
        self._derniere_alerte[cle] = maintenant
        return True

    @staticmethod
    def _purger(file_evenements: deque, maintenant: float, fenetre: float) -> None:
        """Retire de la file les événements plus vieux que la fenêtre."""
        while file_evenements and maintenant - file_evenements[0][0] > fenetre:
            file_evenements.popleft()


class DetecteurBalayage(Detecteur):
    """Balayage de ports : une source qui essaie beaucoup de ports différents.

    C'est ce que fait un outil comme Nmap pour trouver les services ouverts.
    """

    nom = "Balayage de ports"

    def __init__(self):
        super().__init__()
        self._essais = defaultdict(deque)  # source -> [(heure, (cible, port)), ...]

    def analyser(self, paquet: Paquet) -> List[Alerte]:
        if paquet.port_destination is None:
            return []
        if paquet.protocole == "TCP" and not paquet.est_syn:
            return []
        if paquet.protocole not in ("TCP", "UDP"):
            return []

        t = paquet.horodatage
        file_src = self._essais[paquet.source]
        file_src.append((t, (paquet.destination, paquet.port_destination)))
        self._purger(file_src, t, config.BALAYAGE_FENETRE_S)

        ports = {port for _, (_, port) in file_src}
        if len(ports) < config.BALAYAGE_SEUIL_PORTS:
            return []
        if not self._peut_alerter((self.nom, paquet.source), t):
            return []

        cibles = sorted({cible for _, (cible, _) in file_src})
        gravite = Gravite.ELEVEE if len(ports) >= 3 * config.BALAYAGE_SEUIL_PORTS else Gravite.MOYENNE
        return [Alerte(
            type=self.nom,
            gravite=gravite,
            source=paquet.source,
            cible=", ".join(cibles[:3]) + (" …" if len(cibles) > 3 else ""),
            detail=f"{len(ports)} ports différents testés en moins de {config.BALAYAGE_FENETRE_S} s "
                   f"(ex. {', '.join(str(p) for p in sorted(ports)[:6])}…)",
            horodatage=t,
        )]


class DetecteurForceBrute(Detecteur):
    """Force brute : des tentatives de connexion répétées vers SSH, RDP, FTP ou Telnet.

    Un attaquant essaie des milliers de mots de passe ; chaque essai ouvre
    une nouvelle connexion, donc un nouveau paquet SYN vers le même port.
    """

    nom = "Force brute"

    def __init__(self):
        super().__init__()
        self._tentatives = defaultdict(deque)  # (source, cible, port) -> [(heure,), ...]

    def analyser(self, paquet: Paquet) -> List[Alerte]:
        if not paquet.est_syn or paquet.port_destination not in config.FORCE_BRUTE_PORTS:
            return []

        t = paquet.horodatage
        cle = (paquet.source, paquet.destination, paquet.port_destination)
        file_tent = self._tentatives[cle]
        file_tent.append((t,))
        self._purger(file_tent, t, config.FORCE_BRUTE_FENETRE_S)

        if len(file_tent) < config.FORCE_BRUTE_SEUIL:
            return []
        if not self._peut_alerter((self.nom,) + cle, t):
            return []

        service = config.FORCE_BRUTE_PORTS[paquet.port_destination]
        return [Alerte(
            type=f"{self.nom} {service}",
            gravite=Gravite.ELEVEE,
            source=paquet.source,
            cible=f"{paquet.destination}:{paquet.port_destination}",
            detail=f"{len(file_tent)} tentatives de connexion {service} en moins de "
                   f"{config.FORCE_BRUTE_FENETRE_S} s",
            horodatage=t,
        )]


class DetecteurFlood(Detecteur):
    """Inondation : une source qui envoie un volume anormal de pings ou de SYN.

    Le but est de saturer la cible pour la rendre indisponible (déni de service).
    """

    nom = "Inondation"

    def __init__(self):
        super().__init__()
        self._paquets = defaultdict(deque)  # (source, nature) -> [(heure,), ...]

    def analyser(self, paquet: Paquet) -> List[Alerte]:
        if paquet.protocole == "ICMP" and paquet.type_icmp == 8:
            nature = "ICMP (ping)"
        elif paquet.est_syn:
            nature = "SYN"
        else:
            return []

        t = paquet.horodatage
        cle = (paquet.source, nature)
        file_pq = self._paquets[cle]
        file_pq.append((t,))
        self._purger(file_pq, t, config.FLOOD_FENETRE_S)

        if len(file_pq) < config.FLOOD_SEUIL_PAQUETS:
            return []
        if not self._peut_alerter((self.nom,) + cle, t):
            return []

        duree = max(t - file_pq[0][0], 0.1)
        debit = len(file_pq) / duree
        return [Alerte(
            type=f"{self.nom} {nature}",
            gravite=Gravite.ELEVEE,
            source=paquet.source,
            cible=paquet.destination,
            detail=f"{len(file_pq)} paquets {nature} en {duree:.1f} s "
                   f"(environ {debit:.0f} par seconde)",
            horodatage=t,
        )]


class DetecteurUsurpationArp(Detecteur):
    """Usurpation ARP : une adresse IP qui change brusquement d'adresse MAC.

    Sur un réseau local, ARP associe chaque adresse IP à une carte réseau (MAC).
    Un attaquant peut annoncer « l'adresse du routeur, c'est moi » pour faire
    passer le trafic par sa machine : c'est l'attaque de l'homme du milieu.
    """

    nom = "Usurpation ARP"

    def __init__(self):
        super().__init__()
        self._table: Dict[str, str] = {}  # IP -> MAC vue en premier

    def analyser(self, paquet: Paquet) -> List[Alerte]:
        if paquet.protocole != "ARP" or paquet.operation_arp != 2 or not paquet.mac_source:
            return []

        ip, mac = paquet.source, paquet.mac_source.lower()
        connue = self._table.get(ip)
        if connue is None:
            self._table[ip] = mac
            return []
        if connue == mac:
            return []
        if not self._peut_alerter((self.nom, ip, mac), paquet.horodatage):
            return []

        return [Alerte(
            type=self.nom,
            gravite=Gravite.CRITIQUE,
            source=mac,
            cible=ip,
            detail=f"L'adresse {ip} appartenait à {connue}, elle est maintenant annoncée par {mac}. "
                   f"Possible attaque de l'homme du milieu.",
            horodatage=paquet.horodatage,
        )]


class MoteurDetection:
    """Fait passer chaque paquet dans tous les détecteurs."""

    def __init__(self):
        self.detecteurs = [
            DetecteurBalayage(),
            DetecteurForceBrute(),
            DetecteurFlood(),
            DetecteurUsurpationArp(),
        ]

    def analyser(self, paquet: Paquet) -> List[Alerte]:
        alertes: List[Alerte] = []
        for detecteur in self.detecteurs:
            alertes.extend(detecteur.analyser(paquet))
        return alertes

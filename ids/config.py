"""Seuils de détection.

Chaque règle compte des événements dans une « fenêtre glissante » :
on ne garde que ce qui s'est passé pendant les N dernières secondes.
Modifiez ces valeurs pour rendre l'IDS plus ou moins sensible.
"""

# Balayage de ports : une source qui touche beaucoup de ports différents.
BALAYAGE_FENETRE_S = 10        # durée observée, en secondes
BALAYAGE_SEUIL_PORTS = 15      # nombre de ports distincts qui déclenche l'alerte

# Force brute : beaucoup de tentatives de connexion vers un service d'accès à distance.
FORCE_BRUTE_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    3389: "RDP",
}
FORCE_BRUTE_FENETRE_S = 30
FORCE_BRUTE_SEUIL = 10         # tentatives de connexion dans la fenêtre

# Inondation (flood) : trop de paquets ICMP ou SYN venant d'une même source.
FLOOD_FENETRE_S = 5
FLOOD_SEUIL_PAQUETS = 150

# Délai minimal entre deux alertes identiques (même type, même source),
# pour ne pas noyer l'écran sous les doublons.
DELAI_ENTRE_ALERTES_S = 30

# Fichier de la base de données (créé automatiquement).
FICHIER_BASE = "ids_monitor.db"

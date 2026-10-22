"""Historique des alertes dans une base SQLite (un simple fichier)."""

import csv
import sqlite3
import threading
from typing import List, Optional

from .modeles import Alerte, Gravite


class BaseAlertes:
    def __init__(self, chemin: str):
        self.chemin = chemin
        self._verrou = threading.Lock()
        self._cnx = sqlite3.connect(chemin, check_same_thread=False)
        self._cnx.execute(
            """CREATE TABLE IF NOT EXISTS alertes (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   horodatage REAL NOT NULL,
                   type TEXT NOT NULL,
                   gravite INTEGER NOT NULL,
                   source TEXT NOT NULL,
                   cible TEXT NOT NULL,
                   detail TEXT NOT NULL
               )"""
        )
        self._cnx.execute("CREATE INDEX IF NOT EXISTS idx_alertes_heure ON alertes(horodatage)")
        self._cnx.commit()

    def enregistrer(self, alerte: Alerte) -> int:
        with self._verrou:
            cur = self._cnx.execute(
                "INSERT INTO alertes (horodatage, type, gravite, source, cible, detail) VALUES (?, ?, ?, ?, ?, ?)",
                (alerte.horodatage, alerte.type, alerte.gravite.value, alerte.source, alerte.cible, alerte.detail),
            )
            self._cnx.commit()
            alerte.id = cur.lastrowid
            return alerte.id

    def lister(self, type_alerte: Optional[str] = None, gravite_min: Optional[Gravite] = None,
               limite: int = 1000) -> List[Alerte]:
        requete = "SELECT id, horodatage, type, gravite, source, cible, detail FROM alertes WHERE 1=1"
        params: list = []
        if type_alerte:
            requete += " AND type LIKE ?"
            params.append(type_alerte + "%")
        if gravite_min:
            requete += " AND gravite >= ?"
            params.append(gravite_min.value)
        requete += " ORDER BY horodatage DESC LIMIT ?"
        params.append(limite)
        with self._verrou:
            lignes = self._cnx.execute(requete, params).fetchall()
        return [
            Alerte(id=i, horodatage=h, type=t, gravite=Gravite(g), source=s, cible=c, detail=d)
            for i, h, t, g, s, c, d in lignes
        ]

    def compter(self) -> int:
        with self._verrou:
            return self._cnx.execute("SELECT COUNT(*) FROM alertes").fetchone()[0]

    def exporter_csv(self, chemin: str, alertes: List[Alerte]) -> None:
        # utf-8-sig : Excel affiche correctement les accents.
        with open(chemin, "w", newline="", encoding="utf-8-sig") as f:
            ecrivain = csv.writer(f, delimiter=";")
            ecrivain.writerow(["Date", "Gravité", "Type", "Source", "Cible", "Détail"])
            for a in alertes:
                ecrivain.writerow([a.date_heure, a.gravite.libelle, a.type, a.source, a.cible, a.detail])

    def vider(self) -> None:
        with self._verrou:
            self._cnx.execute("DELETE FROM alertes")
            self._cnx.commit()

    def fermer(self) -> None:
        with self._verrou:
            self._cnx.close()

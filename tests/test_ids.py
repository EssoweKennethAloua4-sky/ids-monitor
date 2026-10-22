"""Tests des détecteurs et de la base. Lancer : python -m unittest"""

import os
import queue
import tempfile
import time
import unittest

from ids import config
from ids.capture import SourceDemo
from ids.detecteurs import (DetecteurBalayage, DetecteurFlood, DetecteurForceBrute,
                            DetecteurUsurpationArp, MoteurDetection)
from ids.modeles import Alerte, Gravite, Paquet
from ids.stockage import BaseAlertes


def syn(t, src, dst, dport):
    return Paquet(t, "TCP", src, dst, 50000, dport, "S")


class TestBalayage(unittest.TestCase):
    def test_alerte_au_seuil(self):
        d = DetecteurBalayage()
        alertes = []
        for i in range(config.BALAYAGE_SEUIL_PORTS):
            alertes += d.analyser(syn(100 + i * 0.1, "10.0.0.66", "10.0.0.10", 1000 + i))
        self.assertEqual(len(alertes), 1)
        self.assertEqual(alertes[0].type, "Balayage de ports")
        self.assertEqual(alertes[0].source, "10.0.0.66")

    def test_pas_d_alerte_sous_le_seuil(self):
        d = DetecteurBalayage()
        alertes = []
        for i in range(config.BALAYAGE_SEUIL_PORTS - 1):
            alertes += d.analyser(syn(100 + i, "10.0.0.66", "10.0.0.10", 1000 + i))
        self.assertEqual(alertes, [])

    def test_ports_trop_espaces_dans_le_temps(self):
        d = DetecteurBalayage()
        alertes = []
        for i in range(30):  # un port toutes les 2 s : jamais 15 ports dans 10 s
            alertes += d.analyser(syn(100 + i * 2, "10.0.0.66", "10.0.0.10", 1000 + i))
        self.assertEqual(alertes, [])

    def test_trafic_web_normal_ignore(self):
        d = DetecteurBalayage()
        alertes = []
        for i in range(100):  # beaucoup de connexions, mais toujours le port 443
            alertes += d.analyser(syn(100 + i * 0.01, "10.0.0.12", "203.0.113.10", 443))
        self.assertEqual(alertes, [])

    def test_pas_de_doublon(self):
        d = DetecteurBalayage()
        alertes = []
        for i in range(60):
            alertes += d.analyser(syn(100 + i * 0.05, "10.0.0.66", "10.0.0.10", 1000 + i))
        self.assertEqual(len(alertes), 1)


class TestForceBrute(unittest.TestCase):
    def test_ssh(self):
        d = DetecteurForceBrute()
        alertes = []
        for i in range(config.FORCE_BRUTE_SEUIL):
            alertes += d.analyser(syn(100 + i, "10.0.0.77", "10.0.0.10", 22))
        self.assertEqual(len(alertes), 1)
        self.assertEqual(alertes[0].type, "Force brute SSH")
        self.assertEqual(alertes[0].cible, "10.0.0.10:22")

    def test_port_non_surveille(self):
        d = DetecteurForceBrute()
        alertes = []
        for i in range(50):
            alertes += d.analyser(syn(100 + i, "10.0.0.77", "10.0.0.10", 8080))
        self.assertEqual(alertes, [])

    def test_ack_ignores(self):
        d = DetecteurForceBrute()
        alertes = []
        for i in range(50):  # paquets d'une session déjà ouverte : pas des tentatives
            alertes += d.analyser(Paquet(100 + i, "TCP", "10.0.0.77", "10.0.0.10", 50000, 22, "A"))
        self.assertEqual(alertes, [])


class TestFlood(unittest.TestCase):
    def test_flood_icmp(self):
        d = DetecteurFlood()
        alertes = []
        for i in range(config.FLOOD_SEUIL_PAQUETS):
            alertes += d.analyser(Paquet(100 + i * 0.01, "ICMP", "203.0.113.50", "10.0.0.11", type_icmp=8))
        self.assertEqual(len(alertes), 1)
        self.assertEqual(alertes[0].type, "Inondation ICMP (ping)")

    def test_pings_ordinaires(self):
        d = DetecteurFlood()
        alertes = []
        for i in range(300):  # un ping par seconde : normal
            alertes += d.analyser(Paquet(100 + i, "ICMP", "10.0.0.12", "10.0.0.1", type_icmp=8))
        self.assertEqual(alertes, [])


class TestArp(unittest.TestCase):
    def reponse(self, t, ip, mac):
        return Paquet(t, "ARP", ip, "10.0.0.10", operation_arp=2, mac_source=mac)

    def test_changement_de_mac(self):
        d = DetecteurUsurpationArp()
        self.assertEqual(d.analyser(self.reponse(1, "10.0.0.1", "00:50:56:c0:00:01")), [])
        self.assertEqual(d.analyser(self.reponse(2, "10.0.0.1", "00:50:56:C0:00:01")), [])  # même MAC
        alertes = d.analyser(self.reponse(3, "10.0.0.1", "de:ad:be:ef:13:37"))
        self.assertEqual(len(alertes), 1)
        self.assertEqual(alertes[0].gravite, Gravite.CRITIQUE)
        self.assertEqual(alertes[0].cible, "10.0.0.1")

    def test_questions_arp_ignorees(self):
        d = DetecteurUsurpationArp()
        d.analyser(self.reponse(1, "10.0.0.1", "00:50:56:c0:00:01"))
        q = Paquet(2, "ARP", "10.0.0.1", "10.0.0.10", operation_arp=1, mac_source="de:ad:be:ef:13:37")
        self.assertEqual(d.analyser(q), [])


class TestBase(unittest.TestCase):
    def setUp(self):
        self.dossier = tempfile.mkdtemp()
        self.base = BaseAlertes(os.path.join(self.dossier, "test.db"))

    def tearDown(self):
        self.base.fermer()

    def test_enregistrer_filtrer_exporter(self):
        self.base.enregistrer(Alerte("Balayage de ports", Gravite.MOYENNE, "a", "b", "x", horodatage=1))
        self.base.enregistrer(Alerte("Force brute SSH", Gravite.ELEVEE, "c", "d", "y", horodatage=2))
        self.assertEqual(self.base.compter(), 2)
        self.assertEqual([a.type for a in self.base.lister()], ["Force brute SSH", "Balayage de ports"])
        self.assertEqual(len(self.base.lister(type_alerte="Force brute")), 1)
        self.assertEqual(len(self.base.lister(gravite_min=Gravite.ELEVEE)), 1)
        chemin = os.path.join(self.dossier, "export.csv")
        self.base.exporter_csv(chemin, self.base.lister())
        with open(chemin, encoding="utf-8-sig") as f:
            self.assertEqual(len(f.read().strip().splitlines()), 3)
        self.base.vider()
        self.assertEqual(self.base.compter(), 0)


class TestDemo(unittest.TestCase):
    def test_chaque_attaque_de_la_demo_est_detectee(self):
        """Les scénarios de la démo doivent tous déclencher la bonne alerte."""
        demo = SourceDemo(queue.Queue(), graine=1)
        moteur = MoteurDetection()
        t = 1000.0
        # trafic normal d'abord, pour apprendre la vraie MAC de la passerelle
        for i in range(500):
            for a in moteur.analyser(demo._paquet_normal(t + i * 0.03)):
                self.fail(f"Fausse alerte sur du trafic normal : {a.type}")
        types = set()
        for k, scenario in enumerate(demo.scenarios):
            for _, paquet in scenario(t + 20 + k * 40):
                types.update(a.type for a in moteur.analyser(paquet))
        self.assertEqual(types, {"Balayage de ports", "Force brute SSH", "Inondation ICMP (ping)",
                                 "Usurpation ARP", "Force brute RDP"})


if __name__ == "__main__":
    unittest.main()

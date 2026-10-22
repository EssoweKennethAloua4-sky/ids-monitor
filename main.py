"""Lancement d'IDS Monitor.

    python main.py          ouvre la fenêtre
    python main.py --demo   ouvre la fenêtre et démarre directement le mode démo
"""

import argparse

from ids import config
from ids.interface import Application


def main() -> None:
    parser = argparse.ArgumentParser(description="IDS Monitor : détection d'intrusion réseau")
    parser.add_argument("--demo", action="store_true", help="démarrer directement en mode démo")
    parser.add_argument("--base", default=config.FICHIER_BASE, help="fichier de la base SQLite")
    args = parser.parse_args()
    Application(chemin_base=args.base, demarrer_demo=args.demo).mainloop()


if __name__ == "__main__":
    main()

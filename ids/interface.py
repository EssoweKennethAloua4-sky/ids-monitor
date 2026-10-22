"""Interface graphique Tkinter d'IDS Monitor."""

import math
import queue
import time
import tkinter as tk
from collections import Counter, deque
from tkinter import filedialog, messagebox, ttk
from typing import Optional

from . import __version__, config
from .capture import SourceDemo, SourcePaquets, SourceReelle, lister_interfaces, scapy_disponible
from .detecteurs import MoteurDetection
from .modeles import Alerte, Gravite
from .stockage import BaseAlertes

# --- Couleurs (mêmes tons que le portfolio) ---------------------------------
FOND = "#0A0E14"
PANNEAU = "#0F1520"
FILET = "#223047"
TEXTE = "#E6EAF0"
DISCRET = "#8693A8"
AMBRE = "#FFB224"
ROUGE = "#FF5A4E"
ORANGE = "#FF8A3D"
VERT = "#5BD69A"

COULEUR_GRAVITE = {
    Gravite.FAIBLE: DISCRET,
    Gravite.MOYENNE: AMBRE,
    Gravite.ELEVEE: ORANGE,
    Gravite.CRITIQUE: ROUGE,
}

FAMILLES = ["Balayage de ports", "Force brute", "Inondation", "Usurpation ARP"]

CONSEILS = {
    "Balayage de ports": "Une machine cherche les services ouverts. Vérifiez si cette adresse est connue. "
                         "Si ce n'est pas un audit prévu, bloquez-la sur le pare-feu et fermez les ports inutiles.",
    "Force brute": "Quelqu'un essaie de deviner un mot de passe. Bloquez l'adresse source, vérifiez les "
                   "journaux de connexion du serveur, imposez des mots de passe longs ou des clés SSH, "
                   "et limitez le nombre d'essais (par exemple avec fail2ban).",
    "Inondation": "Un volume anormal de paquets vise une machine pour la saturer. Limitez le débit "
                  "accepté depuis cette source sur le pare-feu ou le routeur.",
    "Usurpation ARP": "Une machine se fait passer pour une autre sur le réseau local, souvent la passerelle. "
                      "Repérez la carte réseau qui porte cette adresse MAC, isolez-la, et envisagez "
                      "des entrées ARP fixes ou l'inspection ARP sur le commutateur.",
}


def famille(type_alerte: str) -> str:
    for f in FAMILLES:
        if type_alerte.startswith(f):
            return f
    return type_alerte


class Application(tk.Tk):
    INTERVALLE_MS = 200        # fréquence de mise à jour de l'écran
    HISTORIQUE_GRAPHE_S = 60   # largeur du graphique, en secondes

    def __init__(self, chemin_base: str = config.FICHIER_BASE, demarrer_demo: bool = False):
        super().__init__()
        self.title(f"IDS Monitor {__version__} · Détection d'intrusion réseau")
        self.geometry("1180x780")
        self.minsize(980, 640)
        self.configure(bg=FOND)

        self.base = BaseAlertes(chemin_base)
        self.moteur = MoteurDetection()
        self.file_paquets: "queue.Queue" = queue.Queue(maxsize=50000)
        self.source: Optional[SourcePaquets] = None

        self.nb_paquets = 0
        self.nb_alertes = 0
        self.nb_graves = 0
        self.sources_suspectes = set()
        self.par_famille = Counter()
        self.debit = deque([0] * self.HISTORIQUE_GRAPHE_S, maxlen=self.HISTORIQUE_GRAPHE_S)
        self.seconde_courante = int(time.time())
        self.paquets_seconde = 0
        self.alertes_affichees = {}

        self._styles()
        self._construire()
        self.protocol("WM_DELETE_WINDOW", self.fermer)
        self.after(self.INTERVALLE_MS, self._boucle)
        if demarrer_demo:
            self.after(300, self.demarrer)

    # ------------------------------------------------------------------ style
    def _styles(self) -> None:
        self.police = ("Segoe UI", 10)
        self.police_titre = ("Segoe UI Semibold", 18)
        self.police_chiffre = ("Segoe UI Semibold", 22)
        self.police_mono = ("Consolas", 10)

        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure(".", background=FOND, foreground=TEXTE, fieldbackground=PANNEAU, font=self.police,
                    bordercolor=FILET, lightcolor=FILET, darkcolor=FILET)
        s.configure("TFrame", background=FOND)
        s.configure("Panneau.TFrame", background=PANNEAU)
        s.configure("TLabel", background=FOND, foreground=TEXTE)
        s.configure("Discret.TLabel", foreground=DISCRET)
        s.configure("Panneau.TLabel", background=PANNEAU)
        s.configure("TRadiobutton", background=FOND, foreground=TEXTE)
        s.map("TRadiobutton", background=[("active", FOND)], indicatorcolor=[("selected", AMBRE)])
        s.configure("TButton", background=PANNEAU, foreground=TEXTE, padding=(14, 6), borderwidth=1)
        s.map("TButton", background=[("active", FILET), ("disabled", FOND)], foreground=[("disabled", DISCRET)])
        s.configure("Principal.TButton", background=AMBRE, foreground=FOND, font=("Segoe UI Semibold", 10))
        s.map("Principal.TButton", background=[("active", "#ffc85a"), ("disabled", FILET)],
              foreground=[("disabled", DISCRET)])
        s.configure("TCombobox", fieldbackground=PANNEAU, background=PANNEAU, foreground=TEXTE, arrowcolor=TEXTE)
        s.map("TCombobox", fieldbackground=[("readonly", PANNEAU), ("disabled", FOND)],
              foreground=[("disabled", DISCRET)])
        s.configure("TNotebook", background=FOND, borderwidth=0)
        s.configure("TNotebook.Tab", background=FOND, foreground=DISCRET, padding=(16, 8))
        s.map("TNotebook.Tab", background=[("selected", PANNEAU)], foreground=[("selected", AMBRE)])
        s.configure("Treeview", background=PANNEAU, fieldbackground=PANNEAU, foreground=TEXTE, rowheight=26,
                    borderwidth=0)
        s.map("Treeview", background=[("selected", FILET)])
        s.configure("Treeview.Heading", background=FOND, foreground=DISCRET, relief="flat",
                    font=("Segoe UI Semibold", 9))
        s.map("Treeview.Heading", background=[("active", FOND)])
        self.option_add("*TCombobox*Listbox.background", PANNEAU)
        self.option_add("*TCombobox*Listbox.foreground", TEXTE)

    # ------------------------------------------------------------ construction
    def _construire(self) -> None:
        racine = ttk.Frame(self, padding=(18, 14))
        racine.pack(fill="both", expand=True)
        racine.columnconfigure(0, weight=1)
        racine.rowconfigure(3, weight=1)

        # En-tête
        tete = ttk.Frame(racine)
        tete.grid(row=0, column=0, sticky="ew")
        tete.columnconfigure(1, weight=1)
        titre = ttk.Frame(tete)
        titre.grid(row=0, column=0, sticky="w")
        tk.Label(titre, text="IDS MONITOR", font=self.police_titre, fg=AMBRE, bg=FOND).pack(anchor="w")
        ttk.Label(titre, text="Détection d'intrusion réseau · observation seule, rien n'est bloqué",
                  style="Discret.TLabel").pack(anchor="w")

        cmd = ttk.Frame(tete)
        cmd.grid(row=0, column=2, sticky="e")
        self.mode = tk.StringVar(value="demo")
        ttk.Radiobutton(cmd, text="Démo", value="demo", variable=self.mode,
                        command=self._changer_mode).grid(row=0, column=0, padx=(0, 8))
        ttk.Radiobutton(cmd, text="Trafic réel", value="reel", variable=self.mode,
                        command=self._changer_mode).grid(row=0, column=1, padx=(0, 10))
        self.interfaces = []
        self.choix_interface = ttk.Combobox(cmd, state="disabled", width=24)
        self.choix_interface.grid(row=0, column=2, padx=(0, 12))
        self.bouton_demarrer = ttk.Button(cmd, text="Démarrer", style="Principal.TButton", command=self.demarrer)
        self.bouton_demarrer.grid(row=0, column=3, padx=(0, 6))
        self.bouton_arreter = ttk.Button(cmd, text="Arrêter", command=self.arreter, state="disabled")
        self.bouton_arreter.grid(row=0, column=4)

        # Bandeau d'état
        etat = tk.Frame(racine, bg=PANNEAU, highlightthickness=1, highlightbackground=FILET)
        etat.grid(row=1, column=0, sticky="ew", pady=(14, 12))
        self.voyant = tk.Label(etat, text="●", fg=DISCRET, bg=PANNEAU, font=("Segoe UI", 14))
        self.voyant.pack(side="left", padx=(12, 6), pady=6)
        self.texte_etat = tk.Label(etat, text="Arrêté. Choisissez un mode puis cliquez sur Démarrer.",
                                   fg=TEXTE, bg=PANNEAU, font=self.police)
        self.texte_etat.pack(side="left")
        self.texte_derniere = tk.Label(etat, text="", fg=DISCRET, bg=PANNEAU, font=self.police)
        self.texte_derniere.pack(side="right", padx=12)

        # Compteurs + graphiques
        milieu = ttk.Frame(racine)
        milieu.grid(row=2, column=0, sticky="ew")
        milieu.columnconfigure(0, weight=3)
        milieu.columnconfigure(1, weight=2)

        compteurs = ttk.Frame(milieu)
        compteurs.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 12))
        self.valeurs = {}
        for i, (cle, libelle) in enumerate([
            ("paquets", "Paquets analysés"), ("debit", "Paquets / seconde"),
            ("alertes", "Alertes"), ("graves", "Élevées ou critiques"), ("sources", "Sources suspectes"),
        ]):
            compteurs.columnconfigure(i, weight=1, uniform="c")
            carte = tk.Frame(compteurs, bg=PANNEAU, highlightthickness=1, highlightbackground=FILET)
            carte.grid(row=0, column=i, sticky="ew", padx=(0 if i == 0 else 10, 0))
            tk.Label(carte, text=libelle.upper(), fg=DISCRET, bg=PANNEAU, font=("Segoe UI", 8)).pack(
                anchor="w", padx=12, pady=(10, 0))
            v = tk.Label(carte, text="0", fg=AMBRE if cle == "graves" else TEXTE, bg=PANNEAU,
                         font=self.police_chiffre)
            v.pack(anchor="w", padx=12, pady=(0, 8))
            self.valeurs[cle] = v

        cadre_graphe = tk.Frame(milieu, bg=PANNEAU, highlightthickness=1, highlightbackground=FILET)
        cadre_graphe.grid(row=1, column=0, sticky="nsew", padx=(0, 10))
        tk.Label(cadre_graphe, text="Trafic des 60 dernières secondes (paquets par seconde)", fg=DISCRET,
                 bg=PANNEAU, font=("Segoe UI", 9)).pack(anchor="w", padx=12, pady=(8, 0))
        self.graphe = tk.Canvas(cadre_graphe, height=150, bg=PANNEAU, highlightthickness=0)
        self.graphe.pack(fill="both", expand=True, padx=8, pady=(4, 8))

        cadre_types = tk.Frame(milieu, bg=PANNEAU, highlightthickness=1, highlightbackground=FILET)
        cadre_types.grid(row=1, column=1, sticky="nsew")
        tk.Label(cadre_types, text="Alertes par type", fg=DISCRET, bg=PANNEAU,
                 font=("Segoe UI", 9)).pack(anchor="w", padx=12, pady=(8, 0))
        self.barres = tk.Canvas(cadre_types, height=150, bg=PANNEAU, highlightthickness=0)
        self.barres.pack(fill="both", expand=True, padx=8, pady=(4, 8))

        # Onglets
        onglets = ttk.Notebook(racine)
        onglets.grid(row=3, column=0, sticky="nsew", pady=(14, 0))
        self.onglets = onglets
        onglets.add(self._onglet_direct(onglets), text="Alertes en direct")
        onglets.add(self._onglet_historique(onglets), text="Historique")
        onglets.bind("<<NotebookTabChanged>>", lambda e: self._charger_historique()
                     if onglets.index("current") == 1 else None)

        pied = ttk.Frame(racine)
        pied.grid(row=4, column=0, sticky="ew", pady=(8, 0))
        ttk.Label(pied, text=f"Base de données : {self.base.chemin}", style="Discret.TLabel").pack(side="left")
        ttk.Label(pied, text="Essowe Kenneth Aloua", style="Discret.TLabel").pack(side="right")

    def _tableau(self, parent) -> ttk.Treeview:
        colonnes = ("heure", "gravite", "type", "source", "cible", "detail")
        tableau = ttk.Treeview(parent, columns=colonnes, show="headings", selectmode="browse")
        for col, titre, largeur, etire in [
            ("heure", "Date", 152, False), ("gravite", "Gravité", 80, False), ("type", "Type", 170, False),
            ("source", "Source", 140, False), ("cible", "Cible", 150, False), ("detail", "Détail", 400, True),
        ]:
            tableau.heading(col, text=titre, anchor="w")
            tableau.column(col, width=largeur, stretch=etire, anchor="w")
        for g, couleur in COULEUR_GRAVITE.items():
            tableau.tag_configure(g.name, foreground=couleur)
        return tableau

    def _onglet_direct(self, parent) -> ttk.Frame:
        cadre = ttk.Frame(parent, style="Panneau.TFrame", padding=10)
        cadre.columnconfigure(0, weight=1)
        cadre.rowconfigure(0, weight=1)
        self.tableau_direct = self._tableau(cadre)
        self.tableau_direct.grid(row=0, column=0, sticky="nsew")
        defil = ttk.Scrollbar(cadre, orient="vertical", command=self.tableau_direct.yview)
        defil.grid(row=0, column=1, sticky="ns")
        self.tableau_direct.configure(yscrollcommand=defil.set)
        self.tableau_direct.bind("<<TreeviewSelect>>", lambda e: self._afficher_detail(self.tableau_direct))

        self.zone_detail = tk.Text(cadre, height=4, bg=FOND, fg=TEXTE, relief="flat", wrap="word",
                                   font=self.police, padx=10, pady=8, highlightthickness=1,
                                   highlightbackground=FILET)
        self.zone_detail.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        self.zone_detail.tag_configure("titre", foreground=AMBRE, font=("Segoe UI Semibold", 10))
        self._ecrire_detail("Sélectionnez une alerte pour voir son explication et que faire.", "")
        return cadre

    def _onglet_historique(self, parent) -> ttk.Frame:
        cadre = ttk.Frame(parent, style="Panneau.TFrame", padding=10)
        cadre.columnconfigure(0, weight=1)
        cadre.rowconfigure(1, weight=1)

        filtres = ttk.Frame(cadre, style="Panneau.TFrame")
        filtres.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        ttk.Label(filtres, text="Type", style="Panneau.TLabel").pack(side="left", padx=(0, 6))
        self.filtre_type = ttk.Combobox(filtres, state="readonly", width=20, values=["Tous"] + FAMILLES)
        self.filtre_type.current(0)
        self.filtre_type.pack(side="left", padx=(0, 16))
        ttk.Label(filtres, text="Gravité minimale", style="Panneau.TLabel").pack(side="left", padx=(0, 6))
        self.filtre_gravite = ttk.Combobox(filtres, state="readonly", width=12,
                                           values=["Toutes"] + [g.libelle for g in Gravite])
        self.filtre_gravite.current(0)
        self.filtre_gravite.pack(side="left", padx=(0, 16))
        for w in (self.filtre_type, self.filtre_gravite):
            w.bind("<<ComboboxSelected>>", lambda e: self._charger_historique())
        ttk.Button(filtres, text="Vider l'historique", command=self._vider).pack(side="right")
        ttk.Button(filtres, text="Exporter en CSV", command=self._exporter).pack(side="right", padx=6)
        self.compte_historique = ttk.Label(filtres, text="", style="Panneau.TLabel")
        self.compte_historique.pack(side="right", padx=12)

        self.tableau_historique = self._tableau(cadre)
        self.tableau_historique.grid(row=1, column=0, sticky="nsew")
        defil = ttk.Scrollbar(cadre, orient="vertical", command=self.tableau_historique.yview)
        defil.grid(row=1, column=1, sticky="ns")
        self.tableau_historique.configure(yscrollcommand=defil.set)
        return cadre

    # ------------------------------------------------------------- commandes
    def _changer_mode(self) -> None:
        if self.mode.get() == "reel":
            ok, message = scapy_disponible()
            if not ok:
                messagebox.showwarning("Trafic réel indisponible", message + "\n\nLe mode démo reste disponible.")
                self.mode.set("demo")
                return
            self.interfaces = lister_interfaces()
            self.choix_interface.configure(values=[nom for nom, _ in self.interfaces], state="readonly")
            if self.interfaces:
                self.choix_interface.current(0)
        else:
            self.choix_interface.configure(state="disabled")

    def demarrer(self) -> None:
        if self.source is not None:
            return
        if self.mode.get() == "reel":
            index = self.choix_interface.current()
            iface = self.interfaces[index][1] if 0 <= index < len(self.interfaces) else None
            self.source = SourceReelle(self.file_paquets, iface)
            libelle = f"Surveillance du trafic réel ({self.choix_interface.get() or 'interface par défaut'})"
        else:
            self.source = SourceDemo(self.file_paquets)
            libelle = "Surveillance en cours · mode démo (trafic simulé, attaques toutes les 11 s)"
        self.source.start()
        self.voyant.configure(fg=VERT)
        self.texte_etat.configure(text=libelle)
        self.bouton_demarrer.configure(state="disabled")
        self.bouton_arreter.configure(state="normal")

    def arreter(self, message: str = "Arrêté.") -> None:
        if self.source is not None:
            self.source.arreter()
            self.source = None
        self.voyant.configure(fg=DISCRET)
        self.texte_etat.configure(text=message)
        self.bouton_demarrer.configure(state="normal")
        self.bouton_arreter.configure(state="disabled")

    def fermer(self) -> None:
        self.arreter()
        self.base.fermer()
        self.destroy()

    # ------------------------------------------------------- boucle principale
    def _boucle(self) -> None:
        traites = 0
        try:
            while traites < 5000:
                paquet = self.file_paquets.get_nowait()
                traites += 1
                self.nb_paquets += 1
                for alerte in self.moteur.analyser(paquet):
                    self._nouvelle_alerte(alerte)
        except queue.Empty:
            pass

        maintenant = int(time.time())
        self.paquets_seconde += traites
        if maintenant != self.seconde_courante:
            for _ in range(min(maintenant - self.seconde_courante, self.HISTORIQUE_GRAPHE_S)):
                self.debit.append(self.paquets_seconde)
                self.paquets_seconde = 0
            self.seconde_courante = maintenant
            self._dessiner_graphe()

        if self.source is not None and self.source.erreur:
            erreur = self.source.erreur
            self.arreter("Capture interrompue.")
            messagebox.showerror("Capture impossible", erreur)

        self.valeurs["paquets"].configure(text=f"{self.nb_paquets:,}".replace(",", " "))
        self.valeurs["debit"].configure(text=str(self.debit[-1]))
        self.valeurs["alertes"].configure(text=str(self.nb_alertes))
        self.valeurs["graves"].configure(text=str(self.nb_graves))
        self.valeurs["sources"].configure(text=str(len(self.sources_suspectes)))
        self.after(self.INTERVALLE_MS, self._boucle)

    def _nouvelle_alerte(self, alerte: Alerte) -> None:
        self.base.enregistrer(alerte)
        self.nb_alertes += 1
        if alerte.gravite.value >= Gravite.ELEVEE.value:
            self.nb_graves += 1
        self.sources_suspectes.add(alerte.source)
        self.par_famille[famille(alerte.type)] += 1

        iid = self.tableau_direct.insert("", 0, values=self._ligne(alerte), tags=(alerte.gravite.name,))
        self.alertes_affichees[iid] = alerte
        enfants = self.tableau_direct.get_children()
        for vieux in enfants[500:]:
            self.tableau_direct.delete(vieux)
            self.alertes_affichees.pop(vieux, None)

        self.voyant.configure(fg=COULEUR_GRAVITE[alerte.gravite])
        self.texte_derniere.configure(text=f"Dernière alerte {alerte.heure} · {alerte.type} · {alerte.source}",
                                      fg=COULEUR_GRAVITE[alerte.gravite])
        self.after(1500, lambda: self.voyant.configure(fg=VERT) if self.source else None)
        self._dessiner_barres()

    @staticmethod
    def _ligne(a: Alerte):
        return (a.date_heure, a.gravite.libelle, a.type, a.source, a.cible, a.detail)

    # -------------------------------------------------------------- dessins
    def _dessiner_graphe(self) -> None:
        c = self.graphe
        c.delete("all")
        l, h = max(c.winfo_width(), 200), max(c.winfo_height(), 100)
        marge_g, marge_b, marge_h = 36, 18, 8
        valeurs = list(self.debit)
        brut = max(max(valeurs), 10) / 4
        base = 10 ** math.floor(math.log10(brut))
        pas = next(m * base for m in (1, 2, 2.5, 5, 10) if m * base >= brut)
        maxi = pas * 4
        lx = (l - marge_g - 8) / (len(valeurs) - 1)
        hy = (h - marge_b - marge_h) / maxi
        for k in range(5):
            y = h - marge_b - k * pas * hy
            c.create_line(marge_g, y, l - 8, y, fill=FILET)
            c.create_text(marge_g - 6, y, text=str(int(k * pas)), fill=DISCRET, anchor="e", font=("Segoe UI", 8))
        c.create_text(marge_g, h - 4, text="−60 s", fill=DISCRET, anchor="w", font=("Segoe UI", 8))
        c.create_text(l - 8, h - 4, text="maintenant", fill=DISCRET, anchor="e", font=("Segoe UI", 8))
        points = []
        for i, v in enumerate(valeurs):
            points += [marge_g + i * lx, h - marge_b - v * hy]
        c.create_polygon([marge_g, h - marge_b] + points + [l - 8, h - marge_b], fill="#2a2416", outline="")
        c.create_line(points, fill=AMBRE, width=2, smooth=True)
        c.create_oval(points[-2] - 3, points[-1] - 3, points[-2] + 3, points[-1] + 3, fill=AMBRE, outline="")

    def _dessiner_barres(self) -> None:
        c = self.barres
        c.delete("all")
        l = max(c.winfo_width(), 200)
        maxi = max(self.par_famille.values(), default=0) or 1
        largeur_libelle = 128
        for i, f in enumerate(FAMILLES):
            y = 16 + i * 32
            n = self.par_famille.get(f, 0)
            c.create_text(4, y, text=f, fill=TEXTE, anchor="w", font=("Segoe UI", 9))
            fond_x1 = l - 36
            c.create_rectangle(largeur_libelle, y - 6, fond_x1, y + 6, fill=FOND, outline="")
            if n:
                c.create_rectangle(largeur_libelle, y - 6,
                                   largeur_libelle + (fond_x1 - largeur_libelle) * n / maxi, y + 6,
                                   fill=ROUGE if f == "Usurpation ARP" else ORANGE, outline="")
            c.create_text(l - 4, y, text=str(n), fill=TEXTE, anchor="e", font=("Segoe UI Semibold", 9))

    # ----------------------------------------------------------- détails
    def _ecrire_detail(self, titre: str, texte: str) -> None:
        self.zone_detail.configure(state="normal")
        self.zone_detail.delete("1.0", "end")
        self.zone_detail.insert("end", titre + "\n", "titre")
        self.zone_detail.insert("end", texte)
        self.zone_detail.configure(state="disabled")

    def _afficher_detail(self, tableau: ttk.Treeview) -> None:
        sel = tableau.selection()
        if not sel:
            return
        a = self.alertes_affichees.get(sel[0])
        if a is None:
            return
        conseil = CONSEILS.get(famille(a.type), "")
        self._ecrire_detail(f"{a.type} · gravité {a.gravite.libelle.lower()} · {a.date_heure}",
                            f"{a.detail}\nQue faire ? {conseil}")

    # -------------------------------------------------------- historique
    def _alertes_filtrees(self):
        t = self.filtre_type.get()
        g = self.filtre_gravite.get()
        return self.base.lister(
            type_alerte=None if t == "Tous" else t,
            gravite_min=None if g == "Toutes" else Gravite.depuis_libelle(g),
        )

    def _charger_historique(self) -> None:
        tab = self.tableau_historique
        tab.delete(*tab.get_children())
        alertes = self._alertes_filtrees()
        for a in alertes:
            tab.insert("", "end", values=self._ligne(a), tags=(a.gravite.name,))
        self.compte_historique.configure(text=f"{len(alertes)} alerte(s) · {self.base.compter()} au total")

    def _exporter(self) -> None:
        chemin = filedialog.asksaveasfilename(
            title="Exporter l'historique", defaultextension=".csv",
            initialfile=f"alertes_{time.strftime('%Y-%m-%d')}.csv", filetypes=[("Fichier CSV", "*.csv")])
        if not chemin:
            return
        alertes = self._alertes_filtrees()
        self.base.exporter_csv(chemin, alertes)
        messagebox.showinfo("Export terminé", f"{len(alertes)} alerte(s) enregistrée(s) dans :\n{chemin}")

    def _vider(self) -> None:
        if messagebox.askyesno("Vider l'historique",
                               "Supprimer définitivement toutes les alertes enregistrées ?"):
            self.base.vider()
            self._charger_historique()

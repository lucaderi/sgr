
""" Modulo per la generazione e gestione dei grafici (Factory Method) """

from __future__ import annotations

import abc
from typing import Dict, Any, List, Tuple
import tkinter as tk

from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

from gui_utils import COLORS

CHART_PALETTE = [
    COLORS["accent"],       # Viola/Indaco (#7c5cff)
    COLORS["success"],      # Verde acqua (#41d7a7)
    "#ffb84d",              # Ambra/Arancio
    COLORS["danger"],       # Rosso/Corallo (#ff7d8f)
    "#38bdf8",              # Celeste cielo
    "#c084fc",              # Lilla
    "#fb7185",              # Rosa magenta
    COLORS["muted"]         # Grigio ardesia
]

# Product --> classe astratta del grafico
class BaseChart(abc.ABC):

    def __init__(self, figsize=(12, 4.5)):
        self.fig = Figure(figsize=figsize, facecolor=COLORS["panel"])
        self.canvas: FigureCanvasTkAgg | None = None

    def embed_in(self, container: tk.Widget) -> FigureCanvasTkAgg:
        self.canvas = FigureCanvasTkAgg(self.fig, master=container) # ponte tra Matplotlib e Tkinter
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(fill="both", expand=True, padx=12, pady=12) # posiziono il vero widget Tkinter che contiene il canvas
        return self.canvas

    def clear(self):
        self.fig.clf()

    def redraw(self):
        if self.canvas:
            self.canvas.draw()

    @abc.abstractmethod
    def draw(self, *args, **kwargs):
        """ Metodo di disegno specifico per ciascun tipo di grafico """
        pass

# Concrete Products --> una per ogni tipo specifico di grafico
class BarChart(BaseChart):

    def draw(self, categories, values, title, color: Any = COLORS["accent"], x_rotation: int = 0):
        self.clear()
        ax = self.fig.add_subplot(111)
        ax.set_facecolor(COLORS["panel_alt"])

        ax.tick_params(colors=COLORS["muted"], labelsize=9)
        for spine in ax.spines.values():
            spine.set_color(COLORS["border"])

        ax.bar(categories, values, color=color)
        ax.set_title(title, color=COLORS["text"], fontsize=12, pad=10)

        if x_rotation:
            self.fig.autofmt_xdate(rotation=x_rotation)

        self.fig.tight_layout()
        self.redraw()

class HorizontalBarChart(BaseChart):

    def draw(self, categories, values, title, color=COLORS["accent"], x_rotation=0):
        self.clear()
        ax = self.fig.add_subplot(111)
        ax.set_facecolor(COLORS["panel_alt"])

        ax.tick_params(colors=COLORS["muted"], labelsize=9)
        for spine in ax.spines.values():
            spine.set_color(COLORS["border"])

        ax.barh(categories, values, color=color)
        ax.set_xscale("log")
        ax.set_title(title, color=COLORS["text"], fontsize=12, pad=10)

        if x_rotation:
            self.fig.autofmt_xdate(rotation=x_rotation)

        self.fig.tight_layout()
        self.redraw()

class MultiPieChart(BaseChart):

    palette = ["blue", "orange", "green", "red", "purple", "brown", "gray", "pink"]

    def draw(self, app_data, cat_data, breed_data):
        self.clear()

        ax1 = self.fig.add_subplot(131)
        ax2 = self.fig.add_subplot(132)
        ax3 = self.fig.add_subplot(133)

        self._draw_pie_panel(ax1, app_data, "Applicazioni - % Byte")
        self._draw_pie_panel(ax2, cat_data, "Categorie - % Byte")
        self._draw_pie_panel(ax3, breed_data, "Breeds - % Byte")

        # Margini per non tagliare le legende sotto
        self.fig.subplots_adjust(left=0.03, right=0.97, top=0.88, bottom=0.22, wspace=0.28)
        self.redraw()

    def _draw_pie_panel(self, ax, data, title):
        ax.set_facecolor(COLORS["panel_alt"])

        if not data:
            ax.text(0.5, 0.5, "Nessun dato", color=COLORS["muted"], ha="center", va="center", fontsize=11)
            ax.set_title(title, color=COLORS["text"], fontsize=10, fontweight="bold", pad=8)
            ax.axis("off")
            return

        sorted_items = sorted(data.items(), key=lambda x: x[1], reverse=True) # per frequenza decrescente
        max_slices = 5
        if len(sorted_items) > max_slices:
            top_items = sorted_items[:max_slices]
            freq_app_sum = sum(freq for _, freq in sorted_items[max_slices:])
            if freq_app_sum > 0:
                top_items.append(("Altro", freq_app_sum))
            labels = [key for key, _ in top_items]
            values = [val for _, val in top_items]
        else:
            labels = [key for key, _ in sorted_items]
            values = [val for _, val in sorted_items]

        wedges, _, autotext = ax.pie(
            values,
            colors=self.palette[:len(values)],
            autopct=lambda pct: f"{pct:.0f}%" if pct >= 6 else "",
            pctdistance=0.75,
            startangle=120,
            wedgeprops={"edgecolor": COLORS["panel"], "linewidth": 1.2}
        )

        for at in autotext:
            at.set_color("white")
            at.set_fontsize(8)
            at.set_fontweight("bold")

        ax.set_title(title, color=COLORS["text"], fontsize=9, fontweight="bold", pad=8)
        ax.legend(
            wedges,
            labels,
            loc="upper center",
            bbox_to_anchor=(0.5, 0.02),
            frameon=False,
            fontsize=8,
            labelcolor=COLORS["muted"],
            handlelength=1,
            handletextpad=0.5
        )

    def show_placeholder(self, message):
        self.clear()
        ax = self.fig.add_subplot(111)
        ax.set_facecolor(COLORS["panel_alt"])
        ax.text(0.5, 0.5, message, color=COLORS["muted"], ha="center", va="center", fontsize=11)
        ax.axis("off")
        self.redraw()

class OverviewDualChart(BaseChart):

    def draw(self, app_data, proto_data, title_left, title_right):
        self.clear()

        ax1 = self.fig.add_subplot(121)
        ax1.set_facecolor(COLORS["panel_alt"])
        ax1.tick_params(colors=COLORS["muted"], labelsize=8)
        for spine in ax1.spines.values():
            spine.set_color(COLORS["border"])

        categories = [app for app, _ in app_data]
        values_mb = [val for _, val in app_data]
        ax1.bar(categories, values_mb, color=COLORS["accent"])
        ax1.set_title(title_left, color=COLORS["text"], fontsize=10, pad=8)
        ax1.tick_params(axis='x', rotation=20)

        ax2 = self.fig.add_subplot(122)
        ax2.set_facecolor(COLORS["panel_alt"])
        for spine in ax2.spines.values():
            spine.set_color(COLORS["border"])

        if proto_data:
            labels = list(proto_data.keys())
            values = list(proto_data.values())
            wedges, _, autotext = ax2.pie(
                values,
                colors=CHART_PALETTE[:len(values)],
                autopct=lambda pct: f"{pct:.1f}%" if pct >= 3 else "",
                pctdistance=0.7,
                startangle=90,
                wedgeprops={"edgecolor": COLORS["panel"], "linewidth": 1.2}
            )
            for at in autotext:
                at.set_color("white")
                at.set_fontsize(8)
                at.set_fontweight("bold")

            ax2.legend(
                wedges, labels,
                loc="upper center", bbox_to_anchor=(0.5, -0.05),
                frameon=False, fontsize=8, labelcolor=COLORS["muted"]
            )
        else:
            ax2.text(0.5, 0.5, "Nessun protocollo", color=COLORS["muted"], ha="center", va="center", fontsize=10)
            ax2.axis("off")

        ax2.set_title(title_right, color=COLORS["text"], fontsize=10, pad=8)

        self.fig.subplots_adjust(left=0.08, right=0.95, top=0.88, bottom=0.22, wspace=0.3)
        self.redraw()


# Factory Method --> creazione delle istanze dei grafici
class ChartFactory:

    _PRODUCTS = {
        "bar": BarChart,
        "horizontal_bar": HorizontalBarChart,
        "multi_pie": MultiPieChart,
        "overview_dual": OverviewDualChart
    }

    @classmethod
    def create_chart(cls, chart_type: str, figsize=(12, 4.5)) -> BaseChart:
        creator = cls._PRODUCTS.get(chart_type)
        if not creator:
            raise ValueError(f"Tipo di grafico sconosciuto: '{chart_type}'. Tipi validi: {list(cls._PRODUCTS.keys())}")
        return creator(figsize=figsize)
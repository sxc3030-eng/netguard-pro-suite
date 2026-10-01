# Copyright (C) 2026 NetGuard AI Suite contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version. See the LICENSE file in the
# repository root for the full GPL v3 text, or
# <https://www.gnu.org/licenses/gpl-3.0.html>.
"""
Argus first-run onboarding wizard.

Standalone module. ``argus_pyqt.py`` is expected to import this and call
:func:`show_first_run_dialog` from its main window's ``__init__`` if
:func:`is_first_run` returns ``True``. The wiring is intentionally NOT
done here — wiring happens manually in a follow-up commit so this
module can be reviewed in isolation.

Public API:

    is_first_run() -> bool
        Returns True iff the ``.first_run`` flag file is missing.

    mark_first_run_complete() -> None
        Creates the ``.first_run`` flag file. Idempotent.

    show_first_run_dialog(parent=None) -> None
        Modal QDialog that walks the user through three explainer
        cards and a "Setup API Keys" placeholder. Calls
        :func:`mark_first_run_complete` when the user clicks
        ``Get Started``.

The dialog is honest about which security modes are real and which
are cosmetic in V1 — see card #2.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Resolved at import time to avoid surprises in tests where cwd may be
# unusual. The flag file lives next to other Argus state under
# ``argus_data/`` (already .gitignored).
_DATA_DIR = Path(__file__).resolve().parent / "argus_data"
_FIRST_RUN_FLAG = _DATA_DIR / ".first_run"

# Documentation anchor for the "what's actually protected" link.
_THREAT_MODEL_URL = "https://github.com/sxc3030-eng/netguard-pro-suite/blob/main/SECURITY.md"


# ---------------------------------------------------------------------------
# Public functional API
# ---------------------------------------------------------------------------

def is_first_run() -> bool:
    """Return ``True`` iff the user has never completed onboarding."""
    return not _FIRST_RUN_FLAG.exists()


def mark_first_run_complete() -> None:
    """Persist the flag indicating onboarding is done. Idempotent."""
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    _FIRST_RUN_FLAG.touch(exist_ok=True)


def show_first_run_dialog(parent: Optional[QWidget] = None) -> None:
    """Open the modal first-run wizard. Blocks until the user dismisses."""
    dialog = _FirstRunDialog(parent)
    dialog.exec()


# ---------------------------------------------------------------------------
# Dialog implementation
# ---------------------------------------------------------------------------

class _FirstRunDialog(QDialog):
    """Welcome wizard shown on the very first launch of Argus."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Welcome to Argus")
        self.setModal(True)
        self.setMinimumSize(620, 560)

        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 20)
        root.setSpacing(16)

        # ---- banner --------------------------------------------------
        banner = QLabel("Welcome to Argus — Cybersecurity Workbench")
        banner_font = QFont()
        banner_font.setPointSize(16)
        banner_font.setBold(True)
        banner.setFont(banner_font)
        banner.setAlignment(Qt.AlignmentFlag.AlignCenter)
        root.addWidget(banner)

        subtitle = QLabel(
            "Three things to know before you start. This dialog only "
            "appears once."
        )
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setStyleSheet("color: #666;")
        root.addWidget(subtitle)

        # ---- scrollable card area -----------------------------------
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        cards_host = QWidget()
        cards_layout = QVBoxLayout(cards_host)
        cards_layout.setContentsMargins(0, 0, 0, 0)
        cards_layout.setSpacing(12)

        cards_layout.addWidget(_make_card(
            icon="\U0001F6E1",  # shield
            title="NetGuard launcher",
            body=(
                "Click the shield button at the bottom-right of the dock "
                "to start the network monitoring backend. It runs locally "
                "on your machine — no traffic data leaves your computer. "
                "Stop it the same way."
            ),
        ))

        cards_layout.addWidget(_make_card(
            icon="\U0001F7E1",  # yellow circle
            title="Mode Coffre for banking — what it really does in V1",
            body=(
                "Argus has three browsing modes: Normal, Privé, and Coffre. "
                "In V1 these modes change ONLY the colored border around "
                "the window. They are NOT yet a security boundary: they "
                "do not enforce strict TLS, they do not block third-party "
                "scripts, and they do not wipe memory on close. "
                "Real isolation lands in V3 (tracked in the README "
                "roadmap). Until then, treat the badge as a visual "
                "reminder, not a guarantee."
            ),
            highlight=True,
        ))

        cards_layout.addWidget(_make_card(
            icon="⌨",  # keyboard
            title="F12 for DevTools",
            body=(
                "Press F12 anywhere inside Argus to open Chromium "
                "DevTools — Elements, Network, Console, Sources. Full "
                "Chromium power, same as a regular browser."
            ),
        ))

        cards_layout.addStretch(1)
        scroll.setWidget(cards_host)
        root.addWidget(scroll, stretch=1)

        # ---- threat-model link --------------------------------------
        threat = QLabel(
            f'See the full threat model and what is / is not protected: '
            f'<a href="{_THREAT_MODEL_URL}">SECURITY.md</a>'
        )
        threat.setOpenExternalLinks(True)
        threat.setAlignment(Qt.AlignmentFlag.AlignCenter)
        threat.setStyleSheet("color: #555;")
        root.addWidget(threat)

        # ---- buttons -------------------------------------------------
        button_row = QHBoxLayout()
        button_row.setSpacing(10)

        self._setup_keys_btn = QPushButton("Setup API Keys")
        self._setup_keys_btn.setToolTip(
            "Opens the Settings dialog at the API Keys section."
        )
        self._setup_keys_btn.clicked.connect(self._on_setup_keys_clicked)

        button_row.addWidget(self._setup_keys_btn)
        button_row.addStretch(1)

        self._get_started_btn = QPushButton("Get Started")
        self._get_started_btn.setDefault(True)
        self._get_started_btn.clicked.connect(self._on_get_started_clicked)
        button_row.addWidget(self._get_started_btn)

        root.addLayout(button_row)

    # ------------------------------------------------------------------
    # Slots
    # ------------------------------------------------------------------

    def _on_setup_keys_clicked(self) -> None:
        """Placeholder hook — the real wiring opens the Settings dialog.

        argus_pyqt.py will replace this slot via signal/slot when it
        imports the dialog. For now we no-op so the button is harmless
        in standalone testing.
        """
        # Intentional no-op in V1. The host application is expected to
        # disconnect this slot and connect its own settings-opener.
        return

    def _on_get_started_clicked(self) -> None:
        mark_first_run_complete()
        self.accept()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_card(
    *,
    icon: str,
    title: str,
    body: str,
    highlight: bool = False,
) -> QFrame:
    """Return a single explainer card widget."""
    card = QFrame()
    card.setFrameShape(QFrame.Shape.StyledPanel)
    border = "#d97706" if highlight else "#d0d7de"
    background = "#fff8eb" if highlight else "#ffffff"
    card.setStyleSheet(
        f"QFrame {{ background: {background}; border: 1px solid {border}; "
        f"border-radius: 8px; }}"
    )

    layout = QHBoxLayout(card)
    layout.setContentsMargins(14, 12, 14, 12)
    layout.setSpacing(14)

    icon_label = QLabel(icon)
    icon_font = QFont()
    icon_font.setPointSize(22)
    icon_label.setFont(icon_font)
    icon_label.setFixedWidth(40)
    icon_label.setAlignment(
        Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignHCenter
    )
    layout.addWidget(icon_label)

    text_col = QVBoxLayout()
    text_col.setSpacing(4)

    title_label = QLabel(title)
    title_font = QFont()
    title_font.setPointSize(11)
    title_font.setBold(True)
    title_label.setFont(title_font)
    text_col.addWidget(title_label)

    body_label = QLabel(body)
    body_label.setWordWrap(True)
    body_label.setStyleSheet("color: #333;")
    text_col.addWidget(body_label)

    layout.addLayout(text_col, stretch=1)
    return card

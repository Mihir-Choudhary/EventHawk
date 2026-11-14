"""
Add / edit a custom column (Event Log Explorer style).

Title, Value template, optional Event ID and Provider filters, Text or
Integer type, and a field picker built from a sample event (the event selected
in the table): clicking a field inserts its token at the cursor.  OK validates
the definition with core.custom_columns.compile_spec; an error keeps the dialog
open and says what is wrong.

While the definition is edited, a preview line shows what the column will hold
for the sample event (or what is wrong so far), the picker can be filtered by
name or value and lists the event's own data fields first, and one click puts
the sample event's ID into the Event ID filter.
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox, QDialog, QFormLayout, QFrame, QHBoxLayout, QLabel, QLineEdit, QMessageBox,
    QPushButton, QSizePolicy, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

from evtx_tool.core.custom_columns import (
    CustomColumnError, CustomColumnSpec, SYSTEM_TOKEN_NAMES, compile_spec, field_catalog,
)
from evtx_tool.core.filters import validate_event_id_expression
from evtx_tool.gui.theme import COLORS

_ROLE_TOKEN = Qt.ItemDataRole.UserRole + 1

# Separators offered for joining several fields in one column: (label, text).
JOIN_CHOICES = (
    ("Space", " "),
    ("\\  (DOMAIN\\user)", "\\"),
    (" |  (pipe)", " | "),
    (" /  (slash)", " / "),
    (":  (colon)", ":"),
    (", (comma)", ", "),
    (" \u2192  (arrow)", " \u2192 "),
    ("Nothing", ""),
)


def template_tokens(text: str) -> list:
    """(start, end, token) of every field token in a Value template, skipping
    the literal braces {{ and }}; an unclosed brace ends the scan."""
    out, i = [], 0
    while i < len(text):
        if text.startswith("{{", i) or text.startswith("}}", i):
            i += 2
            continue
        if text[i] == "{":
            end = text.find("}", i + 1)
            if end < 0:
                break
            out.append((i, end + 1, text[i:end + 1]))
            i = end + 1
            continue
        i += 1
    return out


def token_label(token: str) -> str:
    """Short name of a token for chips and titles: {Data[LogonType]} -> LogonType."""
    inner = token.strip("{}").strip()
    if "[" in inner and inner.endswith("]"):
        name, arg = inner.split("[", 1)
        arg = arg[:-1].strip()
        if name.strip().lower() in ("data", "eventdata", "userdata"):
            return f"Data #{arg}" if arg.isdigit() else arg
        return f"{name.strip()}[{arg}]"
    return inner


class CustomColumnDialog(QDialog):
    def __init__(self, col_id: int, sample_event: "dict | None" = None,
                 spec: "CustomColumnSpec | None" = None, parent=None,
                 peer_fields: "list | None" = None, peer_total: int = 0):
        super().__init__(parent)
        self.setWindowTitle("Edit Custom Column" if spec else "Add Custom Column")
        self.setMinimumSize(620, 540)
        self._col_id = col_id
        self._compiled = None
        self._sample = sample_event
        root = QVBoxLayout(self)

        form = QFormLayout()
        self._inp_title = QLineEdit(spec.title if spec else "")
        self._inp_title.setPlaceholderText("Column title, e.g. Logon Type")
        form.addRow("Column title:", self._inp_title)
        self._inp_value = QLineEdit(spec.template if spec else "")
        self._inp_value.setPlaceholderText("{Data[LogonType]}   {EventID}   {Data[TargetDomainName]}\\{Data[TargetUserName]}")
        self._inp_value.setToolTip(
            "Tokens: {EventID}, {TimeCreated[SystemTime]}, {Provider[Name]}, {Computer}, "
            "{Security[UserID]}, {Execution[ProcessID]} ...; {Data[Name]} for an EventData / "
            "UserData field by name; {Data[3]} for the 3rd <Data> element (counting from 1). "
            "Other text is kept as written; {{ and }} write literal braces.")
        value_box = QVBoxLayout()
        value_box.setSpacing(4)
        value_box.addWidget(self._inp_value)
        join_row = QHBoxLayout()
        join_row.setSpacing(6)
        lbl_join = QLabel("Join fields with:")
        lbl_join.setToolTip("Put between fields when you click more than one into the Value")
        self._cmb_join = QComboBox()
        for label, _sep in JOIN_CHOICES:
            self._cmb_join.addItem(label)
        self._cmb_join.setToolTip("Put between fields when you click more than one into the Value")
        self._chips = QWidget()
        self._chips_layout = QHBoxLayout(self._chips)
        self._chips_layout.setContentsMargins(0, 0, 0, 0)
        self._chips_layout.setSpacing(4)
        join_row.addWidget(lbl_join)
        join_row.addWidget(self._cmb_join)
        join_row.addSpacing(8)
        join_row.addWidget(self._chips, 1)
        value_box.addLayout(join_row)
        form.addRow("Value:", value_box)
        self._auto_title = ""
        self._inp_eids = QLineEdit(spec.eid_expr if spec else "")
        self._inp_eids.setPlaceholderText("All events  (e.g. 4624,4625 or 4600-4700!4634)")
        eid_row = QHBoxLayout()
        eid_row.setSpacing(6)
        eid_row.addWidget(self._inp_eids, 1)
        self._btn_this_eid = None
        _eid = (sample_event or {}).get("event_id")
        if _eid not in (None, ""):
            self._btn_this_eid = QPushButton(f"This event ({_eid})")
            self._btn_this_eid.setToolTip(
                "Only events with the selected event's ID get a value in this column")
            self._btn_this_eid.clicked.connect(lambda _c=False, e=str(_eid): self._inp_eids.setText(e))
            eid_row.addWidget(self._btn_this_eid)
        form.addRow("Event ID filter:", eid_row)
        self._inp_providers = QLineEdit(", ".join(spec.providers) if spec else "")
        self._inp_providers.setPlaceholderText("All providers  (comma-separated provider names)")
        form.addRow("Provider filter:", self._inp_providers)
        self._cmb_type = QComboBox()
        self._cmb_type.addItems(["Text", "Integer"])
        self._cmb_type.setCurrentIndex(1 if spec and spec.kind == "int" else 0)
        self._cmb_type.setToolTip("Integer: sorts by number (decimal and 0x hex); other text is kept as found.")
        form.addRow("Type:", self._cmb_type)
        root.addLayout(form)

        self._lbl_preview = QLabel()
        self._lbl_preview.setObjectName("customColumnPreview")
        self._lbl_preview.setWordWrap(True)
        self._lbl_preview.setTextFormat(Qt.TextFormat.PlainText)
        self._lbl_preview.setMinimumHeight(34)
        root.addWidget(self._lbl_preview)
        for _w in (self._inp_value, self._inp_eids, self._inp_providers):
            _w.textChanged.connect(self._update_preview)
        self._inp_value.textChanged.connect(self._rebuild_chips)
        self._cmb_join.currentIndexChanged.connect(self._rejoin)
        self._cmb_type.currentIndexChanged.connect(self._update_preview)

        hint = ("Fields of the selected event (dimmed: fields other events with its ID have) — "
                "click one to add it to the column; click more to combine them (joined with "
                "the separator above)."
                if sample_event else
                "No event is selected, so only the System fields are listed. Select an event "
                "in the table to pick from its EventData / UserData fields.")
        self._lbl_hint = QLabel(hint)
        self._lbl_hint.setWordWrap(True)
        root.addWidget(self._lbl_hint)
        self._inp_field_filter = QLineEdit()
        self._inp_field_filter.setPlaceholderText("Filter fields by name or value\u2026")
        self._inp_field_filter.setClearButtonEnabled(True)
        self._inp_field_filter.textChanged.connect(self._filter_fields)
        root.addWidget(self._inp_field_filter)
        self._tree = QTreeWidget()
        self._tree.setHeaderLabels(["Field", "Value in the selected event"])
        self._tree.setRootIsDecorated(False)
        self._tree.setColumnWidth(0, 230)
        if sample_event:
            # The event's own data fields first: they are what a column is
            # usually for; the System fields already have built-in columns.
            _cat = field_catalog(sample_event)
            _data = [c for c in _cat if c[0].lower().startswith("{data[")]
            _system = [c for c in _cat if not c[0].lower().startswith("{data[")]
            for token, label, value in _data:
                it = QTreeWidgetItem([label, value[:200]])
                it.setData(0, _ROLE_TOKEN, token)
                it.setToolTip(0, token)
                self._tree.addTopLevelItem(it)
            # Fields other events with this ID carry and this one does not:
            # an event type's fields vary (Restart Manager File_1..n, Defender's
            # optional scan settings), and a column built from one event missed
            # them.  Dimmed, with an example value from another event.
            from PySide6.QtGui import QColor
            _eid = sample_event.get("event_id")
            for token, label, example, count in (peer_fields or []):
                it = QTreeWidgetItem([label, f"not in this event \u2014 e.g. {example[:160]}"
                                      if example else "not in this event"])
                it.setData(0, _ROLE_TOKEN, token)
                it.setToolTip(0, f"{token}\nNot in the selected event; seen in {count:,} of "
                                 f"{peer_total:,} event(s) with ID {_eid} from this provider.")
                it.setToolTip(1, it.toolTip(0))
                for c in (0, 1):
                    it.setForeground(c, QColor(COLORS["text_muted"]))
                self._tree.addTopLevelItem(it)
            for token, label, value in _system:
                it = QTreeWidgetItem([label, value[:200]])
                it.setData(0, _ROLE_TOKEN, token)
                it.setToolTip(0, token)
                self._tree.addTopLevelItem(it)
        else:
            for name in SYSTEM_TOKEN_NAMES:
                it = QTreeWidgetItem([name, ""])
                it.setData(0, _ROLE_TOKEN, "{" + name + "}")
                self._tree.addTopLevelItem(it)
        self._tree.itemClicked.connect(self._insert_field)
        root.addWidget(self._tree, stretch=1)

        buttons = QHBoxLayout()
        buttons.addStretch()
        self._btn_ok = QPushButton("OK")
        self._btn_ok.setDefault(True)
        self._btn_ok.clicked.connect(self.accept)
        btn_cancel = QPushButton("Cancel")
        btn_cancel.clicked.connect(self.reject)
        buttons.addWidget(self._btn_ok)
        buttons.addWidget(btn_cancel)
        root.addLayout(buttons)
        self._rebuild_chips()
        self._update_preview()

    def _filter_fields(self, text: str) -> None:
        needle = text.strip().lower()
        for i in range(self._tree.topLevelItemCount()):
            it = self._tree.topLevelItem(i)
            hay = f"{it.text(0)} {it.text(1)}".lower()
            it.setHidden(bool(needle) and needle not in hay)

    def _set_preview(self, text: str, tone: str) -> None:
        color = {"ok": COLORS["text"], "dim": COLORS["text_dim"],
                 "warn": COLORS["level_warning"], "error": COLORS["level_error"]}[tone]
        self._lbl_preview.setStyleSheet(
            f"QLabel#customColumnPreview {{ color: {color}; background: {COLORS['bg_panel']};"
            f" border-radius: 4px; padding: 6px 8px; }}")
        self._lbl_preview.setText(text)

    def _update_preview(self, *_args) -> None:
        """What the column will hold for the sample event, or what is wrong."""
        spec = self.spec()
        if not spec.template.strip():
            self._set_preview("Preview: type a Value, or click a field below to insert it.", "dim")
            return
        if spec.eid_expr:
            bad = validate_event_id_expression(spec.eid_expr)
            if bad:
                self._set_preview("Event ID filter: invalid token(s) \u2014 "
                                  + ", ".join(repr(t) for t in bad), "error")
                return
        try:
            compiled = compile_spec(spec)
        except CustomColumnError as exc:
            self._set_preview(f"Not valid yet: {exc}", "error")
            return
        except Exception as exc:                    # never let the preview break typing
            self._set_preview(f"Not valid yet: {exc}", "error")
            return
        ev = self._sample
        if not ev:
            self._set_preview("Valid. Select an event in the table to preview its value.", "dim")
            return
        try:
            if not compiled.applies(ev):
                self._set_preview("For the selected event: (empty) \u2014 it is outside the column's "
                                  "Event ID / Provider filter.", "warn")
                return
            val = compiled.value(ev)
        except Exception as exc:
            self._set_preview(f"Not valid yet: {exc}", "error")
            return
        shown = val if len(val) <= 300 else val[:300] + "\u2026"
        if val == "":
            self._set_preview("For the selected event: (empty) \u2014 the event has no such field.", "warn")
        else:
            self._set_preview(f"For the selected event: {shown}", "ok")

    # ── Combining several fields ───────────────────────────────────────────────

    def _join(self) -> str:
        return JOIN_CHOICES[max(0, self._cmb_join.currentIndex())][1]

    def _insert_field(self, item: QTreeWidgetItem, _column: int = 0) -> None:
        """Add the field to the Value at the cursor.  A field next to another
        one gets the "Join fields with" separator between them -- two clicks
        used to give {Data[A]}{Data[B]}, the values run together."""
        token = item.data(0, _ROLE_TOKEN)
        if not token:
            return
        text = self._inp_value.text()
        pos = self._inp_value.cursorPosition()
        before, after = text[:pos], text[pos:]
        sep = self._join()
        ins = token
        if sep and before.endswith("}") and not before.endswith("}}"):
            ins = sep + ins
        if sep and after.startswith("{") and not after.startswith("{{"):
            ins = ins + sep
        self._inp_value.setText(before + ins + after)
        self._update_auto_title()
        self._inp_value.setFocus()
        self._inp_value.deselect()
        self._inp_value.setCursorPosition(len(before) + len(ins))

    def _update_auto_title(self) -> None:
        """While the title is the one suggested here (or empty), it follows
        the fields: "TargetDomainName \\ TargetUserName"."""
        cur = self._inp_title.text().strip()
        if cur and cur != self._auto_title:
            return                                   # the user's own title stays
        names = [token_label(t) for _s, _e, t in template_tokens(self._inp_value.text())]
        sep = self._join().strip() or "+"
        title = f" {sep} ".join(names) if names else ""
        self._auto_title = title
        self._inp_title.setText(title)

    def _remove_token(self, start: int, end: int) -> None:
        """Remove one field (and the separator joining it to a neighbour)."""
        text = self._inp_value.text()
        sep = self._join()
        before, after = text[:start], text[end:]
        if sep and before.endswith(sep):
            before = before[: -len(sep)]
        elif sep and after.startswith(sep):
            after = after[len(sep):]
        self._inp_value.setText(before + after)
        self._update_auto_title()

    def _rejoin(self, *_args) -> None:
        """A new separator: re-join the fields when the Value is only fields
        and separators (anything hand-written is left as it is)."""
        text = self._inp_value.text()
        toks = template_tokens(text)
        if len(toks) < 2:
            self._update_auto_title()
            return
        gaps = [text[toks[i][1]:toks[i + 1][0]] for i in range(len(toks) - 1)]
        known = {sep for _l, sep in JOIN_CHOICES}
        if text[:toks[0][0]] or text[toks[-1][1]:] or any(g not in known for g in gaps):
            self._update_auto_title()
            return
        self._inp_value.setText(self._join().join(t for _s, _e, t in toks))
        self._update_auto_title()

    def _rebuild_chips(self, *_args) -> None:
        """One chip per field in the Value, each with an x to remove it."""
        from .icons import icon as _icon
        while self._chips_layout.count():
            w = self._chips_layout.takeAt(0).widget()
            if w is not None:
                # Off screen now: deleteLater alone left the old chips drawn
                # under the new ones until the event loop came round.
                w.hide()
                w.setParent(None)
                w.deleteLater()
        toks = template_tokens(self._inp_value.text())
        for start, end, tok in toks:
            chip = QFrame()
            chip.setObjectName("fieldChip")
            chip.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)
            chip.setStyleSheet(
                f"QFrame#fieldChip {{ background: {COLORS['selected_bg']}; border-radius: 4px; }}")
            row = QHBoxLayout(chip)
            row.setContentsMargins(7, 1, 2, 1)
            row.setSpacing(2)
            lbl = QLabel(token_label(tok))
            lbl.setStyleSheet(f"color: {COLORS['text']}; font-size: 8pt; background: transparent;")
            lbl.setToolTip(tok)
            btn = QPushButton()
            btn.setIcon(_icon("x", "text_dim", 10))
            btn.setFixedSize(16, 16)
            btn.setToolTip(f"Remove {token_label(tok)} from the column")
            btn.setStyleSheet("QPushButton { border: none; background: transparent; padding: 0;"
                              " min-height: 0; }")
            btn.clicked.connect(lambda _c=False, s_=start, e_=end: self._remove_token(s_, e_))
            row.addWidget(lbl)
            row.addWidget(btn)
            self._chips_layout.addWidget(chip)
        self._chips_layout.addStretch(1)

    def spec(self) -> CustomColumnSpec:
        provs = tuple(p.strip() for p in self._inp_providers.text().split(",") if p.strip())
        return CustomColumnSpec(
            col_id=self._col_id, title=self._inp_title.text().strip(),
            template=self._inp_value.text(), eid_expr=self._inp_eids.text().strip(),
            providers=provs, kind="int" if self._cmb_type.currentIndex() == 1 else "text")

    def compiled(self):
        """The validated column (set when OK succeeded)."""
        return self._compiled

    def accept(self) -> None:  # type: ignore[override]
        spec = self.spec()
        errors = []
        if not spec.title:
            errors.append("Give the column a title.")
        if spec.eid_expr:
            bad = validate_event_id_expression(spec.eid_expr)
            if bad:
                errors.append("Event ID filter: invalid token(s) — " + ", ".join(repr(t) for t in bad))
        try:
            self._compiled = compile_spec(spec)
        except CustomColumnError as exc:
            errors.append(str(exc))
        if errors:
            QMessageBox.warning(self, "Custom column", "\n\n".join(errors))
            return
        super().accept()

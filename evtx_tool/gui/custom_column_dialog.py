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
    QComboBox, QDialog, QFormLayout, QHBoxLayout, QLabel, QLineEdit, QMessageBox,
    QPushButton, QTreeWidget, QTreeWidgetItem, QVBoxLayout,
)

from evtx_tool.core.custom_columns import (
    CustomColumnError, CustomColumnSpec, SYSTEM_TOKEN_NAMES, compile_spec, field_catalog,
)
from evtx_tool.core.filters import validate_event_id_expression
from evtx_tool.gui.theme import COLORS

_ROLE_TOKEN = Qt.ItemDataRole.UserRole + 1


class CustomColumnDialog(QDialog):
    def __init__(self, col_id: int, sample_event: "dict | None" = None,
                 spec: "CustomColumnSpec | None" = None, parent=None):
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
        form.addRow("Value:", self._inp_value)
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
        self._cmb_type.currentIndexChanged.connect(self._update_preview)

        hint = ("Fields of the selected event — click one to insert it into Value."
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
            _cat = ([c for c in _cat if c[0].lower().startswith("{data[")]
                    + [c for c in _cat if not c[0].lower().startswith("{data[")])
            for token, label, value in _cat:
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

    def _insert_field(self, item: QTreeWidgetItem, _column: int = 0) -> None:
        token = item.data(0, _ROLE_TOKEN)
        if token:
            self._inp_value.insert(token)
            if not self._inp_title.text().strip():
                self._inp_title.setText(item.text(0).split("  (#")[0])
            self._inp_value.setFocus()

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

"""
Add / edit a custom column (Event Log Explorer style).

Title, Value template, optional Event ID and Provider filters, Text or
Integer type, and a field picker built from a sample event (the event selected
in the table): clicking a field inserts its token at the cursor.  OK validates
the definition with core.custom_columns.compile_spec; an error keeps the dialog
open and says what is wrong.
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

_ROLE_TOKEN = Qt.ItemDataRole.UserRole + 1


class CustomColumnDialog(QDialog):
    def __init__(self, col_id: int, sample_event: "dict | None" = None,
                 spec: "CustomColumnSpec | None" = None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Edit Custom Column" if spec else "Add Custom Column")
        self.setMinimumSize(620, 520)
        self._col_id = col_id
        self._compiled = None
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
        form.addRow("Event ID filter:", self._inp_eids)
        self._inp_providers = QLineEdit(", ".join(spec.providers) if spec else "")
        self._inp_providers.setPlaceholderText("All providers  (comma-separated provider names)")
        form.addRow("Provider filter:", self._inp_providers)
        self._cmb_type = QComboBox()
        self._cmb_type.addItems(["Text", "Integer"])
        self._cmb_type.setCurrentIndex(1 if spec and spec.kind == "int" else 0)
        self._cmb_type.setToolTip("Integer: sorts by number (decimal and 0x hex); other text is kept as found.")
        form.addRow("Type:", self._cmb_type)
        root.addLayout(form)

        hint = ("Fields of the selected event — click one to insert it into Value."
                if sample_event else
                "No event is selected, so only the System fields are listed. Select an event "
                "in the table to pick from its EventData / UserData fields.")
        self._lbl_hint = QLabel(hint)
        self._lbl_hint.setWordWrap(True)
        root.addWidget(self._lbl_hint)
        self._tree = QTreeWidget()
        self._tree.setHeaderLabels(["Field", "Value in the selected event"])
        self._tree.setRootIsDecorated(False)
        self._tree.setColumnWidth(0, 230)
        if sample_event:
            for token, label, value in field_catalog(sample_event):
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

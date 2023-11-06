import sys
from PyQt5.QtWidgets import QApplication, QListWidget, QListWidgetItem

app = QApplication(sys.argv)

list_widget = QListWidget()
list_widget.resize(400, 200)

# Establece la política de ajuste del tamaño para que los elementos llenen horizontalmente la fila
list_widget.setSizeAdjustPolicy(QListWidget.AdjustToContentsOnFirstShow)

# Agregar elementos a la lista
item1 = QListWidgetItem("Este es un elemento de texto que se autoexpandirá para llenar la fila.")
item2 = QListWidgetItem("Otro elemento con un texto más largo para demostrar la expansión automática.")
list_widget.addItem(item1)
list_widget.addItem(item2)

list_widget.show()
sys.exit(app.exec_())
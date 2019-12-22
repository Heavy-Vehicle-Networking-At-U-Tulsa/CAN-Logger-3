
from PyQt5.QtWidgets import (QMainWindow,
                             QWidget,
                             QTreeView,
                             QMessageBox,
                             QFileDialog,
                             QLabel,
                             QSlider,
                             QCheckBox,
                             QLineEdit,
                             QVBoxLayout,
                             QApplication,
                             QPushButton,
                             QTableWidget,
                             QTableView,
                             QTableWidgetItem,
                             QScrollArea,
                             QAbstractScrollArea,
                             QAbstractItemView,
                             QSizePolicy,
                             QGridLayout,
                             QGroupBox,
                             QComboBox,
                             QAction,
                             QDockWidget,
                             QDialog,
                             QFrame,
                             QDialogButtonBox,
                             QInputDialog,
                             QProgressDialog,
                             QTabWidget)
from PyQt5.QtCore import Qt, QTimer, QCoreApplication
from PyQt5.QtGui import QIcon
import os
import serial
import serial.tools.list_ports
import logging
import threading
import traceback

logger = logging.getLogger(__name__)

class SerialDialog(QDialog):
    def __init__(self,title):
        super(SerialDialog,self).__init__()
        self.baudrate = 4800
        self.comport = "COM1"
        self.setup_dialog()
        self.setWindowTitle("Select GPS")
        self.setWindowModality(Qt.ApplicationModal)
        self.connected = False
        self.ser = None
        self.gps_settings_file = os.path.join(get_storage_path(), "GPS_setting.txt")


    def setup_dialog(self):

        serial_port_label = QLabel("Serial Port")
        self.serial_port_combo_box = QComboBox()
        self.serial_port_combo_box.setInsertPolicy(QComboBox.NoInsert)
        for device in sorted(serial.tools.list_ports.comports(), reverse = True):
            self.serial_port_combo_box.addItem("{} - {}".format(device.device, device.description))
        self.serial_port_combo_box.setSizeAdjustPolicy(QComboBox.AdjustToContents)
        
        self.buttons = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel,
            Qt.Horizontal, self)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)

        self.accepted.connect(self.set_GPS)
        #self.rejected.connect(self.reject_GPS)

        self.v_layout = QVBoxLayout()
        self.v_layout.addWidget(gps_port_label)
        self.v_layout.addWidget(self.gps_port_combo_box)
        self.v_layout.addWidget(baud_label)
        self.v_layout.addWidget(self.baud_combo_box)
        self.v_layout.addWidget(self.buttons)

        self.setLayout(self.v_layout)
    
    def run(self):
        self.gps_port_combo_box.clear()
        for device in sorted(serial.tools.list_ports.comports(), reverse = True):
            self.gps_port_combo_box.addItem("{} - {}".format(device.device, device.description))
        self.gps_port_combo_box.setSizeAdjustPolicy(QComboBox.AdjustToContents)
        self.exec_()

    def set_GPS(self): 
        self.comport = self.gps_port_combo_box.currentText().split('-')[0].strip()
        self.baud = int(self.baud_combo_box.currentText())
        return self.connect_GPS()

    def connect_GPS(self): 
        logger.debug("Trying to connect GPS.")
        try:
            self.ser.close()
            del self.ser
        except AttributeError:
            pass

        try:
            self.ser = serial.Serial(self.comport, baudrate=self.baud, timeout=2)
        except serial.serialutil.SerialException:
            logger.debug(traceback.format_exc())
            if "PermissionError" in repr(traceback.format_exc()):
                QMessageBox.information(self,"GPS Status","The port {} is already in use. Please unplug and replug the GPS unit.".format(self.comport))
            else:
                self.connected = False
                return False
        try:
            test_sentence = self.ser.readline().decode('ascii','ignore')
            if len(test_sentence) > 0:
                logger.info("Successful GPS connection on {}".format(self.comport))
                with open(self.gps_settings_file,"w") as out_file:
                    out_file.write("{},{}\n".format(self.comport, self.baud))
                self.connected = True
                return True
            else:
                logger.debug("Could not find GPS connection on {}".format(self.comport))
                QMessageBox.information(self,"No Connection","Could not find GPS connection on {}".format(self.comport))
                self.connected = False
                return False
        except:
            logger.debug(traceback.format_exc())
            return False

    def try_GPS(self):
        try:
            with open(self.gps_settings_file, "r") as in_file:
                lines = in_file.readlines()
            line_list = lines[0].split(",")
            self.comport = line_list[0]
            self.baud = line_list[1]
            self.connected = self.connect_GPS()

        except FileNotFoundError:
            self.connected = False
        return self.connected 


if __name__.endswith('__main__'):
    app = QApplication(sys.argv)
    execute = SerialInterface()
    sys.exit(app.exec_())
    
import QtQuick 2.4
import QtQuick.Controls 1.3
import QtQuick.Window 2.2
import QtQuick.Dialogs 1.2

ApplicationWindow {
    id: applicationWindow1
    title: qsTr("Door lock")
    width: 800
    height: 600
    visible: true

    function nfcLog(line) {
        mainForm.log.append(line);
    }

    function sigValidated(valid) {
        console.log("Signature validated: ", valid)
        if(valid) {
            mainForm.status.color = "green";
            mainForm.caption.text = "Door UNLOCKED!";
        }
        else {
            mainForm.status.color = "#ae1f1f";
            mainForm.caption.text = "Door LOCKED!";
        }

    }

    function certValidated(valid) {
        console.log("Certificate validated: ", valid)

    }

    menuBar: MenuBar {
        Menu {
            title: qsTr("&File")
            MenuItem {
                text: qsTr("E&xit")
                onTriggered: Qt.quit();
            }
        }
    }

    MainForm {
        id: mainForm
        anchors.top: parent.top
        anchors.topMargin: 0
        anchors.bottom: parent.bottom
        anchors.bottomMargin: 0
        anchors.left: parent.left
        anchors.leftMargin: 0
        anchors.right: parent.right
        anchors.rightMargin: 0
    }

    MessageDialog {
        id: messageDialog
        title: qsTr("May I have your attention, please?")

        function show(caption) {
            messageDialog.text = caption;
            messageDialog.open();
        }
    }
}

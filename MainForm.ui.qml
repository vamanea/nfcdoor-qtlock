import QtQuick 2.4
import QtQuick.Controls 1.3
import QtQuick.Layouts 1.1

Item {
    width: 640
    height: 480

    property alias log: textArea1
    property alias status: rectangle1
    property alias caption: text1
    property alias key: text2


    ColumnLayout {
        id: columnLayout1
        spacing: 2
        anchors.fill: parent

        Rectangle {
            id: rectangle1
            height: 150
            color: "#ae1f1f"
            radius: 1
            border.color: "#696969"
            border.width: 2
            anchors.right: parent.right
            anchors.rightMargin: 0
            anchors.left: parent.left
            anchors.leftMargin: 0

            Text {
                id: text1
                x: 0
                y: 0
                width: 301
                height: 44
                text: qsTr("Door LOCKED!")
                verticalAlignment: Text.AlignVCenter
                horizontalAlignment: Text.AlignHCenter
                anchors.verticalCenterOffset: -24
                anchors.horizontalCenterOffset: 0
                anchors.horizontalCenter: parent.horizontalCenter
                anchors.verticalCenter: parent.verticalCenter
                font.family: "Verdana"
                z: 1
                font.pixelSize: 42
            }

            Text {
                id: text2
                x: 4
                y: 2
                width: 301
                height: 44
                text: qsTr("")
                horizontalAlignment: Text.AlignHCenter
                anchors.horizontalCenterOffset: 0
                font.family: "Verdana"
                anchors.horizontalCenter: parent.horizontalCenter
                anchors.verticalCenter: parent.verticalCenter
                font.pixelSize: 36
                anchors.verticalCenterOffset: 30
                z: 2
            }
        }

        TextArea {
            id: textArea1
            Layout.fillHeight: true
            text: ""
            readOnly: true
            font.family: "Courier"
            anchors.right: parent.right
            anchors.rightMargin: 0
            anchors.left: parent.left
            anchors.leftMargin: 0
        }
    }
}

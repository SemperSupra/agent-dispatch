module example.org/usb-fabric-r24-qmp-usbip-identity

go 1.23

require (
 example.org/usb-fabric-r26-integrated v0.0.0
 example.org/usb-fabric-r26-releasegate v0.0.0
 example.org/usb-fabric-r23-same-lease-qmp v0.0.0
 example.org/usb-fabric-r22-qmp-usbip-compose v0.0.0
)

replace example.org/usb-fabric-r26-integrated => ../../../.r23-existing-go/experiments/usb-fabric-r26/integrated
replace example.org/usb-fabric-r26-releasegate => ../../../.r23-existing-go/experiments/usb-fabric-r26/releasegate
replace example.org/usb-fabric-r23-same-lease-qmp => ../../pi-usb-fabric-r23/same-lease-qmp
replace example.org/usb-fabric-r22-qmp-usbip-compose => ../../pi-usb-fabric-r22/qmp-usbip-compose

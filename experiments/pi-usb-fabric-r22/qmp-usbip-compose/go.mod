module example.org/usb-fabric-r22-qmp-usbip-compose

go 1.23

require (
 example.org/usb-fabric-r26-integrated v0.0.0
 example.org/usb-fabric-r26-releasegate v0.0.0
)

replace example.org/usb-fabric-r26-integrated => ../../../.r22-existing-go/experiments/usb-fabric-r26/integrated
replace example.org/usb-fabric-r26-releasegate => ../../../.r22-existing-go/experiments/usb-fabric-r26/releasegate

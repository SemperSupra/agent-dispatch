module example.org/usb-fabric-r23-dynamic-signed-lease

go 1.23

require (
 example.org/usb-fabric-r26-integrated v0.0.0
 example.org/usb-fabric-r26-releasegate v0.0.0
 example.org/usb-fabric-r22-guest-ed25519 v0.0.0
)

replace example.org/usb-fabric-r26-integrated => ../../usb-fabric-r26/integrated
replace example.org/usb-fabric-r26-releasegate => ../../usb-fabric-r26/releasegate
replace example.org/usb-fabric-r22-guest-ed25519 => ../../pi-usb-fabric-r22/guest-ed25519

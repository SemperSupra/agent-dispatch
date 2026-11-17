module example.org/usb-fabric-r26-integrated

go 1.23

// Exact qualified R26-L8 Go policy/guest wire module staged at sibling path.
// Offline and reversible; never fetch unpublished modules over the network.
require example.org/usb-fabric-r26-releasegate v0.0.0
replace example.org/usb-fabric-r26-releasegate => ../releasegate

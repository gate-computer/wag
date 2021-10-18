module gate.computer/wag/testsuite

go 1.17

require (
	gate.computer/gate v0.0.0-20211018065040-53d94d9f239e
	gate.computer/wag v0.33.1-0.20211018064058-2c01f4772f32
)

require (
	github.com/coreos/go-systemd/v22 v22.3.0 // indirect
	github.com/godbus/dbus/v5 v5.0.3 // indirect
	github.com/golang/protobuf v1.4.2 // indirect
	github.com/knightsc/gapstone v0.0.0-20180903222833-a85919f1441b // indirect
	github.com/tsavola/mu v1.0.0 // indirect
	golang.org/x/sys v0.0.0-20211007075335-d3039528d8ac // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	google.golang.org/protobuf v1.25.0 // indirect
	kernel.org/pub/linux/libs/security/libcap/cap v1.2.49 // indirect
	kernel.org/pub/linux/libs/security/libcap/psx v1.2.49 // indirect
)

replace gate.computer/wag => ../

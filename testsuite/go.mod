module gate.computer/wag/testsuite

go 1.17

require (
	gate.computer/gate v0.0.0-20211218165223-7367374f9e97
	gate.computer/wag v0.33.1-0.20211218164237-6e9c77cac22f
)

require (
	github.com/coreos/go-systemd/v22 v22.3.0 // indirect
	github.com/godbus/dbus/v5 v5.0.3 // indirect
	github.com/golang/protobuf v1.4.2 // indirect
	github.com/knightsc/gapstone v0.0.0-20180903222833-a85919f1441b // indirect
	golang.org/x/sys v0.0.0-20211216021012-1d35b9e2eb4e // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	google.golang.org/protobuf v1.25.0 // indirect
	import.name/lock v0.0.0-20211205191324-f24933776f0b // indirect
	kernel.org/pub/linux/libs/security/libcap/cap v1.2.49 // indirect
	kernel.org/pub/linux/libs/security/libcap/psx v1.2.49 // indirect
)

replace gate.computer/wag => ../

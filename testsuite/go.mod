module gate.computer/wag/testsuite

go 1.23

require (
	gate.computer v0.0.0-20240908135418-e8a041e28a98
	gate.computer/wag v0.36.0
)

require (
	github.com/coreos/go-systemd/v22 v22.5.0 // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/knightsc/gapstone v0.0.0-20211014144438-5e0e64002a6e // indirect
	golang.org/x/sys v0.25.0 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
	import.name/lock v0.0.0-20211205191324-f24933776f0b // indirect
	import.name/pan v0.3.0 // indirect
	kernel.org/pub/linux/libs/security/libcap/cap v1.2.66 // indirect
	kernel.org/pub/linux/libs/security/libcap/psx v1.2.66 // indirect
)

replace gate.computer/wag => ../

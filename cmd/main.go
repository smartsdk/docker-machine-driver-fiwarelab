package main

import (
	"github.com/docker/machine/libmachine/drivers/plugin"
	"github.com/smartsdk/docker-machine-driver-fiwarelab"
)

func main() {
	plugin.RegisterDriver(fiwarelab.NewDriver("", ""))
}

package main

import (
	"github.com/TykTechnologies/tyk/gateway"
	"github.com/pkg/profile"
)

func main() {
	defer profile.Start(profile.MemProfile, profile.ProfilePath("/data/tyk-gateway/")).Stop()
	gateway.Start()
}

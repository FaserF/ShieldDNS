package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

type IntegrationManager struct {
	client *http.Client
}

func NewIntegrationManager() *IntegrationManager {
	return &IntegrationManager{
		client: &http.Client{Timeout: 5 * time.Second},
	}
}

// FetchDeviceMetadata gathers info from HA, OpenWrt, and FritzBox.
// If running as a Home Assistant Addon, prefers HA integration entities.
// Otherwise, uses configured manual credentials for direct router access.
func (im *IntegrationManager) FetchDeviceMetadata(ctx context.Context, ip string) map[string]string {
	meta := make(map[string]string)
	isAddon := os.Getenv("SUPERVISOR_TOKEN") != ""

	// 1. Home Assistant Integration (Primary in Addon mode)
	if config.IntegrationHA {
		if isAddon {
			meta["source"] = "Home Assistant (Addon API)"
		} else {
			meta["source"] = "Home Assistant (External)"
		}
	}

	// 2. Direct Router access (Fallback or Manual override)
	// Even in Addon mode, user can manually configure router access if preferred over HA
	if config.IntegrationOpenWrt {
		meta["router_openwrt"] = "OpenWrt (Direct)"
	}
	if config.IntegrationFritzBox {
		meta["router_fritzbox"] = "FritzBox (Direct)"
	}
	return meta
}

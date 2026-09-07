package main

import (
	"os"
	"strings"
)

func detectOS(ua string) string {
	ua = strings.ToLower(ua)
	switch {
	case strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad") || strings.Contains(ua, "ipod"):
		return "iOS"
	case strings.Contains(ua, "android"):
		if strings.Contains(ua, "tv") || strings.Contains(ua, "fire") {
			return "Android TV"
		}
		return "Android"
	case strings.Contains(ua, "windows nt"):
		return "Windows"
	case strings.Contains(ua, "macintosh") || strings.Contains(ua, "mac os x"):
		return "macOS"
	case strings.Contains(ua, "linux") && !strings.Contains(ua, "android"):
		if strings.Contains(ua, "hass.io") || strings.Contains(ua, "home assistant") {
			return "Home Assistant OS"
		}
		return "Linux"
	case strings.Contains(ua, "crkey") || strings.Contains(ua, "chromecast"):
		return "Chromecast"
	case strings.Contains(ua, "tizen"):
		return "Tizen (Samsung TV)"
	case strings.Contains(ua, "playstation"):
		return "PlayStation"
	case strings.Contains(ua, "nintendo switch"):
		return "Nintendo Switch"
	case strings.Contains(ua, "dnssettings"):
		return "Apple Managed DNS"
	case strings.Contains(ua, "shelly"):
		return "Shelly IoT"
	case strings.Contains(ua, "esphome") || strings.Contains(ua, "tasmota") || strings.Contains(ua, "esp8266") || strings.Contains(ua, "esp32"):
		return "ESP-based IoT"
	case strings.Contains(ua, "sonos"):
		return "Sonos"
	case strings.Contains(ua, "rokios"):
		return "Roku OS"
	case strings.Contains(ua, "appletv") || strings.Contains(ua, "apple tv"):
		return "tvOS"
	case strings.Contains(ua, "aetv") || strings.Contains(ua, "firetv"):
		return "Fire OS"
	case strings.Contains(ua, "hdm") || strings.Contains(ua, "hue"):
		return "Philips Hue"
	}
	return ""
}

func detectDevice(ua string) string {
	ua = strings.ToLower(ua)
	switch {
	case strings.Contains(ua, "iphone"):
		return "iPhone"
	case strings.Contains(ua, "ipad"):
		return "iPad"
	case strings.Contains(ua, "atv") || strings.Contains(ua, "appletv") || strings.Contains(ua, "apple tv"):
		return "Apple TV"
	case strings.Contains(ua, "aft") || strings.Contains(ua, "firetv"):
		return "Amazon Fire TV"
	case strings.Contains(ua, "nexus") || strings.Contains(ua, "pixel"):
		return "Google Pixel"
	case strings.Contains(ua, "sonos"):
		return "Sonos Speaker"
	case strings.Contains(ua, "shelly"):
		return "Shelly Device"
	case strings.Contains(ua, "lg") && strings.Contains(ua, "webos"):
		return "LG Smart TV"
	case strings.Contains(ua, "bravia") || (strings.Contains(ua, "sony") && strings.Contains(ua, "tv")):
		return "Sony Smart TV"
	case strings.Contains(ua, "esphome"):
		return "ESPHome Device"
	case strings.Contains(ua, "unifi"):
		return "Ubiquiti Unifi"
	case strings.Contains(ua, "samsung") || strings.Contains(ua, "sm-"):
		return "Samsung Device"
	case strings.Contains(ua, "oneplus"):
		return "OnePlus Phone"
	case strings.Contains(ua, "huawei") || strings.Contains(ua, "honor"):
		return "Huawei/Honor Device"
	}
	return ""
}

func inferFromHostname(h string) (os, manufacturer string) {
	h = strings.ToLower(h)
	switch {
	case strings.Contains(h, "iphone"):
		return "iOS", "Apple (iPhone)"
	case strings.Contains(h, "ipad"):
		return "iOS", "Apple (iPad)"
	case strings.Contains(h, "macbook") || strings.Contains(h, "mac-") || strings.Contains(h, "imac"):
		return "macOS", "Apple (Mac)"
	case strings.Contains(h, "apple-watch") || strings.Contains(h, "watchos"):
		return "watchOS", "Apple Watch"
	case strings.Contains(h, "android"):
		return "Android", "Android Device"
	case strings.Contains(h, "pixel"):
		return "Android", "Google Pixel"
	case strings.Contains(h, "galaxy") || strings.Contains(h, "samsung"):
		return "Android", "Samsung Device"
	case strings.Contains(h, "windows"):
		return "Windows", "PC/Laptop"
	case strings.Contains(h, "nintendo"):
		return "Nintendo OS", "Nintendo Console"
	case strings.Contains(h, "playstation") || strings.Contains(h, "ps4") || strings.Contains(h, "ps5"):
		return "PlayStation OS", "Sony PlayStation"
	case strings.Contains(h, "xbox"):
		return "Xbox OS", "Microsoft Xbox"
	case strings.Contains(h, "sonos"):
		return "Sonos OS", "Sonos Speaker"
	case strings.Contains(h, "shelly"):
		return "Shelly Native", "Shelly IoT"
	case strings.Contains(h, "esphome") || strings.Contains(h, "tasmota") || strings.Contains(h, "esp32"):
		return "ESP-based", "IoT Device"
	case strings.Contains(h, "raspberry") || strings.Contains(h, "raspi"):
		return "Linux", "Raspberry Pi"
	case strings.Contains(h, "synology") || strings.Contains(h, "diskstation"):
		return "DSM", "Synology NAS"
	case strings.Contains(h, "unifi"):
		return "Unifi OS", "Ubiquiti Device"
	case strings.Contains(h, "fritz.box") || strings.Contains(h, "fritz.nas") || strings.Contains(h, "fritz-box"):
		return "FRITZ!OS", "AVM"
	case strings.Contains(h, "hp-printer") || strings.Contains(h, "hp_printer") || strings.Contains(h, "hpsmart"):
		return "Embedded", "HP Printer"
	case strings.Contains(h, "bridge") || strings.Contains(h, "gateway"):
		return "Embedded", "Network Bridge"
	case strings.Contains(h, "camera") || strings.Contains(h, "cam-"):
		return "Embedded", "Security Camera"
	case strings.Contains(h, "echo") || strings.Contains(h, "alexa") || strings.Contains(h, "amazon"):
		return "Fire OS", "Amazon Echo"
	}
	return "", ""
}

func getMACByIP(ip string) string {
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return ""
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[0] == ip {
			return fields[3]
		}
	}
	return ""
}

func getManufacturerByMAC(mac string) string {
	if len(mac) < 8 {
		return ""
	}
	prefix := strings.ToUpper(strings.ReplaceAll(mac[:8], ":", ""))

	// Expanded OUI database
	ouis := map[string]string{
		"B4FB12": "Apple", "0017F2": "Apple", "D0034B": "Apple", "F01898": "Apple",
		"04D6B8": "Apple", "1499E2": "Apple", "341298": "Apple", "404D7F": "Apple",
		"600308": "Apple", "703560": "Apple", "8C8590": "Apple", "DC2BD4": "Apple",
		"00166B": "Samsung", "E470B8": "Samsung", "286B35": "Samsung", "382D23": "Samsung",
		"484377": "Samsung", "8C71F8": "Samsung", "90B686": "Samsung", "B40B44": "Samsung",
		"702C1F": "Google", "D824BD": "Google", "1CC035": "Google", "BCD074": "Google",
		"28D244": "Xiaomi", "649E33": "Xiaomi", "8CBEBE": "Xiaomi", "ACF7F3": "Xiaomi",
		"00000C": "Cisco", "000142": "Cisco", "000143": "Cisco",
		"0010FA": "Sony", "280D1C": "Sony", "3C0771": "Sony", "709E29": "Sony",
		"001422": "Dell", "000874": "Dell", "000AF7": "Dell",
		"001143": "HP", "000E7F": "HP", "001185": "HP",
		"001132": "Synology", "9009DF": "Synology", "0024A5": "Synology",
		"B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi",
		"000C29": "VMware", "080027": "VirtualBox",
		"000420": "Slim Devices (Logitech)",
		"00096B": "IBM",
		"001F3B": "Nintendo", "98415C": "Nintendo", "E0E751": "Nintendo",
		"C0EEFB": "OnePlus",
		"000FB5": "Netgear", "288088": "Netgear", "BCF685": "Netgear",
		"0014BF": "Linksys",
		"0018E7": "TP-Link", "F4F26D": "TP-Link", "002719": "TP-Link", "50D4F7": "TP-Link", "D807B6": "TP-Link",
		"24A160": "Espressif (IoT)", "30AEA4": "Espressif (IoT)", "A4CF12": "Espressif (IoT)", "84F3EB": "Espressif (IoT)",
		"BCDD26": "Shelly/Allterco", "C049EF": "Shelly/Allterco", "40F520": "Shelly/Allterco",
		"00032F": "Sonos", "B8E937": "Sonos", "5C56D0": "Sonos", "949F3E": "Sonos",
		"00156D": "Ubiquiti", "0418D6": "Ubiquiti", "B4FBE4": "Ubiquiti", "7483C2": "Ubiquiti", "68D79A": "Ubiquiti",
		"0004F2": "Polycom", "64167F": "Polycom",
		"00E062": "Brother", "3C2AF4": "Brother", "E4A7A0": "Brother",
		"001788": "Philips Hue", "ECB5FA": "Philips Hue",
		"603197": "Netatmo",
		"002686": "AVM (FritzBox)", "0896D7": "AVM (FritzBox)", "3431C4": "AVM (FritzBox)", "3810D5": "AVM (FritzBox)",
		"444E6D": "AVM (FritzBox)", "7CC709": "AVM (FritzBox)", "9C28BF": "AVM (FritzBox)", "BC0543": "AVM (FritzBox)",
		"E0286D": "AVM (FritzBox)", "FCFBFB": "AVM (FritzBox)",
		"D4AD70": "Tesla", "44FB42": "Tesla",
		"0024E4": "Withings",
	}

	if m, ok := ouis[prefix]; ok {
		return m
	}
	return "-"
}


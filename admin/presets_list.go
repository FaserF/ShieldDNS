package main

var DefaultPresets = []List{
	// --- Official ---
	{Name: "ShieldDNS Official Blocklist", URL: "https://raw.githubusercontent.com/FaserF/ShieldDNS/main/official/blocklists/default.txt", Enabled: true, Category: "Official", IsRecommended: true},
	{Name: "Search Ads Hybrid Blocklist", URL: "https://raw.githubusercontent.com/FaserF/ShieldDNS/main/official/blocklists/search-ads-hybrid.txt", Enabled: false, Category: "Official"},

	// --- General Blocking ---
	{Name: "AdGuard Base Filter", URL: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt", Enabled: false, Category: "General Blocking", IsRecommended: true},
	{Name: "EasyList (Domains)", URL: "https://justdomains.github.io/blocklists/lists/easylist-justdomains.txt", Enabled: false, Category: "General Blocking", IsRecommended: true},
	{Name: "HaGeZi Multi (Light)", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/multi.txt", Enabled: false, Category: "General Blocking"},
	{Name: "HaGeZi Multi (Normal)", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/multi.txt", Enabled: false, Category: "General Blocking"},
	{Name: "HaGeZi Multi (Pro)", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.txt", Enabled: false, Category: "General Blocking", IsRecommended: true},
	{Name: "HaGeZi Multi (Pro++)", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.plus.txt", Enabled: false, Category: "General Blocking"},
	{Name: "HaGeZi Multi (Ultimate)", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/ultimate.txt", Enabled: false, Category: "General Blocking"},
	{Name: "OISD Basic", URL: "https://small.oisd.nl", Enabled: false, Category: "General Blocking", IsRecommended: true},
	{Name: "OISD Full", URL: "https://big.oisd.nl", Enabled: false, Category: "General Blocking"},
	{Name: "Steven Black Unified", URL: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", Enabled: false, Category: "General Blocking"},
	{Name: "1Hosts (Lite)", URL: "https://badmojr.github.io/1Hosts/Lite/domains.txt", Enabled: false, Category: "General Blocking"},
	{Name: "AdGuard DNS filter (Main)", URL: "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt", Enabled: false, Category: "General Blocking", IsRecommended: true},
	{Name: "Dan Pollock's List", URL: "https://someonewhocares.org/hosts/zero/hosts", Enabled: false, Category: "Legacy & Redundant"},
	{Name: "AdAway Default Blocklist", URL: "https://raw.githubusercontent.com/AdAway/adaway.github.io/master/hosts.txt", Enabled: false, Category: "Legacy & Redundant"},

	// --- Privacy & Tracking ---
	{Name: "AdGuard Tracking Protection", URL: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_3.txt", Enabled: false, Category: "Privacy & Tracking", IsRecommended: true},
	{Name: "AdGuard Annoyances Filter", URL: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_48.txt", Enabled: false, Category: "Privacy & Tracking", IsRecommended: true},
	{Name: "EasyPrivacy (Domains)", URL: "https://justdomains.github.io/blocklists/lists/easyprivacy-justdomains.txt", Enabled: false, Category: "Privacy & Tracking", IsRecommended: true},
	{Name: "AdGuard URL Tracking Filter", URL: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_17.txt", Enabled: false, Category: "Privacy & Tracking"},
	{Name: "HaGeZi CNAME Cloaking", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/cname-tracking.txt", Enabled: false, Category: "Privacy & Tracking", IsRecommended: true},
	{Name: "uBlock Origin Filter List", URL: "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt", Enabled: false, Category: "Privacy & Tracking"},
	{Name: "Lightswitch05 (Ads & Tracking Extended)", URL: "https://raw.githubusercontent.com/lightswitch05/hosts/master/docs/lists/ads-and-tracking-extended.txt", Enabled: false, Category: "Privacy & Tracking"},
	{Name: "EasyPrivacy (Hmirror)", URL: "https://raw.githubusercontent.com/hectorm/hmirror/master/data/easyprivacy/list.txt", Enabled: false, Category: "Privacy & Tracking"},
	{Name: "Disconnect-me Tracking", URL: "https://raw.githubusercontent.com/hectorm/hmirror/master/data/disconnect.me-tracking/list.txt", Enabled: false, Category: "Privacy & Tracking"},
	{Name: "Easyprivacy (Firebog)", URL: "https://v.firebog.net/hosts/Easyprivacy.txt", Enabled: false, Category: "Privacy & Tracking"},
	{Name: "NoTrack Blocklist (Quidsup)", URL: "https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-blocklist.txt", Enabled: false, Category: "Privacy & Tracking"},
	{Name: "spy (WindowsSpyBlocker)", URL: "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt", Enabled: false, Category: "Privacy & Tracking"},
	{Name: "Firstparty Trackers (Frogeye)", URL: "https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt", Enabled: false, Category: "Privacy & Tracking"},
	{Name: "CERT.PL (AdBlock format - DNS4EU Partner)", URL: "https://hole.cert.pl/domains/v2/domains_adblock.txt", Enabled: false, Category: "Privacy & Tracking"},

	// --- Security & Malware ---
	{Name: "HaGeZi TIF (Threat Intelligence)", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/tif.txt", Enabled: false, Category: "Security & Malware", IsRecommended: true},
	{Name: "HaGeZi Fake (Fake Stores/Malware)", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/fake.txt", Enabled: false, Category: "Security & Malware", IsRecommended: true},
	{Name: "Phishing.Database (Phishing Domains)", URL: "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt", Enabled: false, Category: "Security & Malware", IsRecommended: true},
	{Name: "The Big List of Hacked Sites", URL: "https://raw.githubusercontent.com/mitchellkrogza/The-Big-List-of-Hacked-Malware-Web-Sites/master/hacked-domains.list", Enabled: false, Category: "Security & Malware"},
	{Name: "Disconnect-me Malvertising", URL: "https://raw.githubusercontent.com/hectorm/hmirror/master/data/disconnect.me-malvertising/list.txt", Enabled: false, Category: "Security & Malware"},
	{Name: "Eth-phishing-detect", URL: "https://raw.githubusercontent.com/hectorm/hmirror/master/data/eth-phishing-detect/list.txt", Enabled: false, Category: "Security & Malware"},
	{Name: "MalwareDomainList.com", URL: "https://raw.githubusercontent.com/hectorm/hmirror/master/data/malwaredomainlist.com/list.txt", Enabled: false, Category: "Security & Malware"},
	{Name: "Phishing Army Extended", URL: "https://phishing.army/download/phishing_army_blocklist_extended.txt", Enabled: false, Category: "Security & Malware"},
	{Name: "NoTrack Malware (Quidsup)", URL: "https://gitlab.com/quidsup/notrack-blocklists/raw/master/notrack-malware.txt", Enabled: false, Category: "Security & Malware"},
	{Name: "Mandiant APT1 Report", URL: "https://bitbucket.org/ethanr/dns-blacklists/raw/8575c9f96e5b4a1308f2f12394abd86d0927a4a0/bad_lists/Mandiant_APT1_Report_Appendix_D.txt", Enabled: false, Category: "Security & Malware"},
	{Name: "URLHaus Filter (Curben)", URL: "https://gitlab.com/curben/urlhaus-filter/raw/master/urlhaus-filter-hosts.txt", Enabled: false, Category: "Security & Malware", IsRecommended: true},
	{Name: "AntiMalwareHosts (DandelionSprout)", URL: "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt", Enabled: false, Category: "Security & Malware"},
	{Name: "Spam404 Main Blacklist", URL: "https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt", Enabled: false, Category: "Security & Malware"},
	{Name: "CERT.PL (Dangerous Websites - DNS4EU Partner)", URL: "https://hole.cert.pl/domains/v2/domains_hosts.txt", Enabled: false, Category: "Security & Malware"},

	// --- Specialized & Content ---
	{Name: "HaGeZi Gambling", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/gambling.txt", Enabled: false, Category: "Specialized & Content"},
	{Name: "OISD NSFW (Adult)", URL: "https://nsfw.oisd.nl", Enabled: false, Category: "Specialized & Content"},
	{Name: "AdGuard Social Media Filter", URL: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_4.txt", Enabled: false, Category: "Specialized & Content"},
	{Name: "Steven Black (Porn/Gambling/FakeNews)", URL: "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn/hosts", Enabled: false, Category: "Specialized & Content"},
	{Name: "Dandelion Sprout's Game Console List", URL: "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/GameConsoleAdblockList.txt", Enabled: false, Category: "Specialized & Content"},
	{Name: "Sunshine Youtube Blocking", URL: "https://www.sunshine.it/blacklist.txt", Enabled: false, Category: "Specialized & Content"},
	{Name: "Smart-TV Blocklist (Perflyst)", URL: "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV-AGH.txt", Enabled: false, Category: "Specialized & Content"},
	{Name: "Game Console Adblock (DandelionSprout)", URL: "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/GameConsoleAdblockList.txt", Enabled: false, Category: "Specialized & Content"},

	// --- Regional & Languages ---
	{Name: "AdGuard German Filter", URL: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_6.txt", Enabled: false, Category: "Regional & Languages", IsRecommended: true},
	{Name: "KADhost (German Blocklist)", URL: "https://raw.githubusercontent.com/FiltersHeroes/KADhosts/master/KADhosts.txt", Enabled: false, Category: "Regional & Languages", IsRecommended: true},
	{Name: "hostsVN", URL: "https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts", Enabled: false, Category: "Regional & Languages"},
	{Name: "German Websites Ad", URL: "https://raw.githubusercontent.com/deathbybandaid/piholeparser/master/Subscribable-Lists/CountryCodesLists/Germany.txt", Enabled: false, Category: "Regional & Languages"},
	{Name: "AdGuard German Blocklist Optimized", URL: "https://filters.adtidy.org/extension/ublock/filters/6_optimized.txt", Enabled: false, Category: "Regional & Languages", IsRecommended: true},

	// --- Misc & Extra ---
	{Name: "FaserF Other", URL: "https://raw.githubusercontent.com/FaserF/piholeblockinglists/master/other.txt", Enabled: false, Category: "Misc & Extra"},
	{Name: "iOS Ads", URL: "https://raw.githubusercontent.com/BlackJack8/iOSAdblockList/master/Hosts.txt", Enabled: false, Category: "Misc & Extra", IsRecommended: true},
}

var DefaultAllowlists = []List{
	{Name: "ShieldDNS Official Allowlist", URL: "https://raw.githubusercontent.com/FaserF/ShieldDNS/main/official/allowlists/default.txt", Enabled: true, Category: "Official", IsRecommended: true},
	{Name: "FaserF Whitelist", URL: "https://raw.githubusercontent.com/FaserF/adguardhome_lists/master/whitelist", Enabled: true, Category: "Official", IsRecommended: true},
	{Name: "hl2guide", URL: "https://raw.githubusercontent.com/hl2guide/Filterlist-for-AdGuard/master/filter_whitelist.txt", Enabled: false, Category: "Misc & Extra"},
	{Name: "Regex Whitelist", URL: "https://raw.githubusercontent.com/mmotti/pihole-regex/master/whitelist.list", Enabled: false, Category: "Privacy & Tracking"},
	{Name: "AnudeepND", URL: "https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/whitelist.txt", Enabled: false, Category: "General Blocking", IsRecommended: true},
	{Name: "Optional", URL: "https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/optional-list.txt", Enabled: false, Category: "General Blocking"},
	{Name: "Referral", URL: "https://raw.githubusercontent.com/anudeepND/whitelist/master/domains/referral-sites.txt", Enabled: false, Category: "General Blocking", IsRecommended: true},
	{Name: "ookangzheng whitelist", URL: "https://raw.githubusercontent.com/ookangzheng/blahdns/master/hosts/whitelist.txt", Enabled: false, Category: "Misc & Extra"},
	{Name: "FaserF Whitelist Autopilot", URL: "https://raw.githubusercontent.com/FaserF/adguardhome_lists/master/whitelist_ms_autopilot", Enabled: false, Category: "Official", IsRecommended: true},
}

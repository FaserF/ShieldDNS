# ShieldDNS Mobile Setup Help

This guide provides detailed instructions and addresses common questions for setting up ShieldDNS on your mobile devices.

## iOS (iPhone / iPad) - Configuration Profile

When you download the ShieldDNS configuration profile on iOS, you might see a warning that the profile is **"Not Signed"**.

### Why is it not signed?
To provide you with a personalized experience, ShieldDNS generates this configuration profile **on the fly** for your specific domain name. Signing a profile requires a certificate from a trusted authority (like Apple), which is not feasible for dynamically generated local profiles since each installation uses a different domain.

### Is it safe?
**Yes.** Since you are the owner of this ShieldDNS server (or trust its administrator), it is perfectly safe to install. This profile only contains the DNS settings (DoT - DNS over TLS) to point your device to this server. It does not install any other software or monitor your other traffic.

### How to Install:
1.  **Download**: Click the "Download Config Profile" button on the ShieldDNS home page.
2.  **Approve**: A popup will say "This website is trying to download a configuration profile. Do you want to allow this?". Tap **Allow**.
3.  **Settings**: Open your iPhone/iPad **Settings** app.
4.  **Profile**: Tap on the new **"Profile Downloaded"** entry at the top (or go to General &rarr; VPN & Device Management).
5.  **Install**: Tap **Install** in the top right corner. You will need to enter your passcode and confirm a few times (ignoring the "Unsigned" warning).
6.  **Verify**: Once installed, your device will securely use ShieldDNS for all naming resolutions.

---

## Android - Private DNS

Android natively supports "Private DNS" (DNS-over-TLS) to encrypt your queries natively at the OS level. The settings menu varies slightly depending on your device manufacturer (current as of 2026).

### Google Pixel (Android 15 / 16+)
1.  **Open Settings**: Go to your device **Settings**.
2.  **Network**: Tap on **Network & internet**.
3.  **Private DNS**: Scroll down and tap on **Private DNS** (you no longer need to check under "Advanced").
4.  **Configure**: Select **Private DNS provider hostname**.
5.  **Enter Hostname**: Type in your ShieldDNS domain name (e.g., `dns.mydomain.de`).
6.  **Save**: Tap **Save**. Your Pixel will verify the connection and show the active hostname underneath the setting.

### Samsung Galaxy (OneUI 7 / 8+)
1.  **Open Settings**: Go to your device **Settings**.
2.  **Connections**: Tap on **Connections**.
3.  **More Settings**: Scroll down to the bottom and tap on **More connection settings**.
4.  **Private DNS**: Tap on **Private DNS**.
5.  **Configure**: Select **Private DNS provider hostname**.
6.  **Enter Hostname**: Type in your ShieldDNS domain name (e.g., `dns.mydomain.de`).
7.  **Save**: Tap **Save**.

### Other Android Devices
1.  **Search Settings**: Open **Settings** and tap the **Search** icon (magnifying glass) at the top.
2.  **Search**: Type `Private DNS` and tap the highlighted search result.
3.  **Configure**: Select **Private DNS provider hostname**.
4.  **Enter Hostname**: Type in your ShieldDNS domain name (e.g., `dns.mydomain.de`) and save.

### Advanced Android Setup (DoQ / DoH3)
While standard "Private DNS" uses DoT, you can use specialized apps for even better performance and DNS-over-QUIC:
1.  **Google Intra**: Install [Intra](https://play.google.com/store/apps/details?id=app.intra) and enter your DoH URL (e.g. `https://dns.mydomain.de/dns-query`).
2.  **AdGuard**: Use AdGuard for Android for system-wide protection with DoQ support (`quic://dns.mydomain.de:853`).

---

## macOS 14 (Sonoma) and later

Apple now supports encrypted DNS natively in macOS. You can install the same Configuration Profile used for iOS to easily set up your Mac.

1.  **Download Profile**: Open Safari or any browser, go to your ShieldDNS home page, and click **Download Config Profile**.
2.  **Open Settings**: Open **System Settings**.
3.  **Navigate to Profiles**: Go to **Privacy & Security** &rarr; **Profiles** (scroll down to the "Others" section at the bottom).
4.  **Install**: Double-click the downloaded ShieldDNS profile and click **Install**.
5.  **Confirm**: You will need to enter your Mac password.
*Note: The "Not Signed" warning is completely normal for auto-generated local profiles.*

---

## Windows 11 (Native DoH)

Windows 11 natively supports DNS over HTTPS (DoH) at the OS level, meaning all your apps will automatically use encrypted DNS.

1.  **Open Settings**: Go to **Settings** &rarr; **Network & internet**.
2.  **Select Connection**: Click on **Wi-Fi** or **Ethernet** (whichever you are currently using), then click on your network properties (or **Hardware properties**).
3.  **Edit DNS**: Look for "DNS server assignment", click the **Edit** button next to it, and change it to **Manual**.
4.  **Enable IPv4**: Toggle the IPv4 switch to 'On'.
5.  **Set IP**: Enter the IP address of your ShieldDNS server in the **Preferred DNS** field.
6.  **Enable DoH**: Set "DNS over HTTPS" to **On (manual template)**.
7.  **Enter Template**: In the new "DoH template" input box that appears, enter your secure endpoint URL:
    `https://YOUR-SHIELDDNS-DOMAIN/dns-query` (e.g. `https://dns.mydomain.de/dns-query`)
8.  **Save**: Click **Save**. Windows will now securely route your DNS through ShieldDNS.

---

## Troubleshooting

### "No internet connection" after setup
-   Ensure your ShieldDNS server is reachable from the internet on port **853 (DoT)**.
-   Check your firewall (iptables) to ensure port 853 is open.
-   Verify your SSL certificates are valid and not expired.

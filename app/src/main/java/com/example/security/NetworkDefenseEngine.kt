package com.example.security

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.NetworkCapabilities
import android.net.wifi.WifiInfo
import android.net.wifi.WifiManager
import android.os.Build
import com.example.data.db.TrustedNetworkEntity
import java.io.File
import java.net.Inet4Address
import java.net.NetworkInterface

data class ArpEntry(
    val ipAddress: String,
    val macAddress: String,
    val device: String
)

data class NetworkAnomaly(
    val category: String, // SNIFFING_ALERT or WIRELESS_SPOOFING
    val severity: String, // CRITICAL, HIGH, MEDIUM
    val title: String,
    val source: String,
    val target: String,
    val details: String
)

data class NetworkDefenseSnapshot(
    val transportType: String = "Checking...",
    val isInternetValidated: Boolean = true,
    val ssidLabel: String = "Not on Wi-Fi",
    val bssidLabel: String = "N/A",
    val wifiSecurity: String = "N/A",
    val gatewayIp: String = "N/A",
    val gatewayMac: String = "N/A",
    val dnsServers: List<String> = emptyList(),
    val isPrivateDnsActive: Boolean = false,
    val arpEntryCount: Int = 0,
    val activeInterfaces: List<String> = emptyList(),
    val anomalies: List<NetworkAnomaly> = emptyList(),
    val lastAuditedAt: Long = 0L
)

object NetworkDefenseEngine {

    fun inspectLiveNetwork(
        context: Context,
        previousBaseline: TrustedNetworkEntity?
    ): Pair<NetworkDefenseSnapshot, TrustedNetworkEntity?> {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val activeNetwork = cm.activeNetwork
        val caps = activeNetwork?.let { cm.getNetworkCapabilities(it) }
        val linkProps = activeNetwork?.let { cm.getLinkProperties(it) }

        val transport = when {
            caps == null -> "Disconnected"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "Wi-Fi"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "Cellular"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "Ethernet"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> "VPN + Active Link"
            else -> "Other Network"
        }

        val isValidated = caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) ?: false
        val hasCaptivePortal = caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL) ?: false

        // Resolve Wi-Fi details from ConnectivityManager TransportInfo (API 29+) or WifiManager
        val wifiInfo: WifiInfo? = extractWifiInfo(context, caps)
        val rawSsid = wifiInfo?.ssid?.trim('"')?.takeIf { it.isNotBlank() && it != "<unknown ssid>" }
        val rawBssid = wifiInfo?.bssid?.lowercase()?.takeIf { it.isNotBlank() && it != "02:00:00:00:00:00" }
        val securityLabel = resolveWifiSecurityLabel(wifiInfo, caps)

        val gatewayIp = resolveGatewayIp(linkProps) ?: "N/A"
        val dnsList = linkProps?.dnsServers?.mapNotNull { it.hostAddress } ?: emptyList()
        val privateDnsActive = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            linkProps?.isPrivateDnsActive == true
        } else {
            false
        }

        // Read ARP table (best effort on Android OS)
        val arpEntries = readProcNetArp()
        val gatewayMac = if (gatewayIp != "N/A") {
            arpEntries.firstOrNull { it.ipAddress == gatewayIp }?.macAddress ?: "Unavailable"
        } else {
            "N/A"
        }

        val activeIfaces = listActiveNetworkInterfaces()

        val anomalies = mutableListOf<NetworkAnomaly>()

        // 1. Sniffing Detection: Duplicate MAC in ARP table (ARP cache poisoning / MITM sniffing)
        anomalies.addAll(detectArpSpoofingAnomalies(arpEntries))

        // 2. Sniffing Detection: Unexpected capture / promiscuous / secondary tunnel interfaces
        anomalies.addAll(detectSuspiciousCaptureInterfaces(activeIfaces))

        // 3. Wireless Spoofing Detection: Open/weak Wi-Fi, captive portal hijack, or BSSID/Gateway MAC shift
        anomalies.addAll(
            detectWirelessSpoofingAnomalies(
                transport = transport,
                ssid = rawSsid,
                bssid = rawBssid,
                security = securityLabel,
                gatewayIp = gatewayIp,
                gatewayMac = gatewayMac,
                hasCaptivePortal = hasCaptivePortal,
                dnsServers = dnsList,
                privateDnsActive = privateDnsActive,
                baseline = previousBaseline
            )
        )

        val baselineKey = rawSsid ?: if (gatewayIp != "N/A") "gw_$gatewayIp" else null
        val newBaseline = if (baselineKey != null) {
            TrustedNetworkEntity(
                networkKey = baselineKey,
                lastBssid = rawBssid ?: previousBaseline?.lastBssid.orEmpty(),
                lastGatewayIp = gatewayIp,
                lastGatewayMac = if (gatewayMac != "Unavailable" && gatewayMac != "N/A") gatewayMac else previousBaseline?.lastGatewayMac.orEmpty(),
                lastSecurityType = securityLabel,
                lastSeenAt = System.currentTimeMillis()
            )
        } else null

        val snapshot = NetworkDefenseSnapshot(
            transportType = transport,
            isInternetValidated = isValidated,
            ssidLabel = rawSsid ?: if (transport == "Wi-Fi") "Protected SSID (Location Masked)" else transport,
            bssidLabel = rawBssid ?: "Hardware Masked",
            wifiSecurity = securityLabel,
            gatewayIp = gatewayIp,
            gatewayMac = gatewayMac,
            dnsServers = dnsList,
            isPrivateDnsActive = privateDnsActive,
            arpEntryCount = arpEntries.size,
            activeInterfaces = activeIfaces,
            anomalies = anomalies,
            lastAuditedAt = System.currentTimeMillis()
        )
        return snapshot to newBaseline
    }

    /**
     * Parses `/proc/net/arp` lines into structured [ArpEntry] records.
     */
    fun parseArpTableLines(lines: List<String>): List<ArpEntry> {
        val entries = mutableListOf<ArpEntry>()
        for (line in lines.drop(1)) { // skip header
            val cols = line.trim().split(Regex("\\s+"))
            if (cols.size >= 6) {
                val ip = cols[0]
                val mac = cols[3].lowercase()
                val dev = cols[5]
                if (mac != "00:00:00:00:00:00" && mac.contains(':')) {
                    entries.add(ArpEntry(ipAddress = ip, macAddress = mac, device = dev))
                }
            }
        }
        return entries
    }

    fun detectArpSpoofingAnomalies(entries: List<ArpEntry>): List<NetworkAnomaly> {
        if (entries.isEmpty()) return emptyList()
        val alerts = mutableListOf<NetworkAnomaly>()
        val byMac = entries.groupBy { it.macAddress }
        for ((mac, hosts) in byMac) {
            val distinctIps = hosts.map { it.ipAddress }.distinct()
            if (distinctIps.size > 1) {
                alerts.add(
                    NetworkAnomaly(
                        category = "SNIFFING_ALERT",
                        severity = "CRITICAL",
                        title = "Local Network Issue: ARP Conflict Detected",
                        source = mac,
                        target = distinctIps.joinToString(", "),
                        details = "Multiple IPs (${distinctIps.joinToString(", ")}) share MAC $mac in ARP cache — indicates a local network conflict."
                    )
                )
            }
        }
        return alerts
    }

    fun detectSuspiciousCaptureInterfaces(interfaces: List<String>): List<NetworkAnomaly> {
        val alerts = mutableListOf<NetworkAnomaly>()
        val extraTap = interfaces.filter { name ->
            val lower = name.lowercase()
            lower.startsWith("tap") || lower.startsWith("pcap") || lower.startsWith("mon")
        }
        if (extraTap.isNotEmpty()) {
            alerts.add(
                NetworkAnomaly(
                    category = "SNIFFING_ALERT",
                    severity = "HIGH",
                    title = "Local Network Issue: Virtual TAP Interface",
                    source = extraTap.joinToString(", "),
                    target = "Local Network Stack",
                    details = "Detected non-standard capture/tap interface(s): ${extraTap.joinToString(", ")}."
                )
            )
        }
        return alerts
    }

    fun detectWirelessSpoofingAnomalies(
        transport: String,
        ssid: String?,
        bssid: String?,
        security: String,
        gatewayIp: String,
        gatewayMac: String,
        hasCaptivePortal: Boolean,
        dnsServers: List<String>,
        privateDnsActive: Boolean,
        baseline: TrustedNetworkEntity?
    ): List<NetworkAnomaly> {
        val alerts = mutableListOf<NetworkAnomaly>()

        if (transport == "Wi-Fi") {
            if (security.contains("Open", ignoreCase = true) || security.contains("WEP", ignoreCase = true)) {
                alerts.add(
                    NetworkAnomaly(
                        category = "WIRELESS_SPOOFING",
                        severity = "HIGH",
                        title = "Local Network Issue: Unencrypted Wi-Fi ($security)",
                        source = ssid ?: "Wi-Fi AP",
                        target = bssid ?: "Wireless Link",
                        details = "Connected over $security without strong link encryption on this local wireless network."
                    )
                )
            }
            if (hasCaptivePortal) {
                alerts.add(
                    NetworkAnomaly(
                        category = "WIRELESS_SPOOFING",
                        severity = "MEDIUM",
                        title = "Local Network Issue: Captive Portal Redirect",
                        source = ssid ?: "Wi-Fi Gateway",
                        target = gatewayIp,
                        details = "Local network is redirecting HTTP/DNS requests via a captive portal."
                    )
                )
            }
        }

        if (baseline != null) {
            if (!bssid.isNullOrBlank() && baseline.lastBssid.isNotBlank() &&
                !bssid.equals(baseline.lastBssid, ignoreCase = true)
            ) {
                alerts.add(
                    NetworkAnomaly(
                        category = "WIRELESS_SPOOFING",
                        severity = "CRITICAL",
                        title = "Local Network Issue: Wi-Fi AP BSSID Changed",
                        source = bssid,
                        target = ssid ?: baseline.networkKey,
                        details = "Local network '${baseline.networkKey}' changed AP BSSID from ${baseline.lastBssid} to $bssid."
                    )
                )
            }
            if (gatewayMac != "Unavailable" && gatewayMac != "N/A" &&
                baseline.lastGatewayMac.isNotBlank() &&
                !gatewayMac.equals(baseline.lastGatewayMac, ignoreCase = true)
            ) {
                alerts.add(
                    NetworkAnomaly(
                        category = "SNIFFING_ALERT",
                        severity = "CRITICAL",
                        title = "Local Network Issue: Gateway MAC Changed",
                        source = gatewayMac,
                        target = gatewayIp,
                        details = "Local gateway $gatewayIp MAC shifted from ${baseline.lastGatewayMac} to $gatewayMac."
                    )
                )
            }
            if (baseline.lastSecurityType.contains("WPA", ignoreCase = true) &&
                security.contains("Open", ignoreCase = true)
            ) {
                alerts.add(
                    NetworkAnomaly(
                        category = "WIRELESS_SPOOFING",
                        severity = "CRITICAL",
                        title = "Local Network Issue: Wi-Fi Encryption Downgrade",
                        source = ssid ?: baseline.networkKey,
                        target = security,
                        details = "Previously encrypted local network (${baseline.lastSecurityType}) downgraded to $security."
                    )
                )
            }
        }

        if (transport == "Wi-Fi" && !privateDnsActive && dnsServers.any { it.startsWith("192.168.") || it.startsWith("10.") }) {
            alerts.add(
                NetworkAnomaly(
                    category = "SNIFFING_ALERT",
                    severity = "MEDIUM",
                    title = "Unencrypted Local LAN DNS Resolver",
                    source = dnsServers.firstOrNull() ?: gatewayIp,
                    target = "UDP/53 Plain DNS",
                    details = "DNS queries are routed to local LAN resolver (${dnsServers.joinToString(", ")}) without Private DNS encryption; enable VPN DNS filtering."
                )
            )
        }

        return alerts
    }

    private fun readProcNetArp(): List<ArpEntry> {
        return try {
            val file = File("/proc/net/arp")
            if (!file.exists() || !file.canRead()) return emptyList()
            parseArpTableLines(file.readLines())
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun extractWifiInfo(context: Context, caps: NetworkCapabilities?): WifiInfo? {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val info = caps?.transportInfo
            if (info is WifiInfo) return info
        }
        return try {
            val wm = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
            @Suppress("DEPRECATION")
            wm?.connectionInfo
        } catch (_: Exception) {
            null
        }
    }

    private fun resolveWifiSecurityLabel(wifiInfo: WifiInfo?, caps: NetworkCapabilities?): String {
        if (caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) != true) return "N/A"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && wifiInfo != null) {
            return when (wifiInfo.currentSecurityType) {
                WifiInfo.SECURITY_TYPE_OPEN -> "Open (Unencrypted)"
                WifiInfo.SECURITY_TYPE_WEP -> "WEP (Weak)"
                WifiInfo.SECURITY_TYPE_PSK -> "WPA2-PSK"
                WifiInfo.SECURITY_TYPE_EAP -> "WPA2/WPA3-Enterprise"
                WifiInfo.SECURITY_TYPE_SAE -> "WPA3-SAE"
                WifiInfo.SECURITY_TYPE_OWE -> "OWE (Enhanced Open)"
                else -> "Encrypted Wi-Fi"
            }
        }
        return "Encrypted Wi-Fi"
    }

    private fun resolveGatewayIp(linkProps: LinkProperties?): String? {
        val routes = linkProps?.routes ?: return null
        for (route in routes) {
            if (route.isDefaultRoute && route.gateway is Inet4Address) {
                return route.gateway?.hostAddress
            }
        }
        return null
    }

    private fun listActiveNetworkInterfaces(): List<String> {
        return try {
            val list = mutableListOf<String>()
            val ifaces = NetworkInterface.getNetworkInterfaces() ?: return emptyList()
            for (intf in ifaces) {
                if (intf.isUp && !intf.isLoopback) {
                    list.add(intf.name)
                }
            }
            list
        } catch (_: Exception) {
            emptyList()
        }
    }
}

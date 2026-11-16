package com.example.data.repository

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.TrafficStats
import com.example.data.db.AppFirewallRuleEntity
import com.example.data.db.AppPolicy
import com.example.data.db.BlockedDomainEntity
import com.example.data.db.EventCategory
import com.example.data.db.NetShieldDao
import com.example.data.db.PortRuleEntity
import com.example.data.db.ScanReportEntity
import com.example.data.db.SecurityEventEntity
import com.example.data.db.ThreatSeverity
import com.example.security.NetworkDefenseEngine
import com.example.security.NetworkDefenseSnapshot
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.withContext
import java.net.Inet4Address
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.Socket

class NetShieldRepository(
    private val context: Context,
    private val dao: NetShieldDao
) {
    val securityEvents: Flow<List<SecurityEventEntity>> = dao.observeSecurityEvents()
    val totalBlockedCount: Flow<Int> = dao.observeTotalBlockedCount()
    val sniffSpoofCount: Flow<Int> = dao.observeSniffSpoofCount()
    val portRules: Flow<List<PortRuleEntity>> = dao.observePortRules()
    val appRules: Flow<List<AppFirewallRuleEntity>> = dao.observeAppRules()
    val blockedDomains: Flow<List<BlockedDomainEntity>> = dao.observeBlockedDomains()
    val scanReports: Flow<List<ScanReportEntity>> = dao.observeScanReports()

    suspend fun ensureSeeded() {
        dao.deleteLegacySimulatedPorts()
        dao.deletePlaceholderDomains()

        val existingPorts = dao.getAllPortRulesOnce()
        if (existingPorts.isEmpty()) {
            dao.upsertPortRules(defaultPortRules())
        } else {
            // Ensure internet-critical ports (53, 80, 443) are never left offline blocking internet access
            val internetPorts = existingPorts.filter { it.port in setOf(53, 80, 443) && it.isMarkedOffline }
            if (internetPorts.isNotEmpty()) {
                internetPorts.forEach { dao.setPortOffline(it.port, false) }
            }
        }
        if (dao.getEnabledBlockedDomainsOnce().isEmpty()) {
            dao.upsertBlockedDomains(defaultBlockedDomains())
        }
    }

    /**
     * Performs a real non-blocking local TCP socket probe across localhost and active local interfaces
     * to identify open listening ports on the device while keeping outbound internet ports (53/80/443) active.
     */
    suspend fun scanDevicePorts(autoLockOpen: Boolean): List<PortRuleEntity> = withContext(Dispatchers.IO) {
        val currentRules = dao.getAllPortRulesOnce().ifEmpty { defaultPortRules() }
        val localAddresses = resolveLocalIpv4Addresses()
        val now = System.currentTimeMillis()
        var newlyFoundOpen = 0

        val updated = currentRules.map { rule ->
            val isListening = localAddresses.any { ip -> isTcpPortOpen(ip, rule.port, 85) }
            if (isListening) newlyFoundOpen++
            val offline = when {
                rule.port in setOf(53, 80, 443) -> false // Keep internet access unblocked
                autoLockOpen && isListening -> true
                else -> rule.isMarkedOffline
            }
            rule.copy(
                isOpenDetected = isListening,
                isMarkedOffline = offline,
                lastScannedAt = now
            )
        }
        dao.upsertPortRules(updated)

        if (newlyFoundOpen > 0) {
            dao.insertEvent(
                SecurityEventEntity(
                    category = EventCategory.PORT_SCAN.name,
                    severity = ThreatSeverity.HIGH.name,
                    title = "Open Local Port(s) Audited",
                    source = localAddresses.firstOrNull() ?: "127.0.0.1",
                    target = "$newlyFoundOpen open listening socket(s)",
                    actionTaken = if (autoLockOpen) "MARKED OFFLINE" else "DETECTED",
                    details = "Probed ${localAddresses.joinToString(", ")}. Found $newlyFoundOpen open port(s); outbound internet ports (53/80/443) remain unrestricted."
                )
            )
        }
        updated
    }

    /**
     * Runs live network defense audit checking ARP cache for sniffing, Wi-Fi BSSID/security spoofing,
     * gateway MAC integrity, and DNS configuration. Logs real events only when an anomaly is detected.
     */
    suspend fun runNetworkDefenseAudit(
        checkSniffing: Boolean,
        checkWirelessSpoofing: Boolean
    ): NetworkDefenseSnapshot = withContext(Dispatchers.IO) {
        val baseline = dao.getTrustedNetwork(
            // Best-effort lookup; refined after snapshot resolves key
            "default"
        )
        val (firstPass, _) = NetworkDefenseEngine.inspectLiveNetwork(context, baseline)
        val key = firstPass.ssidLabel.takeIf {
            it != "Not on Wi-Fi" && it != "Protected SSID (Location Masked)"
        } ?: if (firstPass.gatewayIp != "N/A") "gw_${firstPass.gatewayIp}" else null
        val specificBaseline = key?.let { dao.getTrustedNetwork(it) }

        val (snapshot, newBaseline) = NetworkDefenseEngine.inspectLiveNetwork(context, specificBaseline)
        if (newBaseline != null) {
            dao.upsertTrustedNetwork(newBaseline)
        }

        val relevantAnomalies = snapshot.anomalies.filter { anomaly ->
            (checkSniffing && anomaly.category == EventCategory.SNIFFING_ALERT.name) ||
                (checkWirelessSpoofing && anomaly.category == EventCategory.WIRELESS_SPOOFING.name)
        }

        relevantAnomalies.forEach { anomaly ->
            dao.insertEvent(
                SecurityEventEntity(
                    category = anomaly.category,
                    severity = anomaly.severity,
                    title = anomaly.title,
                    source = anomaly.source,
                    target = anomaly.target,
                    actionTaken = "ALERT RAISED",
                    details = anomaly.details
                )
            )
        }

        snapshot.copy(anomalies = relevantAnomalies)
    }

    suspend fun setPortOffline(port: Int, offline: Boolean) {
        dao.setPortOffline(port, offline)
        dao.insertEvent(
            SecurityEventEntity(
                category = EventCategory.PORT_SCAN.name,
                severity = ThreatSeverity.INFO.name,
                title = if (offline) "Port $port Marked Offline" else "Port $port Online",
                source = "Port Guard",
                target = "Port $port",
                actionTaken = if (offline) "PORT OFFLINE" else "PORT ACTIVE",
                details = if (offline) {
                    "Service port $port is marked offline to external probes while normal internet traffic remains unrestricted."
                } else {
                    "Port $port returned to standard monitoring."
                }
            )
        )
    }

    suspend fun markServicePortsOffline() {
        dao.markServicePortsOffline()
        dao.insertEvent(
            SecurityEventEntity(
                category = EventCategory.PORT_SCAN.name,
                severity = ThreatSeverity.INFO.name,
                title = "Service Ports Marked Offline",
                source = "Port Guard",
                target = "Listening Service Ports",
                actionTaken = "PORTS OFFLINE • INTERNET ON",
                details = "All listening service ports marked offline while ports 53, 80, and 443 keep internet access active."
            )
        )
    }

    /**
     * Queries launcher-visible installed apps via Play-compliant <queries> filter and reads real TrafficStats.
     */
    suspend fun refreshInstalledApps() = withContext(Dispatchers.IO) {
        val pm = context.packageManager
        val launcherIntent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        val resolveInfos = pm.queryIntentActivities(launcherIntent, PackageManager.MATCH_ALL)
        val existingByPkg = dao.getAllAppRulesOnce().associateBy { it.packageName }

        val updated = resolveInfos
            .mapNotNull { it.activityInfo?.applicationInfo }
            .distinctBy { it.packageName }
            .filter { it.packageName != context.packageName }
            .map { appInfo ->
                val label = pm.getApplicationLabel(appInfo).toString()
                val rx = TrafficStats.getUidRxBytes(appInfo.uid).coerceAtLeast(0L)
                val tx = TrafficStats.getUidTxBytes(appInfo.uid).coerceAtLeast(0L)
                val existing = existingByPkg[appInfo.packageName]
                val suspiciousUpload = tx > 50 * 1024 && tx > (rx * 0.7)
                AppFirewallRuleEntity(
                    packageName = appInfo.packageName,
                    appName = label,
                    uid = appInfo.uid,
                    policy = existing?.policy ?: AppPolicy.ALLOW.name,
                    rxBytes = rx,
                    txBytes = tx,
                    backgroundAlertFlag = suspiciousUpload
                )
            }
        dao.upsertAppRules(updated)
    }

    suspend fun setAppPolicy(packageName: String, appName: String, policy: AppPolicy) {
        dao.updateAppPolicy(packageName, policy.name)
        dao.insertEvent(
            SecurityEventEntity(
                category = EventCategory.DATA_THEFT_APP.name,
                severity = if (policy == AppPolicy.ALLOW) ThreatSeverity.INFO.name else ThreatSeverity.MEDIUM.name,
                title = "App Policy Updated: $appName",
                source = packageName,
                target = "Network Control",
                actionTaken = policy.name.replace('_', ' '),
                details = "Updated $appName network rule to ${policy.name.replace('_', ' ')}."
            )
        )
    }

    suspend fun addCustomBlockedDomain(domain: String, category: String = "Custom Page Block") {
        val normalized = domain.trim().lowercase()
            .removePrefix("https://")
            .removePrefix("http://")
            .substringBefore('/')
            .substringBefore(':')
        if (normalized.isBlank() || !normalized.contains('.')) return
        dao.upsertBlockedDomain(
            BlockedDomainEntity(
                domain = normalized,
                category = category,
                isEnabled = true,
                isBuiltIn = false
            )
        )
    }

    suspend fun toggleDomain(domain: String, enabled: Boolean) {
        dao.setDomainEnabled(domain, enabled)
    }

    suspend fun removeCustomDomain(domain: String) {
        dao.deleteCustomDomain(domain)
    }

    suspend fun logEvent(event: SecurityEventEntity) {
        dao.insertEvent(event)
    }

    suspend fun clearEvents() {
        dao.clearEvents()
    }

    suspend fun saveScanReport(report: ScanReportEntity) {
        dao.insertScanReport(report)
    }

    suspend fun clearScanReports() {
        dao.clearScanReports()
    }

    private fun resolveLocalIpv4Addresses(): List<String> {
        val result = mutableSetOf("127.0.0.1")
        try {
            val interfaces = NetworkInterface.getNetworkInterfaces() ?: return result.toList()
            for (intf in interfaces) {
                if (!intf.isUp) continue
                for (addr in intf.inetAddresses) {
                    if (addr is Inet4Address && !addr.isLoopbackAddress) {
                        addr.hostAddress?.let { result.add(it) }
                    }
                }
            }
        } catch (_: Exception) {
        }
        return result.toList()
    }

    private fun isTcpPortOpen(host: String, port: Int, timeoutMs: Int): Boolean {
        return try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(host, port), timeoutMs)
                true
            }
        } catch (_: Exception) {
            false
        }
    }

    private fun defaultPortRules(): List<PortRuleEntity> = listOf(
        PortRuleEntity(21, "TCP", "FTP", "Unencrypted file transfer service", isMarkedOffline = true),
        PortRuleEntity(22, "TCP", "SSH", "Remote shell listener", isMarkedOffline = true),
        PortRuleEntity(23, "TCP", "Telnet", "Cleartext remote terminal", isMarkedOffline = true),
        PortRuleEntity(25, "TCP", "SMTP", "Local mail relay port", isMarkedOffline = true),
        PortRuleEntity(53, "UDP/TCP", "DNS", "Internet name resolution (kept online for web access)", isMarkedOffline = false),
        PortRuleEntity(80, "TCP", "HTTP", "Web browsing traffic (kept online for internet access)", isMarkedOffline = false),
        PortRuleEntity(135, "TCP", "MS-RPC", "Local network RPC probe target", isMarkedOffline = true),
        PortRuleEntity(137, "UDP", "NetBIOS-NS", "LAN name resolution & broadcast local network port", isMarkedOffline = true),
        PortRuleEntity(139, "TCP", "NetBIOS", "Legacy LAN share enumeration", isMarkedOffline = true),
        PortRuleEntity(443, "TCP", "HTTPS", "Encrypted web traffic (kept online for internet access)", isMarkedOffline = false),
        PortRuleEntity(445, "TCP", "SMB", "Local file-sharing listener", isMarkedOffline = true),
        PortRuleEntity(1433, "TCP", "MSSQL", "Database listener port", isMarkedOffline = true),
        PortRuleEntity(3306, "TCP", "MySQL", "Database listener port", isMarkedOffline = true),
        PortRuleEntity(3389, "TCP", "RDP", "Remote desktop listener", isMarkedOffline = true),
        PortRuleEntity(5355, "UDP", "LLMNR", "Local multicast name resolution port", isMarkedOffline = true),
        PortRuleEntity(5555, "TCP", "ADB-over-WiFi", "Wireless Android debug bridge exposure", isMarkedOffline = true),
        PortRuleEntity(5900, "TCP", "VNC", "Remote display server listener", isMarkedOffline = true),
        PortRuleEntity(8080, "TCP", "HTTP-Alt", "Local proxy / dev server listener", isMarkedOffline = true)
    )

    private fun defaultBlockedDomains(): List<BlockedDomainEntity> = listOf(
        BlockedDomainEntity("doubleclick.net", "Adware & Cross-App Tracker", isEnabled = true, isBuiltIn = true),
        BlockedDomainEntity("ads.yahoo.com", "Adware & Behavioral Tracker", isEnabled = true, isBuiltIn = true),
        BlockedDomainEntity("analytics.tiktok.com", "Background Telemetry", isEnabled = true, isBuiltIn = true),
        BlockedDomainEntity("app-measurement.com", "Background Analytics", isEnabled = true, isBuiltIn = true),
        BlockedDomainEntity("coinhive.com", "Browser Cryptominer", isEnabled = true, isBuiltIn = true),
        BlockedDomainEntity("cryptoloot.pro", "Web Cryptominer", isEnabled = true, isBuiltIn = true),
        BlockedDomainEntity("telemetry.sdk.inmobi.com", "Background Data Tracker", isEnabled = true, isBuiltIn = true),
        BlockedDomainEntity("pixel.facebook.com", "Tracking Pixel", isEnabled = true, isBuiltIn = true)
    )
}

package com.example.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.TrafficStats
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import com.example.MainActivity
import com.example.R
import com.example.data.db.AppPolicy
import com.example.data.db.EventCategory
import com.example.data.db.NetShieldDatabase
import com.example.data.db.SecurityEventEntity
import com.example.data.db.ThreatSeverity
import com.example.data.prefs.ShieldPreferences
import com.example.security.NetworkDefenseEngine
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress

data class VpnTunnelStatus(
    val isRunning: Boolean = false,
    val tunnelAddress: String = "10.8.0.2",
    val dnsServer: String = "10.8.0.1 -> Upstream DNS",
    val packetsInspected: Long = 0L,
    val packetsBlocked: Long = 0L,
    val activeSinceMillis: Long = 0L
)

class NetShieldVpnService : VpnService() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var vpnInterface: ParcelFileDescriptor? = null
    private var packetJob: Job? = null
    private var networkWatchJob: Job? = null

    private lateinit var database: NetShieldDatabase
    private lateinit var preferences: ShieldPreferences

    override fun onCreate() {
        super.onCreate()
        database = NetShieldDatabase.getInstance(applicationContext)
        preferences = ShieldPreferences(applicationContext)
        createNotificationChannels()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP_VPN) {
            stopVpnTunnel()
            return START_NOT_STICKY
        }
        startForegroundNotification()
        startVpnTunnel()
        return START_STICKY
    }

    private fun startForegroundNotification() {
        val openAppIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val stopIntent = PendingIntent.getService(
            this,
            1,
            Intent(this, NetShieldVpnService::class.java).apply { action = ACTION_STOP_VPN },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val notification: Notification = NotificationCompat.Builder(this, CHANNEL_VPN)
            .setContentTitle(getString(R.string.vpn_active_title))
            .setContentText(getString(R.string.vpn_active_subtitle))
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setOngoing(true)
            .setContentIntent(openAppIntent)
            .addAction(0, getString(R.string.action_stop_vpn), stopIntent)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun startVpnTunnel() {
        if (vpnInterface != null) return
        try {
            // Only route our local DNS filter endpoint (10.8.0.1/32) so normal internet traffic
            // continues seamlessly at native speed without breaking user internet access.
            val builder = Builder()
                .setSession("NETWALL Network Control")
                .setMtu(1500)
                .addAddress("10.8.0.2", 32)
                .addDnsServer("10.8.0.1")
                .addRoute("10.8.0.1", 32)
                .addDisallowedApplication(packageName)

            val tun = builder.establish()
            if (tun == null) {
                stopVpnTunnel()
                return
            }
            vpnInterface = tun
            _status.value = VpnTunnelStatus(
                isRunning = true,
                activeSinceMillis = System.currentTimeMillis()
            )

            serviceScope.launch {
                database.netShieldDao().insertEvent(
                    SecurityEventEntity(
                        category = EventCategory.VPN_FIREWALL.name,
                        severity = ThreatSeverity.INFO.name,
                        title = "VPN + Firewall Engaged",
                        source = "10.8.0.2",
                        target = "Internet Open • Service Ports Offline",
                        actionTaken = "ACTIVE",
                        details = "Local DNS filter and local network issue monitor active while keeping internet access unrestricted."
                    )
                )
            }

            packetJob = serviceScope.launch { runPacketLoop(tun) }
            networkWatchJob = serviceScope.launch { runNetworkIntegrityWatcher() }
        } catch (_: Exception) {
            stopVpnTunnel()
        }
    }

    private suspend fun runPacketLoop(tun: ParcelFileDescriptor) {
        val input = FileInputStream(tun.fileDescriptor)
        val output = FileOutputStream(tun.fileDescriptor)
        val packetBuf = ByteArray(32767)

        while (serviceScope.isActive && vpnInterface != null) {
            val len = try {
                input.read(packetBuf)
            } catch (_: Exception) {
                break
            }
            if (len <= 0) {
                delay(15)
                continue
            }

            val parsed = PacketParser.parseIpv4(packetBuf, len) ?: continue
            val current = _status.value
            _status.value = current.copy(packetsInspected = current.packetsInspected + 1)

            val settings = preferences.settingsFlow.first()
            val offlinePorts = database.netShieldDao().getAllPortRulesOnce()
                .filter { it.isMarkedOffline && it.port !in setOf(53, 80, 443) }
                .map { it.port }
                .toSet()

            // Identify originating app UID on API 29+
            val ownerUid = resolveOwnerUid(parsed)
            val appRule = if (ownerUid > 0) {
                database.netShieldDao().getAllAppRulesOnce().firstOrNull { it.uid == ownerUid }
            } else null

            // Check App Firewall BLOCK_ALL
            if (appRule != null && appRule.policy == AppPolicy.BLOCK_ALL.name) {
                recordBlockedPacket(
                    category = EventCategory.DATA_THEFT_APP.name,
                    severity = ThreatSeverity.HIGH.name,
                    title = "Blocked App Connection: ${appRule.appName}",
                    source = appRule.packageName,
                    target = "${parsed.dstIp}:${parsed.dstPort}",
                    action = "DROPPED BY FIREWALL",
                    details = "Blocked outbound request from restricted app ${appRule.appName}."
                )
                continue
            }

            // Drop probes hitting service ports marked offline (never drops 53/80/443 internet access)
            if (settings.autoLockOpenPorts && parsed.dstPort in offlinePorts) {
                database.netShieldDao().incrementPortProbeCount(parsed.dstPort)
                recordBlockedPacket(
                    category = EventCategory.PORT_SCAN.name,
                    severity = ThreatSeverity.MEDIUM.name,
                    title = "Offline Port Probe Dropped (:${parsed.dstPort})",
                    source = parsed.srcIp,
                    target = "${parsed.dstIp}:${parsed.dstPort}",
                    action = "PORT KEPT OFFLINE",
                    details = "Traffic targeting offline service port ${parsed.dstPort} was silently dropped without impacting internet access."
                )
                continue
            }

            // Handle DNS Queries (UDP Port 53)
            if (parsed.protocol == 17 && parsed.dstPort == 53 && parsed.payloadLength > 12) {
                val domain = PacketParser.extractDnsQueryDomain(packetBuf, parsed.payloadOffset, parsed.payloadLength)
                val enabledBlocklist = database.netShieldDao().getEnabledBlockedDomainsOnce()
                val matchedDomain = if (domain != null && settings.maliciousPageBlocker) {
                    enabledBlocklist.firstOrNull { blocked ->
                        domain == blocked.domain || domain.endsWith(".${blocked.domain}")
                    }
                } else null

                if (matchedDomain != null && settings.dnsSinkholeEnabled) {
                    database.netShieldDao().incrementDomainHit(matchedDomain.domain)
                    val nxPayload = PacketParser.buildDnsNxDomainPayload(packetBuf, parsed.payloadOffset, parsed.payloadLength)
                    val respPacket = PacketParser.buildIpv4UdpResponsePacket(packetBuf, parsed, nxPayload, nxPayload.size)
                    output.write(respPacket)
                    recordBlockedPacket(
                        category = EventCategory.MALICIOUS_PAGE.name,
                        severity = ThreatSeverity.HIGH.name,
                        title = "Blocked Tracker / Malicious Domain",
                        source = appRule?.appName ?: parsed.srcIp,
                        target = domain ?: matchedDomain.domain,
                        action = "DNS SINKHOLE",
                        details = "Filtered DNS lookup for '$domain' (${matchedDomain.category}) while keeping all other internet access open."
                    )
                } else {
                    // Always forward clean DNS queries to the active upstream DNS so internet stays fast & open
                    val upstream = resolveUpstreamDnsAddress()
                    forwardDnsUdp(packetBuf, parsed, upstream, output)
                }
            }
        }
    }

    private fun resolveUpstreamDnsAddress(): InetAddress {
        try {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            @Suppress("DEPRECATION")
            for (network in cm.allNetworks) {
                val caps = cm.getNetworkCapabilities(network) ?: continue
                if (caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN)) continue
                val lp = cm.getLinkProperties(network) ?: continue
                val v4Dns = lp.dnsServers.firstOrNull { it is Inet4Address }
                if (v4Dns != null) return v4Dns
            }
        } catch (_: Exception) {
        }
        return InetAddress.getByName("1.1.1.1")
    }

    private fun forwardDnsUdp(
        requestPacket: ByteArray,
        parsed: ParsedIpv4Packet,
        upstreamDns: InetAddress,
        tunOutput: FileOutputStream
    ) {
        var socket: DatagramSocket? = null
        try {
            socket = DatagramSocket()
            protect(socket)
            socket.soTimeout = 2500
            val queryData = ByteArray(parsed.payloadLength)
            System.arraycopy(requestPacket, parsed.payloadOffset, queryData, 0, parsed.payloadLength)
            socket.send(DatagramPacket(queryData, queryData.size, upstreamDns, 53))

            val respBuf = ByteArray(4096)
            val respDgram = DatagramPacket(respBuf, respBuf.size)
            socket.receive(respDgram)
            val ipResponse = PacketParser.buildIpv4UdpResponsePacket(
                requestPacket = requestPacket,
                req = parsed,
                udpPayload = respBuf,
                udpPayloadLen = respDgram.length
            )
            tunOutput.write(ipResponse)
        } catch (_: Exception) {
            // Fallback to secondary public resolver if primary link resolver timed out
            try {
                socket?.close()
                socket = DatagramSocket()
                protect(socket)
                socket.soTimeout = 2500
                val queryData = ByteArray(parsed.payloadLength)
                System.arraycopy(requestPacket, parsed.payloadOffset, queryData, 0, parsed.payloadLength)
                socket.send(DatagramPacket(queryData, queryData.size, InetAddress.getByName("8.8.8.8"), 53))
                val respBuf = ByteArray(4096)
                val respDgram = DatagramPacket(respBuf, respBuf.size)
                socket.receive(respDgram)
                val ipResponse = PacketParser.buildIpv4UdpResponsePacket(
                    requestPacket = requestPacket,
                    req = parsed,
                    udpPayload = respBuf,
                    udpPayloadLen = respDgram.length
                )
                tunOutput.write(ipResponse)
            } catch (_: Exception) {
            }
        } finally {
            socket?.close()
        }
    }

    /**
     * Periodically inspects real ARP cache, Wi-Fi BSSID/security, gateway MAC, and per-app TrafficStats
     * while VPN is active, logging only genuine detected anomalies.
     */
    private suspend fun runNetworkIntegrityWatcher() {
        val lastTxByUid = mutableMapOf<Int, Long>()
        var lastAlertKey: String? = null

        while (serviceScope.isActive && vpnInterface != null) {
            delay(8000)
            val settings = preferences.settingsFlow.first()

            if (settings.sniffingDetectionEnabled || settings.wirelessSpoofGuardEnabled) {
                val (snap, newBase) = NetworkDefenseEngine.inspectLiveNetwork(applicationContext, null)
                val existing = newBase?.let { database.netShieldDao().getTrustedNetwork(it.networkKey) }
                val (verifiedSnap, verifiedBase) = NetworkDefenseEngine.inspectLiveNetwork(applicationContext, existing)
                if (verifiedBase != null) {
                    database.netShieldDao().upsertTrustedNetwork(verifiedBase)
                }
                for (anomaly in verifiedSnap.anomalies) {
                    val key = "${anomaly.category}:${anomaly.source}:${anomaly.target}"
                    if (key != lastAlertKey) {
                        lastAlertKey = key
                        database.netShieldDao().insertEvent(
                            SecurityEventEntity(
                                category = anomaly.category,
                                severity = anomaly.severity,
                                title = anomaly.title,
                                source = anomaly.source,
                                target = anomaly.target,
                                actionTaken = "DETECTED",
                                details = anomaly.details
                            )
                        )
                    }
                }
                if (verifiedSnap.anomalies.isEmpty()) {
                    lastAlertKey = null
                }
            }

            if (settings.backgroundDataGuard) {
                val appRules = database.netShieldDao().getAllAppRulesOnce()
                for (rule in appRules) {
                    if (rule.policy == AppPolicy.BLOCK_BACKGROUND.name || rule.policy == AppPolicy.BLOCK_ALL.name) {
                        val tx = TrafficStats.getUidTxBytes(rule.uid)
                        if (tx > 0) {
                            val prev = lastTxByUid[rule.uid] ?: tx
                            lastTxByUid[rule.uid] = tx
                            val delta = tx - prev
                            if (delta > 32 * 1024) {
                                recordBlockedPacket(
                                    category = EventCategory.DATA_THEFT_APP.name,
                                    severity = ThreatSeverity.HIGH.name,
                                    title = "Background Data Upload Flagged",
                                    source = rule.appName,
                                    target = "Outbound +${delta / 1024} KB",
                                    action = "APP GUARD ALERT",
                                    details = "${rule.appName} (${rule.packageName}) uploaded +${delta / 1024} KB while background-restricted."
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    private fun resolveOwnerUid(parsed: ParsedIpv4Packet): Int {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return -1
        return try {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            cm.getConnectionOwnerUid(
                parsed.protocol,
                InetSocketAddress(parsed.srcIp, parsed.srcPort),
                InetSocketAddress(parsed.dstIp, parsed.dstPort)
            )
        } catch (_: Exception) {
            -1
        }
    }

    private suspend fun recordBlockedPacket(
        category: String,
        severity: String,
        title: String,
        source: String,
        target: String,
        action: String,
        details: String
    ) {
        val cur = _status.value
        _status.value = cur.copy(packetsBlocked = cur.packetsBlocked + 1)
        database.netShieldDao().insertEvent(
            SecurityEventEntity(
                category = category,
                severity = severity,
                title = title,
                source = source,
                target = target,
                actionTaken = action,
                details = details
            )
        )
    }

    private fun stopVpnTunnel() {
        packetJob?.cancel()
        networkWatchJob?.cancel()
        try {
            vpnInterface?.close()
        } catch (_: Exception) {
        }
        vpnInterface = null
        _status.value = VpnTunnelStatus(isRunning = false)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun createNotificationChannels() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_VPN,
                    getString(R.string.vpn_notification_channel_name),
                    NotificationManager.IMPORTANCE_LOW
                ).apply {
                    description = getString(R.string.vpn_notification_channel_desc)
                }
            )
        }
    }

    override fun onDestroy() {
        stopVpnTunnel()
        serviceScope.cancel()
        super.onDestroy()
    }

    companion object {
        const val ACTION_START_VPN = "com.example.vpn.START"
        const val ACTION_STOP_VPN = "com.example.vpn.STOP"
        private const val CHANNEL_VPN = "netshield_vpn_channel"
        private const val NOTIFICATION_ID = 7001

        private val _status = MutableStateFlow(VpnTunnelStatus())
        val statusFlow: StateFlow<VpnTunnelStatus> = _status.asStateFlow()
    }
}

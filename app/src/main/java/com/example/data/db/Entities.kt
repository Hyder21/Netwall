package com.example.data.db

import androidx.room.Entity
import androidx.room.PrimaryKey

enum class EventCategory {
    PORT_SCAN,
    SNIFFING_ALERT,
    WIRELESS_SPOOFING,
    DATA_THEFT_APP,
    MALICIOUS_PAGE,
    METADATA_THREAT,
    VPN_FIREWALL
}

enum class ThreatSeverity {
    CRITICAL,
    HIGH,
    MEDIUM,
    INFO
}

enum class AppPolicy {
    ALLOW,
    BLOCK_BACKGROUND,
    BLOCK_ALL
}

enum class ScanType {
    IMAGE_EXIF,
    QR_CODE,
    EMOJI_UNICODE
}

@Entity(tableName = "security_events")
data class SecurityEventEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val timestamp: Long = System.currentTimeMillis(),
    val category: String,
    val severity: String,
    val title: String,
    val source: String,
    val target: String,
    val actionTaken: String,
    val details: String
)

@Entity(tableName = "port_rules")
data class PortRuleEntity(
    @PrimaryKey val port: Int,
    val protocol: String,
    val serviceName: String,
    val riskReason: String,
    val isOpenDetected: Boolean = false,
    val isMarkedOffline: Boolean = true,
    val blockedProbeCount: Int = 0,
    val lastScannedAt: Long = System.currentTimeMillis()
)

@Entity(tableName = "app_firewall_rules")
data class AppFirewallRuleEntity(
    @PrimaryKey val packageName: String,
    val appName: String,
    val uid: Int,
    val policy: String = AppPolicy.ALLOW.name,
    val rxBytes: Long = 0L,
    val txBytes: Long = 0L,
    val backgroundAlertFlag: Boolean = false,
    val updatedAt: Long = System.currentTimeMillis()
)

@Entity(tableName = "blocked_domains")
data class BlockedDomainEntity(
    @PrimaryKey val domain: String,
    val category: String,
    val hitCount: Int = 0,
    val isEnabled: Boolean = true,
    val isBuiltIn: Boolean = true
)

@Entity(tableName = "scan_reports")
data class ScanReportEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val scanType: String,
    val targetLabel: String,
    val threatLevel: String,
    val findingsCount: Int,
    val summary: String,
    val sanitizedPreview: String,
    val timestamp: Long = System.currentTimeMillis()
)

@Entity(tableName = "trusted_networks")
data class TrustedNetworkEntity(
    @PrimaryKey val networkKey: String, // e.g. SSID or interface key
    val lastBssid: String,
    val lastGatewayIp: String,
    val lastGatewayMac: String,
    val lastSecurityType: String,
    val lastSeenAt: Long = System.currentTimeMillis()
)

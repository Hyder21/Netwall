package com.example.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Dao
interface NetShieldDao {
    // Security Events
    @Query("SELECT * FROM security_events ORDER BY timestamp DESC LIMIT 150")
    fun observeSecurityEvents(): Flow<List<SecurityEventEntity>>

    @Query("SELECT COUNT(*) FROM security_events WHERE category != 'VPN_FIREWALL'")
    fun observeTotalBlockedCount(): Flow<Int>

    @Query("SELECT COUNT(*) FROM security_events WHERE category IN ('SNIFFING_ALERT', 'WIRELESS_SPOOFING')")
    fun observeSniffSpoofCount(): Flow<Int>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertEvent(event: SecurityEventEntity)

    @Query("DELETE FROM security_events")
    suspend fun clearEvents()

    // Port Rules
    @Query("SELECT * FROM port_rules ORDER BY isOpenDetected DESC, port ASC")
    fun observePortRules(): Flow<List<PortRuleEntity>>

    @Query("SELECT * FROM port_rules")
    suspend fun getAllPortRulesOnce(): List<PortRuleEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertPortRules(rules: List<PortRuleEntity>)

    @Query("UPDATE port_rules SET isMarkedOffline = :offline WHERE port = :port")
    suspend fun setPortOffline(port: Int, offline: Boolean)

    @Query("UPDATE port_rules SET isMarkedOffline = 1 WHERE port NOT IN (53, 80, 443)")
    suspend fun markServicePortsOffline()

    @Query("UPDATE port_rules SET blockedProbeCount = blockedProbeCount + 1, lastScannedAt = :timestamp WHERE port = :port")
    suspend fun incrementPortProbeCount(port: Int, timestamp: Long = System.currentTimeMillis())

    @Query("DELETE FROM port_rules WHERE port IN (4444, 31337)")
    suspend fun deleteLegacySimulatedPorts()

    // App Firewall Rules
    @Query("SELECT * FROM app_firewall_rules ORDER BY CASE WHEN policy = 'BLOCK_ALL' THEN 0 WHEN policy = 'BLOCK_BACKGROUND' THEN 1 ELSE 2 END, txBytes DESC, appName ASC")
    fun observeAppRules(): Flow<List<AppFirewallRuleEntity>>

    @Query("SELECT * FROM app_firewall_rules")
    suspend fun getAllAppRulesOnce(): List<AppFirewallRuleEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertAppRules(rules: List<AppFirewallRuleEntity>)

    @Query("UPDATE app_firewall_rules SET policy = :policy, updatedAt = :timestamp WHERE packageName = :packageName")
    suspend fun updateAppPolicy(packageName: String, policy: String, timestamp: Long = System.currentTimeMillis())

    // Blocked Domains
    @Query("SELECT * FROM blocked_domains ORDER BY isBuiltIn ASC, hitCount DESC, domain ASC")
    fun observeBlockedDomains(): Flow<List<BlockedDomainEntity>>

    @Query("SELECT * FROM blocked_domains WHERE isEnabled = 1")
    suspend fun getEnabledBlockedDomainsOnce(): List<BlockedDomainEntity>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertBlockedDomains(domains: List<BlockedDomainEntity>)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertBlockedDomain(domain: BlockedDomainEntity)

    @Query("UPDATE blocked_domains SET isEnabled = :enabled WHERE domain = :domain")
    suspend fun setDomainEnabled(domain: String, enabled: Boolean)

    @Query("UPDATE blocked_domains SET hitCount = hitCount + 1 WHERE domain = :domain")
    suspend fun incrementDomainHit(domain: String)

    @Query("DELETE FROM blocked_domains WHERE domain = :domain AND isBuiltIn = 0")
    suspend fun deleteCustomDomain(domain: String)

    @Query("DELETE FROM blocked_domains WHERE domain LIKE '%.example' OR domain LIKE '%.test'")
    suspend fun deletePlaceholderDomains()

    // Scan Reports
    @Query("SELECT * FROM scan_reports ORDER BY timestamp DESC LIMIT 50")
    fun observeScanReports(): Flow<List<ScanReportEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertScanReport(report: ScanReportEntity)

    @Query("DELETE FROM scan_reports")
    suspend fun clearScanReports()

    // Trusted Network Baselines (Evil-Twin & ARP Gateway Integrity)
    @Query("SELECT * FROM trusted_networks WHERE networkKey = :key LIMIT 1")
    suspend fun getTrustedNetwork(key: String): TrustedNetworkEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertTrustedNetwork(network: TrustedNetworkEntity)
}

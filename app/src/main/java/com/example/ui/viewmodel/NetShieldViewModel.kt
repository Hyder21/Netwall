package com.example.ui.viewmodel

import android.app.Application
import android.content.Intent
import android.net.TrafficStats
import android.net.Uri
import android.os.Build
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.data.db.AppFirewallRuleEntity
import com.example.data.db.AppPolicy
import com.example.data.db.BlockedDomainEntity
import com.example.data.db.EventCategory
import com.example.data.db.NetShieldDatabase
import com.example.data.db.PortRuleEntity
import com.example.data.db.ScanReportEntity
import com.example.data.db.ScanType
import com.example.data.db.SecurityEventEntity
import com.example.data.db.ThreatSeverity
import com.example.data.prefs.ShieldPreferences
import com.example.data.prefs.ShieldSettings
import com.example.data.repository.NetShieldRepository
import com.example.security.EmojiScanResult
import com.example.security.ImageScanResult
import com.example.security.MetadataScannerEngine
import com.example.security.NetworkDefenseSnapshot
import com.example.security.QrScanResult
import com.example.vpn.NetShieldVpnService
import com.example.vpn.VpnTunnelStatus
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class TrafficSample(
    val timestamp: Long,
    val rxBytesPerSec: Long,
    val txBytesPerSec: Long
)

class NetShieldViewModel(application: Application) : AndroidViewModel(application) {

    private val database = NetShieldDatabase.getInstance(application)
    private val repository = NetShieldRepository(application, database.netShieldDao())
    private val preferences = ShieldPreferences(application)

    val vpnStatus: StateFlow<VpnTunnelStatus> = NetShieldVpnService.statusFlow

    val settings: StateFlow<ShieldSettings> = preferences.settingsFlow
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), ShieldSettings())

    val securityEvents: StateFlow<List<SecurityEventEntity>> = repository.securityEvents
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val totalBlockedCount: StateFlow<Int> = repository.totalBlockedCount
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), 0)

    val sniffSpoofCount: StateFlow<Int> = repository.sniffSpoofCount
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), 0)

    val portRules: StateFlow<List<PortRuleEntity>> = repository.portRules
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val appRules: StateFlow<List<AppFirewallRuleEntity>> = repository.appRules
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val blockedDomains: StateFlow<List<BlockedDomainEntity>> = repository.blockedDomains
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val scanReports: StateFlow<List<ScanReportEntity>> = repository.scanReports
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    private val _networkDefenseSnapshot = MutableStateFlow(NetworkDefenseSnapshot())
    val networkDefenseSnapshot: StateFlow<NetworkDefenseSnapshot> = _networkDefenseSnapshot.asStateFlow()

    private val _isAuditingNetwork = MutableStateFlow(false)
    val isAuditingNetwork: StateFlow<Boolean> = _isAuditingNetwork.asStateFlow()

    private val _throughputHistory = MutableStateFlow<List<TrafficSample>>(emptyList())
    val throughputHistory: StateFlow<List<TrafficSample>> = _throughputHistory.asStateFlow()

    private val _isScanningPorts = MutableStateFlow(false)
    val isScanningPorts: StateFlow<Boolean> = _isScanningPorts.asStateFlow()

    private val _isRefreshingApps = MutableStateFlow(false)
    val isRefreshingApps: StateFlow<Boolean> = _isRefreshingApps.asStateFlow()

    private val _imageScanResult = MutableStateFlow<ImageScanResult?>(null)
    val imageScanResult: StateFlow<ImageScanResult?> = _imageScanResult.asStateFlow()

    private val _selectedImageUri = MutableStateFlow<Uri?>(null)
    val selectedImageUri: StateFlow<Uri?> = _selectedImageUri.asStateFlow()

    private val _qrScanResult = MutableStateFlow<QrScanResult?>(null)
    val qrScanResult: StateFlow<QrScanResult?> = _qrScanResult.asStateFlow()

    private val _emojiScanResult = MutableStateFlow<EmojiScanResult?>(null)
    val emojiScanResult: StateFlow<EmojiScanResult?> = _emojiScanResult.asStateFlow()

    private val _urlCheckResult = MutableStateFlow<QrScanResult?>(null)
    val urlCheckResult: StateFlow<QrScanResult?> = _urlCheckResult.asStateFlow()

    private val _feedbackMessage = MutableStateFlow<String?>(null)
    val feedbackMessage: StateFlow<String?> = _feedbackMessage.asStateFlow()

    init {
        viewModelScope.launch {
            repository.ensureSeeded()
            refreshInstalledApps()
            runNetworkDefenseAudit(silent = true)
        }
        startRealTrafficSampler()
    }

    private fun startRealTrafficSampler() {
        viewModelScope.launch(Dispatchers.IO) {
            var prevRx = TrafficStats.getTotalRxBytes().coerceAtLeast(0L)
            var prevTx = TrafficStats.getTotalTxBytes().coerceAtLeast(0L)
            while (isActive) {
                delay(1000)
                val curRx = TrafficStats.getTotalRxBytes().coerceAtLeast(0L)
                val curTx = TrafficStats.getTotalTxBytes().coerceAtLeast(0L)
                val rxRate = (curRx - prevRx).coerceAtLeast(0L)
                val txRate = (curTx - prevTx).coerceAtLeast(0L)
                prevRx = curRx
                prevTx = curTx

                val sample = TrafficSample(
                    timestamp = System.currentTimeMillis(),
                    rxBytesPerSec = rxRate,
                    txBytesPerSec = txRate
                )
                _throughputHistory.value = (_throughputHistory.value + sample).takeLast(24)
            }
        }
    }

    fun startVpnFirewallService() {
        val ctx = getApplication<Application>()
        val intent = Intent(ctx, NetShieldVpnService::class.java).apply {
            action = NetShieldVpnService.ACTION_START_VPN
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            ctx.startForegroundService(intent)
        } else {
            ctx.startService(intent)
        }
    }

    fun stopVpnFirewallService() {
        val ctx = getApplication<Application>()
        val intent = Intent(ctx, NetShieldVpnService::class.java).apply {
            action = NetShieldVpnService.ACTION_STOP_VPN
        }
        ctx.startService(intent)
    }

    fun scanDevicePorts() {
        if (_isScanningPorts.value) return
        viewModelScope.launch {
            _isScanningPorts.value = true
            val autoLock = settings.value.autoLockOpenPorts
            val result = repository.scanDevicePorts(autoLock)
            val openCount = result.count { it.isOpenDetected }
            val offlineCount = result.count { it.isMarkedOffline }
            _feedbackMessage.value = if (openCount > 0) {
                "Found $openCount open local port(s) — $offlineCount service ports offline (internet open)."
            } else {
                "Port audit clean: $offlineCount service ports offline, internet active."
            }
            _isScanningPorts.value = false
        }
    }

    fun runNetworkDefenseAudit(silent: Boolean = false) {
        if (_isAuditingNetwork.value) return
        viewModelScope.launch {
            _isAuditingNetwork.value = true
            val currentSettings = settings.value
            val snap = repository.runNetworkDefenseAudit(
                checkSniffing = currentSettings.sniffingDetectionEnabled,
                checkWirelessSpoofing = currentSettings.wirelessSpoofGuardEnabled
            )
            _networkDefenseSnapshot.value = snap
            if (!silent) {
                _feedbackMessage.value = if (snap.anomalies.isEmpty()) {
                    "No local network issues detected."
                } else {
                    "Detected ${snap.anomalies.size} local network issue(s)!"
                }
            }
            _isAuditingNetwork.value = false
        }
    }

    fun togglePortOffline(port: Int, offline: Boolean) {
        viewModelScope.launch {
            repository.setPortOffline(port, offline)
        }
    }

    fun markServicePortsOffline() {
        viewModelScope.launch {
            repository.markServicePortsOffline()
            _feedbackMessage.value = "Service ports marked OFFLINE while keeping internet active."
        }
    }

    fun refreshInstalledApps() {
        if (_isRefreshingApps.value) return
        viewModelScope.launch {
            _isRefreshingApps.value = true
            repository.refreshInstalledApps()
            _isRefreshingApps.value = false
        }
    }

    fun setAppPolicy(packageName: String, appName: String, policy: AppPolicy) {
        viewModelScope.launch {
            repository.setAppPolicy(packageName, appName, policy)
        }
    }

    fun addBlockedDomain(domain: String) {
        viewModelScope.launch {
            repository.addCustomBlockedDomain(domain)
            _feedbackMessage.value = "Domain added to DNS/Page blocklist."
        }
    }

    fun toggleDomain(domain: String, enabled: Boolean) {
        viewModelScope.launch {
            repository.toggleDomain(domain, enabled)
        }
    }

    fun removeCustomDomain(domain: String) {
        viewModelScope.launch {
            repository.removeCustomDomain(domain)
        }
    }

    fun checkUrlSafety(urlOrDomain: String) {
        viewModelScope.launch {
            val blocked = blockedDomains.first().filter { it.isEnabled }.map { it.domain }.toSet()
            val normalized = if (urlOrDomain.contains("://")) urlOrDomain.trim() else "https://${urlOrDomain.trim()}"
            val result = withContext(Dispatchers.Default) {
                MetadataScannerEngine.inspectQrPayload(normalized, blocked)
            }
            _urlCheckResult.value = result
            if (result.threatLevel != "CLEAN") {
                repository.logEvent(
                    SecurityEventEntity(
                        category = EventCategory.MALICIOUS_PAGE.name,
                        severity = if (result.threatLevel == "CRITICAL") ThreatSeverity.CRITICAL.name else ThreatSeverity.HIGH.name,
                        title = "Malicious Page Check Flagged",
                        source = "URL Inspector",
                        target = urlOrDomain.take(80),
                        actionTaken = "BLOCK RECOMMENDED",
                        details = result.findings.joinToString(" • ") { it.title }
                    )
                )
            }
        }
    }

    fun scanImage(uri: Uri) {
        _selectedImageUri.value = uri
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                MetadataScannerEngine.scanImageUri(getApplication(), uri)
            }
            _imageScanResult.value = result
            repository.saveScanReport(
                ScanReportEntity(
                    scanType = ScanType.IMAGE_EXIF.name,
                    targetLabel = result.fileName,
                    threatLevel = result.threatLevel,
                    findingsCount = result.findings.count { it.severity != "INFO" },
                    summary = result.findings.firstOrNull()?.title ?: "Scanned",
                    sanitizedPreview = "${result.dimensions} • ${result.exifFields.size} EXIF tags"
                )
            )
            if (result.threatLevel != "CLEAN") {
                repository.logEvent(
                    SecurityEventEntity(
                        category = EventCategory.METADATA_THREAT.name,
                        severity = if (result.threatLevel == "CRITICAL") ThreatSeverity.CRITICAL.name else ThreatSeverity.HIGH.name,
                        title = "Picture Metadata Threat: ${result.fileName}",
                        source = "Media Inspector",
                        target = result.fileName,
                        actionTaken = "QUARANTINE / STRIP ADVISED",
                        details = result.findings.joinToString(" | ") { it.title }
                    )
                )
            }
        }
    }

    fun stripSelectedImageMetadata() {
        val uri = _selectedImageUri.value ?: return
        val name = _imageScanResult.value?.fileName ?: "image"
        viewModelScope.launch {
            val savedPath = withContext(Dispatchers.IO) {
                MetadataScannerEngine.stripMetadataAndSaveCleanCopy(getApplication(), uri, name)
            }
            _feedbackMessage.value = if (savedPath != null) {
                "Sanitized copy saved without EXIF/GPS: $savedPath"
            } else {
                "Unable to save sanitized copy for this image."
            }
        }
    }

    fun scanQrFromImage(uri: Uri) {
        viewModelScope.launch {
            val blocked = blockedDomains.first().filter { it.isEnabled }.map { it.domain }.toSet()
            val result = withContext(Dispatchers.IO) {
                MetadataScannerEngine.scanQrFromImageUri(getApplication(), uri, blocked)
            }
            if (result == null) {
                _feedbackMessage.value = "No readable QR code found in the selected image."
                return@launch
            }
            _qrScanResult.value = result
            persistQrReport(result)
        }
    }

    fun inspectQrText(payload: String) {
        if (payload.isBlank()) return
        viewModelScope.launch {
            val blocked = blockedDomains.first().filter { it.isEnabled }.map { it.domain }.toSet()
            val result = withContext(Dispatchers.Default) {
                MetadataScannerEngine.inspectQrPayload(payload, blocked)
            }
            _qrScanResult.value = result
            persistQrReport(result)
        }
    }

    private suspend fun persistQrReport(result: QrScanResult) {
        repository.saveScanReport(
            ScanReportEntity(
                scanType = ScanType.QR_CODE.name,
                targetLabel = result.rawPayload.take(48),
                threatLevel = result.threatLevel,
                findingsCount = result.findings.count { it.severity != "INFO" },
                summary = result.findings.firstOrNull()?.title ?: "QR Inspected",
                sanitizedPreview = result.sanitizedPayload.take(80)
            )
        )
        if (result.threatLevel != "CLEAN") {
            repository.logEvent(
                SecurityEventEntity(
                    category = EventCategory.METADATA_THREAT.name,
                    severity = if (result.threatLevel == "CRITICAL") ThreatSeverity.CRITICAL.name else ThreatSeverity.HIGH.name,
                    title = "Malicious QR Payload Blocked",
                    source = result.payloadType,
                    target = result.rawPayload.take(64),
                    actionTaken = "PAYLOAD QUARANTINED",
                    details = result.findings.joinToString(" • ") { it.title }
                )
            )
        }
    }

    fun scanEmojiText(input: String) {
        if (input.isEmpty()) return
        viewModelScope.launch {
            val result = withContext(Dispatchers.Default) {
                MetadataScannerEngine.scanEmojiAndText(input)
            }
            _emojiScanResult.value = result
            repository.saveScanReport(
                ScanReportEntity(
                    scanType = ScanType.EMOJI_UNICODE.name,
                    targetLabel = input.take(32),
                    threatLevel = result.threatLevel,
                    findingsCount = result.findings.count { it.severity != "INFO" },
                    summary = result.findings.firstOrNull()?.title ?: "Unicode Checked",
                    sanitizedPreview = result.sanitizedText.take(64)
                )
            )
            if (result.threatLevel != "CLEAN") {
                repository.logEvent(
                    SecurityEventEntity(
                        category = EventCategory.METADATA_THREAT.name,
                        severity = if (result.threatLevel == "CRITICAL") ThreatSeverity.CRITICAL.name else ThreatSeverity.HIGH.name,
                        title = "Malformed Emoji / Unicode Exploit Detected",
                        source = "Text & Emoji Scanner",
                        target = "${result.originalLength} chars",
                        actionTaken = "SANITIZED",
                        details = result.findings.joinToString(" • ") { it.title }
                    )
                )
            }
        }
    }

    fun clearEvents() {
        viewModelScope.launch { repository.clearEvents() }
    }

    fun clearScanReports() {
        viewModelScope.launch { repository.clearScanReports() }
    }

    fun consumeFeedback() {
        _feedbackMessage.value = null
    }

    // Settings mutations
    fun setDarkMode(enabled: Boolean) = viewModelScope.launch { preferences.setDarkMode(enabled) }
    fun setAutoLockOpenPorts(enabled: Boolean) = viewModelScope.launch { preferences.setAutoLockOpenPorts(enabled) }
    fun setSniffingDetectionEnabled(enabled: Boolean) = viewModelScope.launch { preferences.setSniffingDetectionEnabled(enabled) }
    fun setWirelessSpoofGuardEnabled(enabled: Boolean) = viewModelScope.launch { preferences.setWirelessSpoofGuardEnabled(enabled) }
    fun setMaliciousPageBlocker(enabled: Boolean) = viewModelScope.launch { preferences.setMaliciousPageBlocker(enabled) }
    fun setBackgroundDataGuard(enabled: Boolean) = viewModelScope.launch { preferences.setBackgroundDataGuard(enabled) }
    fun setDnsSinkholeEnabled(enabled: Boolean) = viewModelScope.launch { preferences.setDnsSinkholeEnabled(enabled) }
}

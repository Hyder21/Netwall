package com.example.data.prefs

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

private val Context.shieldDataStore: DataStore<Preferences> by preferencesDataStore(name = "netshield_prefs")

data class ShieldSettings(
    val darkMode: Boolean = true,
    val autoLockOpenPorts: Boolean = true,
    val sniffingDetectionEnabled: Boolean = true,
    val wirelessSpoofGuardEnabled: Boolean = true,
    val maliciousPageBlocker: Boolean = true,
    val backgroundDataGuard: Boolean = true,
    val dnsSinkholeEnabled: Boolean = true
)

class ShieldPreferences(private val context: Context) {

    private object Keys {
        val DARK_MODE = booleanPreferencesKey("dark_mode")
        val AUTO_LOCK_PORTS = booleanPreferencesKey("auto_lock_ports")
        val SNIFFING_DETECTION = booleanPreferencesKey("sniffing_detection")
        val WIRELESS_SPOOF_GUARD = booleanPreferencesKey("wireless_spoof_guard")
        val MALICIOUS_PAGE_BLOCK = booleanPreferencesKey("malicious_page_block")
        val BACKGROUND_DATA_GUARD = booleanPreferencesKey("background_data_guard")
        val DNS_SINKHOLE = booleanPreferencesKey("dns_sinkhole")
    }

    val settingsFlow: Flow<ShieldSettings> = context.shieldDataStore.data.map { prefs ->
        ShieldSettings(
            darkMode = prefs[Keys.DARK_MODE] ?: true,
            autoLockOpenPorts = prefs[Keys.AUTO_LOCK_PORTS] ?: true,
            sniffingDetectionEnabled = prefs[Keys.SNIFFING_DETECTION] ?: true,
            wirelessSpoofGuardEnabled = prefs[Keys.WIRELESS_SPOOF_GUARD] ?: true,
            maliciousPageBlocker = prefs[Keys.MALICIOUS_PAGE_BLOCK] ?: true,
            backgroundDataGuard = prefs[Keys.BACKGROUND_DATA_GUARD] ?: true,
            dnsSinkholeEnabled = prefs[Keys.DNS_SINKHOLE] ?: true
        )
    }

    suspend fun setDarkMode(enabled: Boolean) {
        context.shieldDataStore.edit { it[Keys.DARK_MODE] = enabled }
    }

    suspend fun setAutoLockOpenPorts(enabled: Boolean) {
        context.shieldDataStore.edit { it[Keys.AUTO_LOCK_PORTS] = enabled }
    }

    suspend fun setSniffingDetectionEnabled(enabled: Boolean) {
        context.shieldDataStore.edit { it[Keys.SNIFFING_DETECTION] = enabled }
    }

    suspend fun setWirelessSpoofGuardEnabled(enabled: Boolean) {
        context.shieldDataStore.edit { it[Keys.WIRELESS_SPOOF_GUARD] = enabled }
    }

    suspend fun setMaliciousPageBlocker(enabled: Boolean) {
        context.shieldDataStore.edit { it[Keys.MALICIOUS_PAGE_BLOCK] = enabled }
    }

    suspend fun setBackgroundDataGuard(enabled: Boolean) {
        context.shieldDataStore.edit { it[Keys.BACKGROUND_DATA_GUARD] = enabled }
    }

    suspend fun setDnsSinkholeEnabled(enabled: Boolean) {
        context.shieldDataStore.edit { it[Keys.DNS_SINKHOLE] = enabled }
    }
}

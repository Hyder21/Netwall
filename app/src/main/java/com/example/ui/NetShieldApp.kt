package com.example.ui

import android.Manifest
import android.app.Activity
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Analytics
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Timeline
import androidx.compose.material.icons.outlined.Apps
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.QrCodeScanner
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material.icons.outlined.Timeline
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.example.R
import com.example.data.db.AppPolicy
import com.example.data.prefs.ShieldSettings
import com.example.ui.components.ColourfulStatusPill
import com.example.ui.screens.AppFirewallScreen
import com.example.ui.screens.DashboardScreen
import com.example.ui.screens.MetadataScannerScreen
import com.example.ui.screens.PortGuardScreen
import com.example.ui.screens.ThreatDashboardScreen
import com.example.ui.screens.TrafficMonitorScreen
import com.example.ui.theme.LocalNetShieldColors
import com.example.ui.theme.NetShieldTheme
import com.example.ui.viewmodel.NetShieldViewModel

sealed class NetShieldDest(
    val route: String,
    val labelRes: Int,
    val selectedIcon: ImageVector,
    val unselectedIcon: ImageVector,
    val testTag: String
) {
    data object Dashboard : NetShieldDest(
        route = "dashboard",
        labelRes = R.string.nav_dashboard,
        selectedIcon = Icons.Filled.Shield,
        unselectedIcon = Icons.Outlined.Shield,
        testTag = "nav_dashboard"
    )
    data object Ports : NetShieldDest(
        route = "ports",
        labelRes = R.string.nav_ports,
        selectedIcon = Icons.Filled.Lock,
        unselectedIcon = Icons.Outlined.Lock,
        testTag = "nav_ports"
    )
    data object Firewall : NetShieldDest(
        route = "firewall",
        labelRes = R.string.nav_firewall,
        selectedIcon = Icons.Filled.Apps,
        unselectedIcon = Icons.Outlined.Apps,
        testTag = "nav_firewall"
    )
    data object Scanner : NetShieldDest(
        route = "scanner",
        labelRes = R.string.nav_scanner,
        selectedIcon = Icons.Filled.QrCodeScanner,
        unselectedIcon = Icons.Outlined.QrCodeScanner,
        testTag = "nav_scanner"
    )
    data object Traffic : NetShieldDest(
        route = "traffic",
        labelRes = R.string.nav_traffic,
        selectedIcon = Icons.Filled.Timeline,
        unselectedIcon = Icons.Outlined.Timeline,
        testTag = "nav_traffic"
    )
    data object ThreatDashboard : NetShieldDest(
        route = "threat_dashboard",
        labelRes = R.string.nav_threat_dashboard,
        selectedIcon = Icons.Filled.Analytics,
        unselectedIcon = Icons.Filled.Analytics,
        testTag = "nav_threat_dashboard"
    )
}

private val destinations = listOf(
    NetShieldDest.Dashboard,
    NetShieldDest.Ports,
    NetShieldDest.Firewall,
    NetShieldDest.Scanner,
    NetShieldDest.Traffic
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NetShieldApp(viewModel: NetShieldViewModel) {
    val settings by viewModel.settings.collectAsStateWithLifecycle()
    val vpnStatus by viewModel.vpnStatus.collectAsStateWithLifecycle()
    val throughputHistory by viewModel.throughputHistory.collectAsStateWithLifecycle()
    val portRules by viewModel.portRules.collectAsStateWithLifecycle()
    val isScanningPorts by viewModel.isScanningPorts.collectAsStateWithLifecycle()
    val appRules by viewModel.appRules.collectAsStateWithLifecycle()
    val isRefreshingApps by viewModel.isRefreshingApps.collectAsStateWithLifecycle()
    val blockedDomains by viewModel.blockedDomains.collectAsStateWithLifecycle()
    val securityEvents by viewModel.securityEvents.collectAsStateWithLifecycle()
    val totalBlockedCount by viewModel.totalBlockedCount.collectAsStateWithLifecycle()
    val sniffSpoofCount by viewModel.sniffSpoofCount.collectAsStateWithLifecycle()
    val networkSnapshot by viewModel.networkDefenseSnapshot.collectAsStateWithLifecycle()
    val isAuditingNetwork by viewModel.isAuditingNetwork.collectAsStateWithLifecycle()
    val imageScanResult by viewModel.imageScanResult.collectAsStateWithLifecycle()
    val qrScanResult by viewModel.qrScanResult.collectAsStateWithLifecycle()
    val emojiScanResult by viewModel.emojiScanResult.collectAsStateWithLifecycle()
    val scanReports by viewModel.scanReports.collectAsStateWithLifecycle()
    val urlCheckResult by viewModel.urlCheckResult.collectAsStateWithLifecycle()
    val feedbackMessage by viewModel.feedbackMessage.collectAsStateWithLifecycle()

    NetShieldTheme(darkTheme = settings.darkMode) {
        val accents = LocalNetShieldColors.current
        val context = LocalContext.current
        val navController = rememberNavController()
        val navBackStackEntry by navController.currentBackStackEntryAsState()
        val currentRoute = navBackStackEntry?.destination?.route ?: NetShieldDest.Dashboard.route
        val snackbarHostState = remember { SnackbarHostState() }
        var showSettingsDialog by remember { mutableStateOf(false) }

        val vpnConsentLauncher = rememberLauncherForActivityResult(
            contract = ActivityResultContracts.StartActivityForResult()
        ) { result ->
            if (result.resultCode == Activity.RESULT_OK) {
                viewModel.startVpnFirewallService()
            }
        }

        val notificationPermLauncher = rememberLauncherForActivityResult(
            contract = ActivityResultContracts.RequestPermission()
        ) { _ ->
            // Start VPN regardless of notification permission; FGS continues working safely
            val prepareIntent = VpnService.prepare(context)
            if (prepareIntent != null) {
                vpnConsentLauncher.launch(prepareIntent)
            } else {
                viewModel.startVpnFirewallService()
            }
        }

        val toggleVpnAction: () -> Unit = {
            if (vpnStatus.isRunning) {
                viewModel.stopVpnFirewallService()
            } else {
                val needsNotifPerm = Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
                    ContextCompat.checkSelfPermission(
                        context,
                        Manifest.permission.POST_NOTIFICATIONS
                    ) != PackageManager.PERMISSION_GRANTED
                if (needsNotifPerm) {
                    notificationPermLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                } else {
                    val prepareIntent = VpnService.prepare(context)
                    if (prepareIntent != null) {
                        vpnConsentLauncher.launch(prepareIntent)
                    } else {
                        viewModel.startVpnFirewallService()
                    }
                }
            }
        }

        val navigateToTab: (String) -> Unit = { route ->
            navController.navigate(route) {
                popUpTo(navController.graph.findStartDestination().id) {
                    saveState = true
                }
                launchSingleTop = true
                restoreState = true
            }
        }

        // Handle back press on secondary tabs to return to Shield dashboard
        BackHandler(enabled = currentRoute != NetShieldDest.Dashboard.route) {
            navigateToTab(NetShieldDest.Dashboard.route)
        }

        LaunchedEffect(feedbackMessage) {
            val msg = feedbackMessage ?: return@LaunchedEffect
            snackbarHostState.showSnackbar(msg)
            viewModel.consumeFeedback()
        }

        BoxWithConstraints(modifier = Modifier.fillMaxSize()) {
            val isWideScreen = maxWidth >= 700.dp

            Scaffold(
                contentWindowInsets = WindowInsets.safeDrawing,
                snackbarHost = { SnackbarHost(hostState = snackbarHostState) },
                topBar = {
                    TopAppBar(
                        colors = TopAppBarDefaults.topAppBarColors(
                            containerColor = MaterialTheme.colorScheme.surface
                        ),
                        title = {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Image(
                                    painter = painterResource(id = R.drawable.netshield_icon_1794580913324),
                                    contentDescription = stringResource(id = R.string.cd_shield_logo),
                                    contentScale = ContentScale.Crop,
                                    modifier = Modifier
                                        .size(34.dp)
                                        .clip(CircleShape)
                                )
                                Spacer(modifier = Modifier.width(10.dp))
                                Column {
                                    Text(
                                        text = "NETWALL",
                                        style = MaterialTheme.typography.titleLarge,
                                        fontWeight = FontWeight.Bold
                                    )
                                }
                                Spacer(modifier = Modifier.width(10.dp))
                                ColourfulStatusPill(
                                    label = if (vpnStatus.isRunning) "VPN ON" else "STANDBY",
                                    accent = if (vpnStatus.isRunning) accents.emerald else accents.amber
                                )
                            }
                        },
                        actions = {
                            IconButton(
                                onClick = { navigateToTab(NetShieldDest.ThreatDashboard.route) },
                                modifier = Modifier
                                    .size(48.dp)
                                    .testTag("threat_dashboard_button")
                            ) {
                                Icon(
                                    imageVector = Icons.Default.Analytics,
                                    contentDescription = stringResource(id = R.string.cd_threat_dashboard),
                                    tint = if (currentRoute == NetShieldDest.ThreatDashboard.route) accents.magenta else MaterialTheme.colorScheme.onSurface
                                )
                            }
                            IconButton(
                                onClick = { showSettingsDialog = true },
                                modifier = Modifier
                                    .size(48.dp)
                                    .testTag("settings_button")
                            ) {
                                Icon(
                                    imageVector = Icons.Default.Settings,
                                    contentDescription = stringResource(id = R.string.cd_settings)
                                )
                            }
                        }
                    )
                },
                bottomBar = {
                    if (!isWideScreen) {
                        NavigationBar(
                            containerColor = MaterialTheme.colorScheme.surface
                        ) {
                            destinations.forEach { dest ->
                                val selected = currentRoute == dest.route
                                NavigationBarItem(
                                    selected = selected,
                                    onClick = { navigateToTab(dest.route) },
                                    icon = {
                                        Icon(
                                            imageVector = if (selected) dest.selectedIcon else dest.unselectedIcon,
                                            contentDescription = stringResource(id = dest.labelRes)
                                        )
                                    },
                                    label = {
                                        Text(
                                            text = stringResource(id = dest.labelRes),
                                            maxLines = 1
                                        )
                                    },
                                    colors = NavigationBarItemDefaults.colors(
                                        selectedIconColor = accents.cyan,
                                        selectedTextColor = accents.cyan,
                                        indicatorColor = accents.cyan.copy(alpha = 0.18f)
                                    ),
                                    modifier = Modifier.testTag(dest.testTag)
                                )
                            }
                        }
                    }
                }
            ) { innerPadding ->
                Row(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(innerPadding)
                ) {
                    if (isWideScreen) {
                        NavigationRail(
                            containerColor = MaterialTheme.colorScheme.surface,
                            modifier = Modifier.fillMaxHeight()
                        ) {
                            destinations.forEach { dest ->
                                val selected = currentRoute == dest.route
                                NavigationRailItem(
                                    selected = selected,
                                    onClick = { navigateToTab(dest.route) },
                                    icon = {
                                        Icon(
                                            imageVector = if (selected) dest.selectedIcon else dest.unselectedIcon,
                                            contentDescription = stringResource(id = dest.labelRes)
                                        )
                                    },
                                    label = { Text(stringResource(id = dest.labelRes)) },
                                    modifier = Modifier.testTag(dest.testTag)
                                )
                            }
                        }
                    }

                    Box(
                        contentAlignment = Alignment.TopCenter,
                        modifier = Modifier.fillMaxSize()
                    ) {
                        NavHost(
                            navController = navController,
                            startDestination = NetShieldDest.Dashboard.route,
                            modifier = Modifier
                                .fillMaxSize()
                                .widthIn(max = 840.dp)
                        ) {
                            composable(NetShieldDest.Dashboard.route) {
                                DashboardScreen(
                                    vpnStatus = vpnStatus,
                                    throughputHistory = throughputHistory,
                                    networkSnapshot = networkSnapshot,
                                    offlinePortsCount = portRules.count { it.isMarkedOffline },
                                    totalPortsCount = portRules.size,
                                    blockedAppsCount = appRules.count { it.policy != AppPolicy.ALLOW.name },
                                    blockedDomainsCount = blockedDomains.count { it.isEnabled },
                                    sniffSpoofCount = sniffSpoofCount,
                                    totalBlockedCount = totalBlockedCount,
                                    recentEvents = securityEvents,
                                    onToggleVpn = toggleVpnAction,
                                    onNavigateToPorts = { navigateToTab(NetShieldDest.Ports.route) },
                                    onNavigateToFirewall = { navigateToTab(NetShieldDest.Firewall.route) },
                                    onNavigateToScanner = { navigateToTab(NetShieldDest.Scanner.route) },
                                    onNavigateToTraffic = { navigateToTab(NetShieldDest.Traffic.route) },
                                    onNavigateToThreatDashboard = { navigateToTab(NetShieldDest.ThreatDashboard.route) }
                                )
                            }
                            composable(NetShieldDest.Ports.route) {
                                PortGuardScreen(
                                    portRules = portRules,
                                    isScanningPorts = isScanningPorts,
                                    networkSnapshot = networkSnapshot,
                                    isAuditingNetwork = isAuditingNetwork,
                                    onScanPorts = { viewModel.scanDevicePorts() },
                                    onMarkServicePortsOffline = { viewModel.markServicePortsOffline() },
                                    onTogglePortOffline = { port, offline ->
                                        viewModel.togglePortOffline(port, offline)
                                    },
                                    onRunNetworkAudit = { viewModel.runNetworkDefenseAudit() }
                                )
                            }
                            composable(NetShieldDest.Firewall.route) {
                                AppFirewallScreen(
                                    appRules = appRules,
                                    blockedDomains = blockedDomains,
                                    isRefreshingApps = isRefreshingApps,
                                    urlCheckResult = urlCheckResult,
                                    onRefreshApps = { viewModel.refreshInstalledApps() },
                                    onSetAppPolicy = { pkg, name, policy ->
                                        viewModel.setAppPolicy(pkg, name, policy)
                                    },
                                    onAddBlockedDomain = { viewModel.addBlockedDomain(it) },
                                    onToggleDomain = { domain, enabled ->
                                        viewModel.toggleDomain(domain, enabled)
                                    },
                                    onRemoveCustomDomain = { viewModel.removeCustomDomain(it) },
                                    onCheckUrlSafety = { viewModel.checkUrlSafety(it) }
                                )
                            }
                            composable(NetShieldDest.Scanner.route) {
                                MetadataScannerScreen(
                                    imageScanResult = imageScanResult,
                                    qrScanResult = qrScanResult,
                                    emojiScanResult = emojiScanResult,
                                    scanReports = scanReports,
                                    onScanImageUri = { viewModel.scanImage(it) },
                                    onStripImageMetadata = { viewModel.stripSelectedImageMetadata() },
                                    onScanQrImageUri = { viewModel.scanQrFromImage(it) },
                                    onInspectQrText = { viewModel.inspectQrText(it) },
                                    onScanEmojiText = { viewModel.scanEmojiText(it) }
                                )
                            }
                            composable(NetShieldDest.Traffic.route) {
                                TrafficMonitorScreen(
                                    events = securityEvents,
                                    onClearEvents = { viewModel.clearEvents() }
                                )
                            }
                            composable(NetShieldDest.ThreatDashboard.route) {
                                ThreatDashboardScreen(
                                    vpnStatus = vpnStatus,
                                    securityEvents = securityEvents,
                                    scanReports = scanReports,
                                    onNavigateToTraffic = { navigateToTab(NetShieldDest.Traffic.route) }
                                )
                            }
                        }
                    }
                }
            }
        }

        if (showSettingsDialog) {
            SettingsDialog(
                settings = settings,
                onDismiss = { showSettingsDialog = false },
                onSetDarkMode = { viewModel.setDarkMode(it) },
                onSetAutoLockPorts = { viewModel.setAutoLockOpenPorts(it) },
                onSetSniffingDetection = { viewModel.setSniffingDetectionEnabled(it) },
                onSetWirelessSpoofGuard = { viewModel.setWirelessSpoofGuardEnabled(it) },
                onSetPageBlocker = { viewModel.setMaliciousPageBlocker(it) },
                onSetBgGuard = { viewModel.setBackgroundDataGuard(it) },
                onSetDnsSinkhole = { viewModel.setDnsSinkholeEnabled(it) }
            )
        }
    }
}

@Composable
private fun SettingsDialog(
    settings: ShieldSettings,
    onDismiss: () -> Unit,
    onSetDarkMode: (Boolean) -> Unit,
    onSetAutoLockPorts: (Boolean) -> Unit,
    onSetSniffingDetection: (Boolean) -> Unit,
    onSetWirelessSpoofGuard: (Boolean) -> Unit,
    onSetPageBlocker: (Boolean) -> Unit,
    onSetBgGuard: (Boolean) -> Unit,
    onSetDnsSinkhole: (Boolean) -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("NETWALL Security Policies", style = MaterialTheme.typography.titleLarge) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                SettingToggleRow("Dark Cyber-Shield Theme", settings.darkMode, onSetDarkMode)
                SettingToggleRow("Keep Service Ports Offline", settings.autoLockOpenPorts, onSetAutoLockPorts)
                SettingToggleRow("LAN & ARP Issue Detection", settings.sniffingDetectionEnabled, onSetSniffingDetection)
                SettingToggleRow("Wi-Fi Local Issue Guard", settings.wirelessSpoofGuardEnabled, onSetWirelessSpoofGuard)
                SettingToggleRow("Malicious Page & Tracker Block", settings.maliciousPageBlocker, onSetPageBlocker)
                SettingToggleRow("Background Data-Stealing Guard", settings.backgroundDataGuard, onSetBgGuard)
                SettingToggleRow("VPN DNS Privacy Filter", settings.dnsSinkholeEnabled, onSetDnsSinkhole)
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text("Done")
            }
        }
    )
}

@Composable
private fun SettingToggleRow(
    label: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
        modifier = Modifier.fillMaxWidth()
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.weight(1f)
        )
        Switch(checked = checked, onCheckedChange = onCheckedChange)
    }
}

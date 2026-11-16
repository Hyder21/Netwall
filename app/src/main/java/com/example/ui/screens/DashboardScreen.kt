package com.example.ui.screens

import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Analytics
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.GppBad
import androidx.compose.material.icons.filled.GppGood
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.VpnLock
import androidx.compose.material.icons.filled.WifiFind
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.R
import com.example.data.db.SecurityEventEntity
import com.example.security.NetworkDefenseSnapshot
import com.example.ui.components.ColourfulStatusPill
import com.example.ui.components.GradientFeatureCard
import com.example.ui.components.LiveTrafficSparkline
import com.example.ui.components.NetShieldLogoBadge
import com.example.ui.components.SeverityBadge
import com.example.ui.components.formatTimestamp
import com.example.ui.theme.LocalNetShieldColors
import com.example.ui.viewmodel.TrafficSample
import com.example.vpn.VpnTunnelStatus

@Composable
fun DashboardScreen(
    vpnStatus: VpnTunnelStatus,
    throughputHistory: List<TrafficSample>,
    networkSnapshot: NetworkDefenseSnapshot,
    offlinePortsCount: Int,
    totalPortsCount: Int,
    blockedAppsCount: Int,
    blockedDomainsCount: Int,
    sniffSpoofCount: Int,
    totalBlockedCount: Int,
    recentEvents: List<SecurityEventEntity>,
    onToggleVpn: () -> Unit,
    onNavigateToPorts: () -> Unit,
    onNavigateToFirewall: () -> Unit,
    onNavigateToScanner: () -> Unit,
    onNavigateToTraffic: () -> Unit,
    onNavigateToThreatDashboard: () -> Unit,
    modifier: Modifier = Modifier
) {
    val accents = LocalNetShieldColors.current
    val activeAccent by animateColorAsState(
        targetValue = if (vpnStatus.isRunning) accents.emerald else accents.amber,
        label = "vpn_accent"
    )

    LazyColumn(
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
        modifier = modifier.fillMaxSize()
    ) {
        // Hero Shield Card with Combined VPN + Firewall Master Toggle
        item {
            Surface(
                shape = MaterialTheme.shapes.large,
                color = MaterialTheme.colorScheme.surfaceContainer,
                border = BorderStroke(1.5.dp, activeAccent.copy(alpha = 0.55f)),
                modifier = Modifier.fillMaxWidth()
            ) {
                Box(modifier = Modifier.fillMaxWidth()) {
                    Image(
                        painter = painterResource(id = R.drawable.netshield_hero_1794580914009),
                        contentDescription = stringResource(id = R.string.cd_hero_banner),
                        contentScale = ContentScale.Crop,
                        alpha = if (accents.isDark) 0.38f else 0.16f,
                        modifier = Modifier
                            .matchParentSize()
                            .clip(MaterialTheme.shapes.large)
                    )
                    Box(
                        modifier = Modifier
                            .matchParentSize()
                            .background(
                                Brush.verticalGradient(
                                    colors = listOf(
                                        MaterialTheme.colorScheme.surface.copy(alpha = 0.55f),
                                        MaterialTheme.colorScheme.surface.copy(alpha = 0.92f)
                                    )
                                )
                            )
                    )

                    Column(modifier = Modifier.padding(18.dp)) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            NetShieldLogoBadge(
                                isActive = vpnStatus.isRunning,
                                size = 76.dp
                            )
                            Spacer(modifier = Modifier.width(14.dp))
                            Column(modifier = Modifier.weight(1f)) {
                                ColourfulStatusPill(
                                    label = if (vpnStatus.isRunning) "VPN + FIREWALL ARMED" else "SHIELD STANDBY",
                                    accent = activeAccent,
                                    icon = if (vpnStatus.isRunning) Icons.Default.GppGood else Icons.Default.GppBad
                                )
                                Spacer(modifier = Modifier.height(6.dp))
                                Text(
                                    text = if (vpnStatus.isRunning) "Network Protected" else "Enable NETWALL VPN",
                                    style = MaterialTheme.typography.headlineSmall,
                                    color = MaterialTheme.colorScheme.onSurface
                                )
                                Text(
                                    text = if (vpnStatus.isRunning) {
                                        "Tunnel ${vpnStatus.tunnelAddress} • Ports offline • Internet open"
                                    } else {
                                        "Tap below to engage unified VPN filter, port lockdown & local network monitor."
                                    },
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }

                        Spacer(modifier = Modifier.height(14.dp))

                        Row(
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            MetricMiniPill(
                                label = "Inspected",
                                value = "${vpnStatus.packetsInspected}",
                                color = accents.cyan,
                                modifier = Modifier.weight(1f)
                            )
                            MetricMiniPill(
                                label = "Blocked",
                                value = "$totalBlockedCount",
                                color = accents.coral,
                                modifier = Modifier.weight(1f)
                            )
                            MetricMiniPill(
                                label = "Ports Offline",
                                value = "$offlinePortsCount/$totalPortsCount",
                                color = accents.emerald,
                                modifier = Modifier.weight(1f)
                            )
                        }

                        Spacer(modifier = Modifier.height(14.dp))

                        Button(
                            onClick = onToggleVpn,
                            colors = ButtonDefaults.buttonColors(
                                containerColor = if (vpnStatus.isRunning) accents.coral else accents.cyan,
                                contentColor = if (vpnStatus.isRunning) Color.White else Color(0xFF061022)
                            ),
                            shape = RoundedCornerShape(14.dp),
                            modifier = Modifier
                                .fillMaxWidth()
                                .heightIn(min = 50.dp)
                                .testTag("vpn_master_toggle")
                        ) {
                            Icon(
                                imageVector = if (vpnStatus.isRunning) Icons.Default.PowerSettingsNew else Icons.Default.VpnLock,
                                contentDescription = null,
                                modifier = Modifier.size(20.dp)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = if (vpnStatus.isRunning) "Disconnect VPN + Firewall" else "Activate Combined VPN + Firewall",
                                style = MaterialTheme.typography.labelLarge,
                                fontWeight = FontWeight.Bold
                            )
                        }
                    }
                }
            }
        }

        // Live Real-Time Network Throughput Graph
        item {
            LiveTrafficSparkline(samples = throughputHistory)
        }

        // Threat Dashboard Visual Analytics Banner
        item {
            GradientFeatureCard(
                accent = accents.magenta,
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(MaterialTheme.shapes.medium)
                    .clickable(onClick = onNavigateToThreatDashboard)
                    .testTag("open_threat_dashboard_card")
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Surface(
                        shape = RoundedCornerShape(12.dp),
                        color = accents.magenta.copy(alpha = 0.2f)
                    ) {
                        Icon(
                            imageVector = Icons.Default.Analytics,
                            contentDescription = "Threat Dashboard",
                            tint = accents.magenta,
                            modifier = Modifier
                                .padding(10.dp)
                                .size(24.dp)
                        )
                    }
                    Spacer(modifier = Modifier.width(12.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "Threat Dashboard",
                            style = MaterialTheme.typography.titleSmall,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                        Text(
                            text = "Real-time charts for blocked connections & metadata threats",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    ColourfulStatusPill(label = "Charts →", accent = accents.magenta)
                }
            }
        }

        // 2x2 Colourful Security Pillars Grid (layout preserved)
        item {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Row(
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    PillarTile(
                        title = "Port Guard",
                        subtitle = "$offlinePortsCount of $totalPortsCount ports offline",
                        badge = "INTERNET OPEN",
                        accent = accents.emerald,
                        icon = Icons.Default.Lock,
                        onClick = onNavigateToPorts,
                        modifier = Modifier
                            .weight(1f)
                            .testTag("pillar_ports")
                    )
                    PillarTile(
                        title = "Local Network",
                        subtitle = "${networkSnapshot.transportType} • $sniffSpoofCount issue(s)",
                        badge = if (networkSnapshot.anomalies.isEmpty()) "LOCAL OK" else "ISSUE",
                        accent = if (networkSnapshot.anomalies.isEmpty()) accents.cyan else accents.coral,
                        icon = Icons.Default.WifiFind,
                        onClick = onNavigateToPorts,
                        modifier = Modifier
                            .weight(1f)
                            .testTag("pillar_sniff_spoof")
                    )
                }
                Row(
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    PillarTile(
                        title = "App & Page Guard",
                        subtitle = "$blockedAppsCount apps • $blockedDomainsCount domains",
                        badge = "DATA SHIELD",
                        accent = accents.amber,
                        icon = Icons.Default.Apps,
                        onClick = onNavigateToFirewall,
                        modifier = Modifier
                            .weight(1f)
                            .testTag("pillar_firewall")
                    )
                    PillarTile(
                        title = "Metadata Scan",
                        subtitle = "EXIF, QR & malformed emoji",
                        badge = "DEEP INSPECT",
                        accent = accents.violet,
                        icon = Icons.Default.QrCodeScanner,
                        onClick = onNavigateToScanner,
                        modifier = Modifier
                            .weight(1f)
                            .testTag("pillar_scanner")
                    )
                }
            }
        }

        // Recent Real-Time Threat & Protection Feed Header
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "Recent Shield Activity",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onBackground
                )
                Text(
                    text = "View All",
                    style = MaterialTheme.typography.labelLarge,
                    color = accents.cyan,
                    modifier = Modifier
                        .clip(RoundedCornerShape(8.dp))
                        .clickable(onClick = onNavigateToTraffic)
                        .padding(horizontal = 10.dp, vertical = 6.dp)
                        .testTag("view_all_traffic")
                )
            }
        }

        if (recentEvents.isEmpty()) {
            item {
                Surface(
                    shape = MaterialTheme.shapes.medium,
                    color = MaterialTheme.colorScheme.surfaceContainer,
                    border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally,
                        modifier = Modifier.padding(24.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Default.GppGood,
                            contentDescription = null,
                            tint = accents.emerald,
                            modifier = Modifier.size(36.dp)
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = "Perimeter Quiet",
                            style = MaterialTheme.typography.titleSmall
                        )
                        Text(
                            text = "Activate VPN + Firewall or run a Port Audit or Network Audit to inspect live events.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        } else {
            items(recentEvents.take(5), key = { it.id }) { event ->
                EventMiniRow(event = event, onClick = onNavigateToTraffic)
            }
        }
    }
}

@Composable
private fun MetricMiniPill(
    label: String,
    value: String,
    color: Color,
    modifier: Modifier = Modifier
) {
    Surface(
        shape = RoundedCornerShape(12.dp),
        color = color.copy(alpha = 0.13f),
        border = BorderStroke(1.dp, color.copy(alpha = 0.35f)),
        modifier = modifier
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            modifier = Modifier.padding(vertical = 8.dp, horizontal = 6.dp)
        ) {
            Text(
                text = value,
                style = MaterialTheme.typography.titleMedium,
                color = color,
                fontWeight = FontWeight.Bold,
                maxLines = 1
            )
            Text(
                text = label,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}

@Composable
private fun PillarTile(
    title: String,
    subtitle: String,
    badge: String,
    accent: Color,
    icon: ImageVector,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    GradientFeatureCard(
        accent = accent,
        modifier = modifier
            .heightIn(min = 122.dp)
            .clip(MaterialTheme.shapes.medium)
            .clickable(onClick = onClick)
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
                modifier = Modifier.fillMaxWidth()
            ) {
                Surface(
                    shape = RoundedCornerShape(10.dp),
                    color = accent.copy(alpha = 0.22f)
                ) {
                    Icon(
                        imageVector = icon,
                        contentDescription = title,
                        tint = accent,
                        modifier = Modifier
                            .padding(7.dp)
                            .size(20.dp)
                    )
                }
                Text(
                    text = badge,
                    style = MaterialTheme.typography.labelSmall,
                    color = accent,
                    fontWeight = FontWeight.Bold,
                    maxLines = 1
                )
            }
            Text(
                text = title,
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.onSurface,
                maxLines = 1
            )
            Text(
                text = subtitle,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}

@Composable
private fun EventMiniRow(
    event: SecurityEventEntity,
    onClick: () -> Unit
) {
    Surface(
        shape = MaterialTheme.shapes.small,
        color = MaterialTheme.colorScheme.surfaceContainer,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
        modifier = Modifier
            .fillMaxWidth()
            .clip(MaterialTheme.shapes.small)
            .clickable(onClick = onClick)
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.padding(12.dp)
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = event.title,
                    style = MaterialTheme.typography.titleSmall,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Spacer(modifier = Modifier.height(2.dp))
                Text(
                    text = "${event.source} → ${event.target} • ${formatTimestamp(event.timestamp)}",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
            Spacer(modifier = Modifier.width(8.dp))
            SeverityBadge(severity = event.severity)
        }
    }
}

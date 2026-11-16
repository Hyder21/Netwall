package com.example.ui.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Radar
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material.icons.filled.WifiFind
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.example.data.db.PortRuleEntity
import com.example.security.NetworkDefenseSnapshot
import com.example.ui.components.ColourfulStatusPill
import com.example.ui.components.GradientFeatureCard
import com.example.ui.components.SeverityBadge
import com.example.ui.theme.LocalNetShieldColors

@Composable
fun PortGuardScreen(
    portRules: List<PortRuleEntity>,
    isScanningPorts: Boolean,
    networkSnapshot: NetworkDefenseSnapshot,
    isAuditingNetwork: Boolean,
    onScanPorts: () -> Unit,
    onMarkServicePortsOffline: () -> Unit,
    onTogglePortOffline: (Int, Boolean) -> Unit,
    onRunNetworkAudit: () -> Unit,
    modifier: Modifier = Modifier
) {
    val accents = LocalNetShieldColors.current
    val offlineCount = portRules.count { it.isMarkedOffline }
    val openDetectedCount = portRules.count { it.isOpenDetected }

    LazyColumn(
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
        modifier = modifier.fillMaxSize()
    ) {
        // Card 1: Port Lockdown (Service Ports Offline • Internet Unrestricted)
        item {
            GradientFeatureCard(accent = accents.emerald, modifier = Modifier.fillMaxWidth()) {
                Column {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        ColourfulStatusPill(
                            label = "PORT GUARD • INTERNET OPEN",
                            accent = accents.emerald,
                            icon = Icons.Default.VisibilityOff
                        )
                        ColourfulStatusPill(
                            label = "$offlineCount/${portRules.size} OFFLINE",
                            accent = accents.cyan
                        )
                    }
                    Spacer(modifier = Modifier.height(10.dp))
                    Text(
                        text = "Keep Service Ports Offline",
                        style = MaterialTheme.typography.titleLarge
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = if (openDetectedCount > 0) {
                            "Audited local interfaces: $openDetectedCount open port(s) found. Service ports are kept offline while DNS/HTTP/HTTPS internet stays active."
                        } else {
                            "Probes local listening sockets and keeps unused service ports offline without blocking normal internet browsing."
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(10.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Button(
                            onClick = onScanPorts,
                            enabled = !isScanningPorts,
                            colors = ButtonDefaults.buttonColors(
                                containerColor = accents.cyan,
                                contentColor = Color(0xFF061022)
                            ),
                            modifier = Modifier
                                .weight(1f)
                                .heightIn(min = 48.dp)
                                .testTag("scan_ports_button")
                        ) {
                            if (isScanningPorts) {
                                CircularProgressIndicator(
                                    modifier = Modifier.size(16.dp),
                                    strokeWidth = 2.dp,
                                    color = Color(0xFF061022)
                                )
                            } else {
                                Icon(Icons.Default.Radar, contentDescription = null, modifier = Modifier.size(18.dp))
                            }
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(if (isScanningPorts) "Scanning..." else "Scan Ports")
                        }
                        OutlinedButton(
                            onClick = onMarkServicePortsOffline,
                            border = BorderStroke(1.dp, accents.emerald),
                            modifier = Modifier
                                .weight(1f)
                                .heightIn(min = 48.dp)
                                .testTag("lock_all_ports_button")
                        ) {
                            Icon(
                                Icons.Default.Lock,
                                contentDescription = null,
                                tint = accents.emerald,
                                modifier = Modifier.size(18.dp)
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Lock Services", color = accents.emerald)
                        }
                    }
                }
            }
        }

        // Card 2: Real Sniffing & Wireless Spoofing Detection (same card layout, zero fake probes)
        item {
            val hasAnomalies = networkSnapshot.anomalies.isNotEmpty()
            val cardAccent = if (hasAnomalies) accents.coral else accents.cyan

            GradientFeatureCard(accent = cardAccent, modifier = Modifier.fillMaxWidth()) {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        ColourfulStatusPill(
                            label = if (hasAnomalies) "LOCAL NETWORK ISSUE" else "LOCAL NETWORK MONITOR",
                            accent = cardAccent,
                            icon = Icons.Default.WifiFind
                        )
                        ColourfulStatusPill(
                            label = if (networkSnapshot.isInternetValidated) "INTERNET ACTIVE" else networkSnapshot.transportType.uppercase(),
                            accent = if (networkSnapshot.isInternetValidated) accents.emerald else accents.amber
                        )
                    }

                    Text(
                        text = "Local Network Issues",
                        style = MaterialTheme.typography.titleMedium
                    )
                    Text(
                        text = "Inspects live Wi-Fi encryption, AP BSSID shifts, security downgrades, ARP conflicts, gateway MAC changes, capture interfaces, and DNS resolvers for local network issues.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )

                    Surface(
                        shape = RoundedCornerShape(12.dp),
                        color = MaterialTheme.colorScheme.surface.copy(alpha = 0.8f),
                        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(
                            verticalArrangement = Arrangement.spacedBy(4.dp),
                            modifier = Modifier.padding(10.dp)
                        ) {
                            TelemetryRow("Link / Transport", "${networkSnapshot.transportType} (${networkSnapshot.wifiSecurity})")
                            TelemetryRow("Gateway IP / MAC", "${networkSnapshot.gatewayIp} • ${networkSnapshot.gatewayMac}")
                            TelemetryRow("DNS Servers", networkSnapshot.dnsServers.joinToString(", ").ifBlank { "System Default" })
                            TelemetryRow(
                                "Private DNS / ARP",
                                "${if (networkSnapshot.isPrivateDnsActive) "DoT Active" else "Standard DNS"} • ${networkSnapshot.arpEntryCount} ARP host(s)"
                            )
                            TelemetryRow("Active Interfaces", networkSnapshot.activeInterfaces.joinToString(", ").ifBlank { "None" })
                        }
                    }

                    if (networkSnapshot.anomalies.isEmpty()) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Default.CheckCircle,
                                contentDescription = null,
                                tint = accents.emerald,
                                modifier = Modifier.size(16.dp)
                            )
                            Text(
                                text = "No local network issues, capture interfaces, or gateway conflicts detected.",
                                style = MaterialTheme.typography.bodySmall,
                                color = accents.emerald
                            )
                        }
                    } else {
                        networkSnapshot.anomalies.forEach { anomaly ->
                            Surface(
                                shape = RoundedCornerShape(10.dp),
                                color = MaterialTheme.colorScheme.surface.copy(alpha = 0.9f),
                                border = BorderStroke(1.dp, accents.coral.copy(alpha = 0.5f)),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(modifier = Modifier.padding(10.dp)) {
                                    Row(
                                        verticalAlignment = Alignment.CenterVertically,
                                        horizontalArrangement = Arrangement.SpaceBetween,
                                        modifier = Modifier.fillMaxWidth()
                                    ) {
                                        Text(
                                            text = anomaly.title,
                                            style = MaterialTheme.typography.labelLarge,
                                            color = accents.coral,
                                            modifier = Modifier.weight(1f)
                                        )
                                        SeverityBadge(severity = anomaly.severity)
                                    }
                                    Spacer(modifier = Modifier.height(3.dp))
                                    Text(
                                        text = anomaly.details,
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurface
                                    )
                                }
                            }
                        }
                    }

                    Button(
                        onClick = onRunNetworkAudit,
                        enabled = !isAuditingNetwork,
                        colors = ButtonDefaults.buttonColors(
                            containerColor = accents.violet,
                            contentColor = Color.White
                        ),
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(min = 48.dp)
                            .testTag("run_network_audit_button")
                    ) {
                        if (isAuditingNetwork) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(16.dp),
                                strokeWidth = 2.dp,
                                color = Color.White
                            )
                        } else {
                            Icon(Icons.Default.WifiFind, contentDescription = null, modifier = Modifier.size(18.dp))
                        }
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(if (isAuditingNetwork) "Checking Network..." else "Check Local Network Issues")
                    }
                }
            }
        }

        // Device Ports Table (layout preserved)
        item {
            Text(
                text = "Port Firewall Matrix (${portRules.size} Ports)",
                style = MaterialTheme.typography.titleMedium
            )
        }

        items(portRules, key = { it.port }) { rule ->
            PortRuleRow(
                rule = rule,
                onToggleOffline = { offline -> onTogglePortOffline(rule.port, offline) }
            )
        }
    }
}

@Composable
private fun TelemetryRow(label: String, value: String) {
    Row(
        horizontalArrangement = Arrangement.SpaceBetween,
        modifier = Modifier.fillMaxWidth()
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(modifier = Modifier.width(8.dp))
        Text(
            text = value,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurface,
            fontWeight = FontWeight.SemiBold
        )
    }
}

@Composable
private fun PortRuleRow(
    rule: PortRuleEntity,
    onToggleOffline: (Boolean) -> Unit
) {
    val accents = LocalNetShieldColors.current
    val isInternetCorePort = rule.port in setOf(53, 80, 443)
    val statusColor = when {
        rule.isMarkedOffline -> accents.emerald
        rule.isOpenDetected -> accents.coral
        else -> accents.cyan
    }
    val statusLabel = when {
        rule.isMarkedOffline -> "OFFLINE • SECURED"
        rule.isOpenDetected -> "OPEN • EXPOSED"
        isInternetCorePort -> "ONLINE • INTERNET"
        else -> "MONITORING"
    }

    Surface(
        shape = MaterialTheme.shapes.small,
        color = MaterialTheme.colorScheme.surfaceContainer,
        border = BorderStroke(1.dp, statusColor.copy(alpha = 0.3f)),
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp)
        ) {
            Surface(
                shape = RoundedCornerShape(10.dp),
                color = statusColor.copy(alpha = 0.16f)
            ) {
                Text(
                    text = ":${rule.port}",
                    style = MaterialTheme.typography.labelLarge,
                    color = statusColor,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.padding(horizontal = 10.dp, vertical = 8.dp)
                )
            }
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    Text(
                        text = "${rule.serviceName} (${rule.protocol})",
                        style = MaterialTheme.typography.titleSmall
                    )
                    if (rule.blockedProbeCount > 0) {
                        ColourfulStatusPill(
                            label = "${rule.blockedProbeCount} blocked",
                            accent = accents.amber
                        )
                    }
                }
                Text(
                    text = rule.riskReason,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(modifier = Modifier.height(4.dp))
                ColourfulStatusPill(
                    label = statusLabel,
                    accent = statusColor
                )
            }
            Spacer(modifier = Modifier.width(8.dp))
            Switch(
                checked = rule.isMarkedOffline,
                onCheckedChange = onToggleOffline,
                colors = SwitchDefaults.colors(
                    checkedThumbColor = Color(0xFF061022),
                    checkedTrackColor = accents.emerald
                ),
                modifier = Modifier.testTag("port_switch_${rule.port}")
            )
        }
    }
}

package com.example.ui.screens

import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.drawable.BitmapDrawable
import android.graphics.drawable.Drawable
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
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
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.data.db.AppFirewallRuleEntity
import com.example.data.db.AppPolicy
import com.example.data.db.BlockedDomainEntity
import com.example.security.QrScanResult
import com.example.ui.components.ColourfulStatusPill
import com.example.ui.components.GradientFeatureCard
import com.example.ui.components.SeverityBadge
import com.example.ui.components.formatBytes
import com.example.ui.theme.LocalNetShieldColors
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

@Composable
fun AppFirewallScreen(
    appRules: List<AppFirewallRuleEntity>,
    blockedDomains: List<BlockedDomainEntity>,
    isRefreshingApps: Boolean,
    urlCheckResult: QrScanResult?,
    onRefreshApps: () -> Unit,
    onSetAppPolicy: (String, String, AppPolicy) -> Unit,
    onAddBlockedDomain: (String) -> Unit,
    onToggleDomain: (String, Boolean) -> Unit,
    onRemoveCustomDomain: (String) -> Unit,
    onCheckUrlSafety: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    val accents = LocalNetShieldColors.current
    var subTab by remember { mutableIntStateOf(0) } // 0 = Apps, 1 = Pages/Domains
    var searchQuery by remember { mutableStateOf("") }
    var appFilter by remember { mutableIntStateOf(0) } // 0 = All, 1 = High Bg, 2 = Blocked
    var domainInput by remember { mutableStateOf("") }

    Column(modifier = modifier.fillMaxSize()) {
        // Sub-Tab Switcher
        Row(
            horizontalArrangement = Arrangement.spacedBy(10.dp),
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 10.dp)
        ) {
            SubTabButton(
                title = "App Data Guard (${appRules.size})",
                icon = Icons.Default.Apps,
                selected = subTab == 0,
                accent = accents.cyan,
                onClick = { subTab = 0 },
                modifier = Modifier
                    .weight(1f)
                    .testTag("firewall_tab_apps")
            )
            SubTabButton(
                title = "Page Blocker (${blockedDomains.count { it.isEnabled }})",
                icon = Icons.Default.Language,
                selected = subTab == 1,
                accent = accents.magenta,
                onClick = { subTab = 1 },
                modifier = Modifier
                    .weight(1f)
                    .testTag("firewall_tab_pages")
            )
        }

        if (subTab == 0) {
            val filteredApps = remember(appRules, searchQuery, appFilter) {
                appRules.filter { app ->
                    val matchesQuery = searchQuery.isBlank() ||
                        app.appName.contains(searchQuery, ignoreCase = true) ||
                        app.packageName.contains(searchQuery, ignoreCase = true)
                    val matchesFilter = when (appFilter) {
                        1 -> app.backgroundAlertFlag || app.txBytes > 32 * 1024
                        2 -> app.policy != AppPolicy.ALLOW.name
                        else -> true
                    }
                    matchesQuery && matchesFilter
                }
            }

            LazyColumn(
                contentPadding = PaddingValues(horizontal = 16.dp, vertical = 6.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
                modifier = Modifier.fillMaxSize()
            ) {
                item {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        OutlinedTextField(
                            value = searchQuery,
                            onValueChange = { searchQuery = it },
                            placeholder = { Text("Search installed apps...") },
                            leadingIcon = { Icon(Icons.Default.Search, contentDescription = null) },
                            singleLine = true,
                            shape = RoundedCornerShape(14.dp),
                            modifier = Modifier
                                .weight(1f)
                                .testTag("app_search_input")
                        )
                        IconButton(
                            onClick = onRefreshApps,
                            enabled = !isRefreshingApps,
                            modifier = Modifier
                                .size(48.dp)
                                .testTag("refresh_apps_button")
                        ) {
                            Icon(Icons.Default.Refresh, contentDescription = "Refresh app usage")
                        }
                    }
                }

                item {
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        listOf("All Apps", "High Upload", "Restricted").forEachIndexed { idx, label ->
                            FilterChip(
                                selected = appFilter == idx,
                                onClick = { appFilter = idx },
                                label = { Text(label) },
                                colors = FilterChipDefaults.filterChipColors(
                                    selectedContainerColor = accents.cyan.copy(alpha = 0.2f),
                                    selectedLabelColor = accents.cyan
                                )
                            )
                        }
                    }
                }

                items(filteredApps, key = { it.packageName }) { app ->
                    AppRuleCard(
                        app = app,
                        onSelectPolicy = { policy ->
                            onSetAppPolicy(app.packageName, app.appName, policy)
                        }
                    )
                }
            }
        } else {
            LazyColumn(
                contentPadding = PaddingValues(horizontal = 16.dp, vertical = 6.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
                modifier = Modifier.fillMaxSize()
            ) {
                item {
                    GradientFeatureCard(accent = accents.magenta, modifier = Modifier.fillMaxWidth()) {
                        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                            Text(
                                text = "Malicious Page & Tracker Blocker",
                                style = MaterialTheme.typography.titleMedium
                            )
                            Text(
                                text = "Inspect any URL/page before visiting or add domains directly to the VPN DNS sinkhole.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            OutlinedTextField(
                                value = domainInput,
                                onValueChange = { domainInput = it },
                                placeholder = { Text("e.g. suspicious-login.example or https://...") },
                                singleLine = true,
                                shape = RoundedCornerShape(12.dp),
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .testTag("domain_block_input")
                            )
                            Row(
                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Button(
                                    onClick = {
                                        if (domainInput.isNotBlank()) onCheckUrlSafety(domainInput)
                                    },
                                    colors = ButtonDefaults.buttonColors(
                                        containerColor = accents.violet,
                                        contentColor = Color.White
                                    ),
                                    modifier = Modifier
                                        .weight(1f)
                                        .heightIn(min = 48.dp)
                                        .testTag("check_url_button")
                                ) {
                                    Text("Check Page")
                                }
                                Button(
                                    onClick = {
                                        if (domainInput.isNotBlank()) {
                                            onAddBlockedDomain(domainInput)
                                            domainInput = ""
                                        }
                                    },
                                    colors = ButtonDefaults.buttonColors(
                                        containerColor = accents.coral,
                                        contentColor = Color.White
                                    ),
                                    modifier = Modifier
                                        .weight(1f)
                                        .heightIn(min = 48.dp)
                                        .testTag("add_block_domain_button")
                                ) {
                                    Icon(Icons.Default.Add, contentDescription = null, modifier = Modifier.size(18.dp))
                                    Spacer(modifier = Modifier.width(4.dp))
                                    Text("Block Domain")
                                }
                            }

                            if (urlCheckResult != null) {
                                Surface(
                                    shape = RoundedCornerShape(12.dp),
                                    color = MaterialTheme.colorScheme.surface.copy(alpha = 0.85f),
                                    border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
                                    modifier = Modifier.fillMaxWidth()
                                ) {
                                    Column(modifier = Modifier.padding(10.dp)) {
                                        Row(
                                            verticalAlignment = Alignment.CenterVertically,
                                            horizontalArrangement = Arrangement.SpaceBetween,
                                            modifier = Modifier.fillMaxWidth()
                                        ) {
                                            Text(
                                                text = urlCheckResult.payloadType,
                                                style = MaterialTheme.typography.titleSmall
                                            )
                                            SeverityBadge(severity = urlCheckResult.threatLevel)
                                        }
                                        Spacer(modifier = Modifier.height(4.dp))
                                        urlCheckResult.findings.forEach { finding ->
                                            Text(
                                                text = "• ${finding.title}: ${finding.description}",
                                                style = MaterialTheme.typography.bodySmall,
                                                color = MaterialTheme.colorScheme.onSurfaceVariant
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                items(blockedDomains, key = { it.domain }) { domain ->
                    Surface(
                        shape = MaterialTheme.shapes.small,
                        color = MaterialTheme.colorScheme.surfaceContainer,
                        border = BorderStroke(
                            1.dp,
                            if (domain.isEnabled) accents.coral.copy(alpha = 0.3f) else MaterialTheme.colorScheme.outlineVariant
                        ),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp)
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = domain.domain,
                                    style = MaterialTheme.typography.titleSmall,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                                Text(
                                    text = "${domain.category} • ${domain.hitCount} blocked",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                            if (!domain.isBuiltIn) {
                                IconButton(
                                    onClick = { onRemoveCustomDomain(domain.domain) },
                                    modifier = Modifier.size(48.dp)
                                ) {
                                    Icon(
                                        Icons.Default.Delete,
                                        contentDescription = "Remove custom domain",
                                        tint = accents.coral
                                    )
                                }
                            }
                            Switch(
                                checked = domain.isEnabled,
                                onCheckedChange = { onToggleDomain(domain.domain, it) },
                                colors = SwitchDefaults.colors(
                                    checkedThumbColor = Color.White,
                                    checkedTrackColor = accents.coral
                                )
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun SubTabButton(
    title: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    selected: Boolean,
    accent: Color,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(14.dp),
        color = if (selected) accent.copy(alpha = 0.2f) else MaterialTheme.colorScheme.surfaceContainer,
        border = BorderStroke(1.dp, if (selected) accent else MaterialTheme.colorScheme.outlineVariant),
        modifier = modifier.heightIn(min = 48.dp)
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.Center,
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 10.dp)
        ) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = if (selected) accent else MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(18.dp)
            )
            Spacer(modifier = Modifier.width(6.dp))
            Text(
                text = title,
                style = MaterialTheme.typography.labelLarge,
                color = if (selected) accent else MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}

@Composable
private fun AppRuleCard(
    app: AppFirewallRuleEntity,
    onSelectPolicy: (AppPolicy) -> Unit
) {
    val accents = LocalNetShieldColors.current
    val context = LocalContext.current
    val iconBitmap by produceState<ImageBitmap?>(initialValue = null, app.packageName) {
        value = withContext(Dispatchers.IO) {
            runCatching {
                val drawable = context.packageManager.getApplicationIcon(app.packageName)
                drawableToBitmap(drawable).asImageBitmap()
            }.getOrNull()
        }
    }

    val currentPolicy = runCatching { AppPolicy.valueOf(app.policy) }.getOrDefault(AppPolicy.ALLOW)

    Surface(
        shape = MaterialTheme.shapes.small,
        color = MaterialTheme.colorScheme.surfaceContainer,
        border = BorderStroke(
            1.dp,
            when (currentPolicy) {
                AppPolicy.BLOCK_ALL -> accents.coral.copy(alpha = 0.45f)
                AppPolicy.BLOCK_BACKGROUND -> accents.amber.copy(alpha = 0.45f)
                AppPolicy.ALLOW -> MaterialTheme.colorScheme.outlineVariant
            }
        ),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (iconBitmap != null) {
                    Image(
                        bitmap = iconBitmap!!,
                        contentDescription = app.appName,
                        modifier = Modifier
                            .size(40.dp)
                            .clip(RoundedCornerShape(10.dp))
                    )
                } else {
                    Surface(
                        shape = RoundedCornerShape(10.dp),
                        color = accents.cyan.copy(alpha = 0.16f),
                        modifier = Modifier.size(40.dp)
                    ) {
                        Icon(
                            Icons.Default.Apps,
                            contentDescription = app.appName,
                            tint = accents.cyan,
                            modifier = Modifier.padding(8.dp)
                        )
                    }
                }
                Spacer(modifier = Modifier.width(12.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        Text(
                            text = app.appName,
                            style = MaterialTheme.typography.titleSmall,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                            modifier = Modifier.weight(1f, fill = false)
                        )
                        if (app.backgroundAlertFlag) {
                            ColourfulStatusPill(
                                label = "HIGH TX",
                                accent = accents.amber,
                                icon = Icons.Default.Warning
                            )
                        }
                    }
                    Text(
                        text = "${app.packageName} • ↑ ${formatBytes(app.txBytes)}  ↓ ${formatBytes(app.rxBytes)}",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }

            Spacer(modifier = Modifier.height(10.dp))

            Row(
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                PolicyChip(
                    label = "Allow",
                    selected = currentPolicy == AppPolicy.ALLOW,
                    accent = accents.emerald,
                    onClick = { onSelectPolicy(AppPolicy.ALLOW) },
                    modifier = Modifier.weight(1f)
                )
                PolicyChip(
                    label = "Block Bg",
                    selected = currentPolicy == AppPolicy.BLOCK_BACKGROUND,
                    accent = accents.amber,
                    onClick = { onSelectPolicy(AppPolicy.BLOCK_BACKGROUND) },
                    modifier = Modifier.weight(1f)
                )
                PolicyChip(
                    label = "Block All",
                    selected = currentPolicy == AppPolicy.BLOCK_ALL,
                    accent = accents.coral,
                    onClick = { onSelectPolicy(AppPolicy.BLOCK_ALL) },
                    modifier = Modifier.weight(1f)
                )
            }
        }
    }
}

@Composable
private fun PolicyChip(
    label: String,
    selected: Boolean,
    accent: Color,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(10.dp),
        color = if (selected) accent.copy(alpha = 0.22f) else MaterialTheme.colorScheme.surface,
        border = BorderStroke(1.dp, if (selected) accent else MaterialTheme.colorScheme.outlineVariant),
        modifier = modifier.heightIn(min = 40.dp)
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.Center,
            modifier = Modifier.padding(horizontal = 6.dp, vertical = 6.dp)
        ) {
            Text(
                text = label,
                style = MaterialTheme.typography.labelSmall,
                color = if (selected) accent else MaterialTheme.colorScheme.onSurfaceVariant,
                fontWeight = if (selected) FontWeight.Bold else FontWeight.Medium,
                maxLines = 1
            )
        }
    }
}

private fun drawableToBitmap(drawable: Drawable): Bitmap {
    if (drawable is BitmapDrawable && drawable.bitmap != null) {
        return drawable.bitmap
    }
    val w = drawable.intrinsicWidth.coerceAtLeast(1)
    val h = drawable.intrinsicHeight.coerceAtLeast(1)
    val bitmap = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
    val canvas = Canvas(bitmap)
    drawable.setBounds(0, 0, canvas.width, canvas.height)
    drawable.draw(canvas)
    return bitmap
}

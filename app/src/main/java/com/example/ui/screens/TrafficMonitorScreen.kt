package com.example.ui.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.DeleteSweep
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.data.db.SecurityEventEntity
import com.example.ui.components.ColourfulStatusPill
import com.example.ui.components.SeverityBadge
import com.example.ui.components.formatTimestamp
import com.example.ui.theme.LocalNetShieldColors

@Composable
fun TrafficMonitorScreen(
    events: List<SecurityEventEntity>,
    onClearEvents: () -> Unit,
    modifier: Modifier = Modifier
) {
    val accents = LocalNetShieldColors.current
    var search by remember { mutableStateOf("") }
    var selectedFilter by remember { mutableStateOf("ALL") }
    var inspectedEvent by remember { mutableStateOf<SecurityEventEntity?>(null) }

    val filters = listOf(
        "ALL" to "All Events",
        "SNIFFING_ALERT" to "LAN Issues",
        "WIRELESS_SPOOFING" to "Wi-Fi Issues",
        "PORT_SCAN" to "Ports",
        "DATA_THEFT_APP" to "App Data Theft",
        "MALICIOUS_PAGE" to "Pages",
        "METADATA_THREAT" to "Metadata"
    )

    val filtered = remember(events, search, selectedFilter) {
        events.filter { ev ->
            val matchCat = selectedFilter == "ALL" || ev.category == selectedFilter
            val matchSearch = search.isBlank() ||
                ev.title.contains(search, ignoreCase = true) ||
                ev.source.contains(search, ignoreCase = true) ||
                ev.target.contains(search, ignoreCase = true) ||
                ev.details.contains(search, ignoreCase = true)
            matchCat && matchSearch
        }
    }

    Column(modifier = modifier.fillMaxSize()) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 10.dp)
        ) {
            OutlinedTextField(
                value = search,
                onValueChange = { search = it },
                placeholder = { Text("Filter IP, port, app, domain...") },
                leadingIcon = { Icon(Icons.Default.Search, contentDescription = null) },
                singleLine = true,
                shape = RoundedCornerShape(14.dp),
                modifier = Modifier
                    .weight(1f)
                    .testTag("traffic_search_input")
            )
            IconButton(
                onClick = onClearEvents,
                modifier = Modifier
                    .size(48.dp)
                    .testTag("clear_events_button")
            ) {
                Icon(
                    Icons.Default.DeleteSweep,
                    contentDescription = "Clear security event log",
                    tint = accents.coral
                )
            }
        }

        LazyRow(
            contentPadding = PaddingValues(horizontal = 16.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            items(filters) { (key, label) ->
                FilterChip(
                    selected = selectedFilter == key,
                    onClick = { selectedFilter = key },
                    label = { Text(label) },
                    colors = FilterChipDefaults.filterChipColors(
                        selectedContainerColor = accents.cyan.copy(alpha = 0.2f),
                        selectedLabelColor = accents.cyan
                    )
                )
            }
        }

        Spacer(modifier = Modifier.height(6.dp))

        if (filtered.isEmpty()) {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center,
                modifier = Modifier
                    .fillMaxSize()
                    .padding(32.dp)
            ) {
                Icon(
                    imageVector = Icons.Default.Shield,
                    contentDescription = null,
                    tint = accents.cyan,
                    modifier = Modifier.size(48.dp)
                )
                Spacer(modifier = Modifier.height(10.dp))
                Text(
                    text = "No Matching Events",
                    style = MaterialTheme.typography.titleMedium
                )
                Text(
                    text = "All inspected network flows and payloads are recorded here in real time.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        } else {
            LazyColumn(
                contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
                modifier = Modifier.fillMaxSize()
            ) {
                items(filtered, key = { it.id }) { event ->
                    Surface(
                        shape = MaterialTheme.shapes.small,
                        color = MaterialTheme.colorScheme.surfaceContainer,
                        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(MaterialTheme.shapes.small)
                            .clickable { inspectedEvent = event }
                    ) {
                        Column(
                            verticalArrangement = Arrangement.spacedBy(6.dp),
                            modifier = Modifier.padding(12.dp)
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween,
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text(
                                    text = event.title,
                                    style = MaterialTheme.typography.titleSmall,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                    modifier = Modifier.weight(1f)
                                )
                                Spacer(modifier = Modifier.width(8.dp))
                                SeverityBadge(severity = event.severity)
                            }
                            Text(
                                text = "${event.source} → ${event.target}",
                                style = MaterialTheme.typography.labelMedium,
                                color = accents.cyan,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                            Text(
                                text = event.details,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                maxLines = 2,
                                overflow = TextOverflow.Ellipsis
                            )
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween,
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                ColourfulStatusPill(
                                    label = event.actionTaken,
                                    accent = accents.emerald
                                )
                                Text(
                                    text = formatTimestamp(event.timestamp),
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    inspectedEvent?.let { ev ->
        AlertDialog(
            onDismissRequest = { inspectedEvent = null },
            title = { Text(ev.title, style = MaterialTheme.typography.titleLarge) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    SeverityBadge(severity = ev.severity)
                    val categoryLabel = when (ev.category) {
                        "SNIFFING_ALERT" -> "Local Network Issue (LAN)"
                        "WIRELESS_SPOOFING" -> "Local Network Issue (Wi-Fi)"
                        "PORT_SCAN" -> "Port Guard"
                        "DATA_THEFT_APP" -> "App Data Theft"
                        "MALICIOUS_PAGE" -> "Malicious Page"
                        "METADATA_THREAT" -> "Metadata Threat"
                        else -> ev.category
                    }
                    Text("Category: $categoryLabel", style = MaterialTheme.typography.labelMedium)
                    Text("Source: ${ev.source}", style = MaterialTheme.typography.labelMedium)
                    Text("Target: ${ev.target}", style = MaterialTheme.typography.labelMedium)
                    Text(
                        "Action: ${ev.actionTaken}",
                        style = MaterialTheme.typography.labelMedium,
                        color = accents.emerald,
                        fontWeight = FontWeight.Bold
                    )
                    Text(ev.details, style = MaterialTheme.typography.bodyMedium)
                }
            },
            confirmButton = {
                TextButton(onClick = { inspectedEvent = null }) {
                    Text("Close")
                }
            }
        )
    }
}

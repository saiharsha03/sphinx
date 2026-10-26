package dev.sphinx

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp

private val Dark = darkColorScheme(
    primary = Color(0xFFE8A33D), onPrimary = Color(0xFF17151C), background = Color(0xFF17151C), surface = Color(0xFF17151C),
    surfaceVariant = Color(0xFF242129), onBackground = Color(0xFFF1ECE4), onSurface = Color(0xFFF1ECE4), onSurfaceVariant = Color(0xFFB9B2A8),
    outlineVariant = Color(0xFF39353F), error = Color(0xFFF2876F),
)
private val Light = lightColorScheme(
    primary = Color(0xFFA8650F), onPrimary = Color.White, background = Color(0xFFF8F5F0), surface = Color(0xFFF8F5F0),
    surfaceVariant = Color(0xFFEDE7DE), onBackground = Color(0xFF221F26), onSurface = Color(0xFF221F26), onSurfaceVariant = Color(0xFF5E5850),
    outlineVariant = Color(0xFFDDD5C9), error = Color(0xFFB3261E),
)

@Composable
fun SphinxTheme(content: @Composable () -> Unit) {
    val scheme = if (isSystemInDarkTheme()) Dark else Light
    // Text outside a Surface takes LocalContentColor, which defaults to black: give every screen its scheme's ink
    // (owner, 2026-10-26: black text on the dark background).
    MaterialTheme(colorScheme = scheme) {
        androidx.compose.runtime.CompositionLocalProvider(androidx.compose.material3.LocalContentColor provides scheme.onBackground, content = content)
    }
}

/** A small uppercase label over a section. */
@Composable
fun Kicker(text: String, modifier: Modifier = Modifier) =
    Text(text.uppercase(), modifier, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)

/** "Label   value" on one row, under a rule. */
@Composable
fun Fact(label: String, value: String) {
    Column(Modifier.fillMaxWidth()) {
        HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
        Row(Modifier.padding(vertical = 8.dp)) {
            Text(label, Modifier.width(110.dp), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(value, style = MaterialTheme.typography.bodySmall)
        }
    }
}

package dev.sphinx

import android.provider.Settings
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.CubicBezierEasing
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.keyframes
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.snap
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Shapes
import androidx.compose.material3.Text
import androidx.compose.material3.TextFieldColors
import androidx.compose.material3.Typography
import androidx.compose.material3.VerticalDivider
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.scale
import androidx.compose.ui.graphics.drawscope.translate
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.ExperimentalTextApi
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontVariation
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.em
import androidx.compose.ui.unit.sp

/**
 * Sphinx's look, "basalt and jade" (the owner chose it from mockups, 2026-10-26): black basalt, white type, one jade
 * accent; tonal surfaces with 1 px hairlines, no glows, no gradients. The Sphinx itself is only a hint: a small
 * silhouette by the name whose jade eye blinks now and then, a faint one behind the approval question, and codes in a
 * cartouche. Always dark.
 */
@Immutable
data class Palette(
    val page: Color, val canvas: Color, val surface1: Color, val surface2: Color, val surface3: Color,
    val border: Color, val divider: Color, val rim: Color,
    val text: Color, val text2: Color, val text3: Color,
    val primary: Color, val onPrimary: Color, val primaryPressed: Color, val switchOn: Color,
    val danger: Color, val dangerText: Color, val success: Color,
    /** The small silhouette's body, and the big faint one behind the approval question. */
    val mark: Color, val ghost: Color,
)

val Basalt = Palette(
    page = Color(0xFF000000), canvas = Color(0xFF0A0A0A), surface1 = Color(0xFF141414), surface2 = Color(0xFF141414), surface3 = Color(0xFF1E1E1E),
    border = Color(0x1AFFFFFF), divider = Color(0x0FFFFFFF), rim = Color(0x1AFFFFFF),
    text = Color(0xFFF2F2F2), text2 = Color(0xFF8C8C8C), text3 = Color(0xFF8C8C8C),
    primary = Color(0xFF7FD6AA), onPrimary = Color(0xFF0A0A0A), primaryPressed = Color(0xFF6CBF96), switchOn = Color(0xFF7FD6AA),
    danger = Color(0xFFF05A45), dangerText = Color(0xFFF05A45), success = Color(0xFF7FD6AA),
    mark = Color(0xFF2A2A2A), ghost = Color(0xFF111111),
)

val LocalPalette = staticCompositionLocalOf { Basalt }
/** False when the phone's animator scale is 0 (Settings, Developer options, or Remove animations): nothing moves. */
val LocalMotion = staticCompositionLocalOf { true }

/** The palette in effect: `Sx.p.primary`; `Sx.motion`: may things move. */
object Sx {
    val p: Palette @Composable get() = LocalPalette.current
    val motion: Boolean @Composable get() = LocalMotion.current
}

/** Instrument Sans is one variable font: each weight is a wght setting on the same file. */
@OptIn(ExperimentalTextApi::class)
val Instrument = FontFamily(
    Font(R.font.instrument_sans, FontWeight.Normal, variationSettings = FontVariation.Settings(FontVariation.weight(400))),
    Font(R.font.instrument_sans, FontWeight.Medium, variationSettings = FontVariation.Settings(FontVariation.weight(500))),
    Font(R.font.instrument_sans, FontWeight.SemiBold, variationSettings = FontVariation.Settings(FontVariation.weight(600))),
)
val PlexMono = FontFamily(Font(R.font.plex_mono_medium, FontWeight.Medium), Font(R.font.plex_mono_semibold, FontWeight.SemiBold))
/** Only the "Sphinx" wordmark and the big approval question. */
val Marcellus = FontFamily(Font(R.font.marcellus_regular, FontWeight.Normal))

/** The type roles of the mockup. */
object Type {
    private fun sans(size: Float, line: Float, w: FontWeight) = TextStyle(fontFamily = Instrument, fontSize = size.sp, lineHeight = line.sp, fontWeight = w)
    private fun mono(size: Float, line: Float, w: FontWeight) =
        TextStyle(fontFamily = PlexMono, fontSize = size.sp, lineHeight = line.sp, fontWeight = w, fontFeatureSettings = "tnum")

    val title = sans(26f, 32f, FontWeight.SemiBold).copy(letterSpacing = 0.01.em)
    val headlineLg = sans(22f, 28f, FontWeight.SemiBold)
    val headlineMd = sans(19f, 25f, FontWeight.SemiBold)
    val headlineSm = sans(16f, 21f, FontWeight.SemiBold)
    val bodyLg = sans(16f, 22f, FontWeight.Normal)
    val bodyMd = sans(15f, 20f, FontWeight.Normal)
    val bodySm = sans(12.5f, 17f, FontWeight.Normal)
    val labelUi = sans(11.5f, 15f, FontWeight.Medium)
    /** Uppercase group labels: 11 px, +0.07em. */
    val micro = sans(11f, 14f, FontWeight.SemiBold).copy(letterSpacing = 0.07.em)
    /** The jade eyebrow over the approval question: +0.1em. */
    val eyebrow = micro.copy(letterSpacing = 0.1.em)
    val code = mono(18f, 22f, FontWeight.SemiBold).copy(letterSpacing = 0.04.em)
    val codeHidden = code.copy(letterSpacing = 0.12.em)
    val codeSm = mono(12.5f, 17f, FontWeight.Medium)
    val wordmark = TextStyle(fontFamily = Marcellus, fontSize = 22.sp, lineHeight = 24.sp, letterSpacing = 0.04.em)
    val question = TextStyle(fontFamily = Marcellus, fontSize = 27.sp, lineHeight = 34.sp)
}

private val Typo = Typography(
    headlineLarge = Type.title, headlineMedium = Type.headlineLg, headlineSmall = Type.headlineMd,
    titleLarge = Type.headlineMd, titleMedium = Type.headlineSm, titleSmall = Type.bodyMd.copy(fontWeight = FontWeight.Medium),
    bodyLarge = Type.bodyLg, bodyMedium = Type.bodyMd, bodySmall = Type.bodySm,
    labelLarge = Type.bodyMd.copy(fontWeight = FontWeight.SemiBold), labelMedium = Type.labelUi, labelSmall = Type.labelUi,
)

/** 16 px cards, 12 px buttons, 10 px inputs, 9 px tiles. */
object Corner {
    val card = RoundedCornerShape(16.dp)
    val button = RoundedCornerShape(12.dp)
    val control = RoundedCornerShape(10.dp)
    val tile = RoundedCornerShape(9.dp)
}

private val Scheme = darkColorScheme(
    primary = Basalt.primary, onPrimary = Basalt.onPrimary, primaryContainer = Basalt.surface3, onPrimaryContainer = Basalt.text,
    secondary = Basalt.primary, background = Basalt.canvas, onBackground = Basalt.text, surface = Basalt.surface1, onSurface = Basalt.text,
    surfaceVariant = Basalt.surface3, onSurfaceVariant = Basalt.text2, surfaceContainerLowest = Basalt.page, surfaceContainerLow = Basalt.canvas,
    surfaceContainer = Basalt.surface1, surfaceContainerHigh = Basalt.surface1, surfaceContainerHighest = Basalt.surface3,
    outline = Basalt.border, outlineVariant = Basalt.divider, error = Basalt.danger, onError = Basalt.onPrimary,
)

@Composable
fun SphinxTheme(content: @Composable () -> Unit) {
    val ctx = LocalContext.current
    val motion = remember { runCatching { Settings.Global.getFloat(ctx.contentResolver, Settings.Global.ANIMATOR_DURATION_SCALE, 1f) }.getOrDefault(1f) > 0f }
    // Text outside a Surface takes LocalContentColor, which defaults to black: give every screen its scheme's ink
    // (owner, 2026-10-26: black text on the dark background).
    MaterialTheme(colorScheme = Scheme, typography = Typo,
        shapes = Shapes(extraSmall = Corner.control, small = Corner.control, medium = Corner.card, large = Corner.card)) {
        CompositionLocalProvider(LocalPalette provides Basalt, LocalMotion provides motion,
            androidx.compose.material3.LocalContentColor provides Scheme.onBackground,
            androidx.compose.material3.LocalTextStyle provides Type.bodyMd, content = content)
    }
}

/** A small uppercase label. */
@Composable
fun Kicker(text: String, modifier: Modifier = Modifier, color: Color = Sx.p.text2) =
    Text(text.uppercase(), modifier, style = Type.micro, color = color)

/** A group's label, over its card. */
@Composable
fun SectionLabel(text: String, modifier: Modifier = Modifier, danger: Boolean = false) =
    Kicker(text, modifier.padding(start = 4.dp, bottom = 8.dp), if (danger) Sx.p.danger else Sx.p.text2)

/** A tab's heading: the title, a muted line, and an action at the right (Codes' +). */
@Composable
fun Header(title: String, sub: String? = null, action: (@Composable () -> Unit)? = null) {
    Row(Modifier.fillMaxWidth().padding(start = 4.dp, end = 0.dp, top = 6.dp, bottom = 4.dp), verticalAlignment = Alignment.Bottom) {
        Column(Modifier.weight(1f)) {
            Text(title, style = Type.title, color = Sx.p.text)
            sub?.let { Text(it, Modifier.padding(top = 2.dp), style = Type.bodySm.copy(fontSize = 13.sp), color = Sx.p.text2) }
        }
        action?.invoke()
    }
}

/** A grouped card: the raised surface, 16 px corners, a 1 px hairline. Rows inside are separated by [Hairline]. */
@Composable
fun Group(modifier: Modifier = Modifier, border: Color = Sx.p.border, content: @Composable ColumnScope.() -> Unit) =
    Column(modifier.fillMaxWidth().clip(Corner.card).background(Sx.p.surface1).border(1.dp, border, Corner.card), content = content)

@Composable
fun Hairline(modifier: Modifier = Modifier) = HorizontalDivider(modifier, 1.dp, Sx.p.divider)

/** "Label   value" on one row inside a group, under a hairline unless it is the first. */
@Composable
fun Fact(label: String, value: String, rule: Boolean = true) {
    if (rule) Hairline()
    Row(Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 11.dp), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        Text(label, style = Type.bodySm.copy(fontSize = 13.sp), color = Sx.p.text2)
        // Ids, hosts, sizes and dates in mono; a sentence stays in the UI face.
        val prose = value.length > 22 && value.count { it == ' ' } > 2
        Text(value, Modifier.weight(1f), style = if (prose) Type.bodySm.copy(fontSize = 13.sp) else Type.codeSm, color = Sx.p.text, textAlign = TextAlign.End)
    }
}

/** A row in a group: title, optional subtitle, optional trailing content; tappable when [onClick] is set. */
@Composable
fun ListRow(
    title: String, subtitle: String? = null, modifier: Modifier = Modifier, titleColor: Color = Sx.p.text, rule: Boolean = false,
    onClick: (() -> Unit)? = null, trailing: (@Composable () -> Unit)? = null,
) {
    if (rule) Hairline()
    Row(
        modifier.fillMaxWidth().then(if (onClick != null) Modifier.clickable(role = Role.Button, onClick = onClick) else Modifier)
            .defaultMinSize(minHeight = 52.dp).padding(horizontal = 16.dp, vertical = 13.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f).padding(end = if (trailing != null) 12.dp else 0.dp)) {
            Text(title, style = Type.bodyMd.copy(fontWeight = FontWeight.Medium), color = titleColor)
            subtitle?.let { Text(it, Modifier.padding(top = 2.dp), style = Type.bodySm, color = Sx.p.text2) }
        }
        trailing?.invoke()
    }
}

/** A row's value at the right: muted, or jade when it is a good state. */
@Composable
fun Value(text: String, ok: Boolean = false) = Text(text, style = Type.bodySm.copy(fontSize = 13.sp), color = if (ok) Sx.p.success else Sx.p.text2, maxLines = 1)

@Composable
fun Chevron() = Text("›", style = Type.bodyLg, color = Sx.p.text2)

/** Plain helper text in a group, muted. */
@Composable
fun GroupText(text: String, modifier: Modifier = Modifier, color: Color = Sx.p.text2) =
    Text(text, modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp), style = Type.bodySm, color = color)

enum class Kind { PRIMARY, SECONDARY, DANGER, QUIET }

/** Buttons: primary solid jade, secondary a hairline outline, danger a red outline, quiet jade text. 12 px corners, 50 tall (36 small). */
@Composable
fun SxButton(text: String, onClick: () -> Unit, modifier: Modifier = Modifier, kind: Kind = Kind.PRIMARY, enabled: Boolean = true, small: Boolean = false) {
    val p = Sx.p
    val source = remember { MutableInteractionSource() }
    val pressed by source.collectIsPressedAsState()
    val (bg, fg, line) = when (kind) {
        Kind.PRIMARY -> Triple(if (pressed) p.primaryPressed else p.primary, p.onPrimary, null)
        Kind.SECONDARY -> Triple(if (pressed) p.surface3 else Color.Transparent, p.text, p.border)
        Kind.DANGER -> Triple(if (pressed) p.danger.copy(alpha = 0.12f) else Color.Transparent, p.danger, p.danger.copy(alpha = 0.5f))
        Kind.QUIET -> Triple(if (pressed) p.surface3 else Color.Transparent, p.primary, null)
    }
    Box(
        modifier.alpha(if (enabled) 1f else 0.4f).defaultMinSize(minHeight = if (small) 36.dp else 50.dp).clip(Corner.button).background(bg)
            .then(if (line != null) Modifier.border(1.dp, line, Corner.button) else Modifier)
            .clickable(source, null, enabled = enabled, role = Role.Button, onClick = onClick)
            .padding(horizontal = if (kind == Kind.QUIET) 10.dp else 16.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(text, style = (if (small) Type.bodySm.copy(fontSize = 13.sp) else Type.bodyMd).copy(fontWeight = FontWeight.SemiBold), color = fg, textAlign = TextAlign.Center)
    }
}

/** The + on Codes: a 40 px jade square. */
@Composable
fun PlusButton(onClick: () -> Unit, label: String) =
    Box(Modifier.size(44.dp).clip(Corner.button).clickable(role = Role.Button, onClickLabel = label, onClick = onClick), contentAlignment = Alignment.Center) {
        Box(Modifier.size(40.dp).clip(Corner.button).background(Sx.p.primary), contentAlignment = Alignment.Center) {
            Text("+", style = Type.title.copy(fontSize = 24.sp, lineHeight = 24.sp), color = Sx.p.onPrimary)
        }
    }

/**
 * The cartouche, Sphinx's signature: a pill outline with a short vertical bar near its right end (an Egyptian
 * cartouche's tie). [small] is the site / "sealed" chip in a muted hairline.
 */
@Composable
fun Cartouche(modifier: Modifier = Modifier, small: Boolean = false, color: Color = if (small) Sx.p.border else Sx.p.primary, content: @Composable RowScope.() -> Unit) {
    Row(
        modifier.drawBehind {
            val w = 1.dp.toPx()
            drawRoundRect(color, Offset(w / 2, w / 2), Size(size.width - w, size.height - w), CornerRadius(size.height / 2), style = Stroke(w))
            val x = size.width - (if (small) 5.dp else 8.dp).toPx()
            val inset = (if (small) 4.dp else 7.dp).toPx()
            drawLine(color, Offset(x, inset), Offset(x, size.height - inset), if (small) w else 1.5.dp.toPx(), StrokeCap.Round)
        }.padding(start = if (small) 8.dp else 10.dp, end = if (small) 14.dp else 18.dp, top = if (small) 1.dp else 4.dp, bottom = if (small) 1.dp else 4.dp),
        verticalAlignment = Alignment.CenterVertically, content = content,
    )
}

/** A small muted cartouche with a label (a site, "sealed"). */
@Composable
fun Pill(text: String, color: Color = Sx.p.text2, line: Color = Sx.p.border, max: Dp = 150.dp) =
    Cartouche(Modifier.widthIn(max = max), small = true, color = line) {
        Text(text, style = Type.bodySm.copy(fontSize = 12.sp, lineHeight = 16.sp), color = color, maxLines = 1, overflow = TextOverflow.Ellipsis)
    }

/** The question's cartouche on the approval screens: 1.5 px jade, the tie bar 16 px from the end. */
@Composable
fun QuestionCartouche(text: String) {
    val c = Sx.p.primary
    Box(
        Modifier.fillMaxWidth().drawBehind {
            val w = 1.5.dp.toPx()
            drawRoundRect(c, Offset(w / 2, w / 2), Size(size.width - w, size.height - w), CornerRadius(size.height / 2), style = Stroke(w))
            val x = size.width - 16.dp.toPx()
            drawLine(c, Offset(x, 18.dp.toPx()), Offset(x, size.height - 18.dp.toPx()), 2.dp.toPx(), StrokeCap.Round)
        }.padding(start = 26.dp, end = 34.dp, top = 26.dp, bottom = 26.dp),
        contentAlignment = Alignment.Center,
    ) { Text(text, style = Type.question, color = Sx.p.text, textAlign = TextAlign.Center) }
}

/** The service tile: the first letter in jade on the high surface, 9 px corners. */
@Composable
fun IconTile(letter: String, size: Dp = 30.dp, style: TextStyle = Type.bodySm.copy(fontSize = 13.sp, fontWeight = FontWeight.SemiBold)) =
    Box(Modifier.size(size).clip(if (size > 48.dp) Corner.card else Corner.tile).background(Sx.p.surface3).border(1.dp, Sx.p.divider, if (size > 48.dp) Corner.card else Corner.tile),
        contentAlignment = Alignment.Center) {
        Text(letter.take(1).uppercase().ifEmpty { "?" }, style = style, color = Sx.p.primary)
    }

/** The countdown ring: a hairline track and the time left of [total] in jade, red under 5 s. 16 px. */
@Composable
fun CountdownRing(left: Int, total: Int, size: Dp = 16.dp) {
    val p = Sx.p
    val target = (left.toFloat() / total.coerceAtLeast(1)).coerceIn(0f, 1f)
    val f by animateFloatAsState(target, if (Sx.motion) tween(1000, easing = LinearEasing) else snap(), label = "ring")
    val active = if (left < 5) p.danger else p.primary
    Canvas(Modifier.size(size)) {
        val w = 1.6.dp.toPx()
        val inset = w / 2
        val box = Size(this.size.width - w, this.size.height - w)
        drawCircle(p.surface1, this.size.width / 2 - w)
        drawArc(p.border, 0f, 360f, false, Offset(inset, inset), box, style = Stroke(w))
        drawArc(active, -90f, 360f * f, false, Offset(inset, inset), box, style = Stroke(w, cap = StrokeCap.Round))
    }
}

/** A soft note: a hairline box with a jade dot. */
@Composable
fun NoteLine(text: String, modifier: Modifier = Modifier) =
    Row(modifier.fillMaxWidth().clip(Corner.button).border(1.dp, Sx.p.border, Corner.button).padding(horizontal = 12.dp, vertical = 10.dp)) {
        Box(Modifier.padding(top = 5.dp).size(7.dp).clip(CircleShape).background(Sx.p.success))
        Spacer(Modifier.width(8.dp))
        Text(text, style = Type.bodySm, color = Sx.p.text2)
    }

/** The toggle: jade with a dark knob on the right when on; the high surface with a muted knob when off. Null [onClick] = state only. */
@Composable
fun SxSwitch(on: Boolean, onClick: (() -> Unit)?) {
    val p = Sx.p
    Box(
        Modifier.size(width = 40.dp, height = 24.dp).clip(CircleShape).background(if (on) p.switchOn else p.surface3)
            .then(if (on) Modifier else Modifier.border(1.dp, p.border, CircleShape))
            .then(if (onClick != null) Modifier.clickable(role = Role.Switch, onClick = onClick) else Modifier)
            .padding(3.dp),
        contentAlignment = if (on) Alignment.CenterEnd else Alignment.CenterStart,
    ) { Box(Modifier.size(18.dp).clip(CircleShape).background(if (on) p.canvas else p.text2)) }
}

/** Input fields: the raised fill, a hairline border that turns jade on focus, no glow. */
@Composable
fun fieldColors(): TextFieldColors {
    val p = Sx.p
    return OutlinedTextFieldDefaults.colors(
        focusedContainerColor = p.surface1, unfocusedContainerColor = p.surface1, disabledContainerColor = p.surface1,
        focusedBorderColor = p.primary, unfocusedBorderColor = p.border, focusedLabelColor = p.primary, unfocusedLabelColor = p.text2,
        focusedPlaceholderColor = p.text3, unfocusedPlaceholderColor = p.text3, cursorColor = p.primary,
        focusedTextColor = p.text, unfocusedTextColor = p.text,
    )
}

/** The "Sphinx" wordmark: the small silhouette and the name in Marcellus. */
@Composable
fun Wordmark(modifier: Modifier = Modifier, small: Boolean = false) =
    Row(modifier, verticalAlignment = Alignment.CenterVertically) {
        SphinxMark(if (small) 26.dp else 40.dp, if (small) Sx.p.mark else Color(0xFF3A3A3A))
        Spacer(Modifier.width(6.dp))
        Text("Sphinx", style = if (small) Type.wordmark.copy(fontSize = 14.sp, lineHeight = 16.sp) else Type.wordmark, color = if (small) Sx.p.text2 else Sx.p.text)
    }

/** The top of every tab: the wordmark at the right, as on the mockup's status line. */
@Composable
fun TopBar(modifier: Modifier = Modifier) =
    Box(modifier.fillMaxWidth().height(34.dp).padding(horizontal = 20.dp), contentAlignment = Alignment.CenterEnd) { Wordmark(small = true) }

/** One navigation destination: a glyph and its word. */
class NavItem(val glyph: Glyph, val word: String, val selected: Boolean, val onClick: () -> Unit)

/** The phone's tab bar: under a hairline, the active item jade with a small jade dot. */
@Composable
fun BottomBar(items: List<NavItem>, modifier: Modifier = Modifier) {
    Column(modifier.fillMaxWidth().background(Sx.p.canvas)) {
        HorizontalDivider(thickness = 1.dp, color = Sx.p.border)
        Row(Modifier.fillMaxWidth().height(64.dp), horizontalArrangement = Arrangement.SpaceAround, verticalAlignment = Alignment.CenterVertically) {
            for (it in items) NavCell(it, Modifier.weight(1f))
        }
    }
}

/** The same destinations as a side rail, for the Fold's inner screen. */
@Composable
fun SideRail(items: List<NavItem>, modifier: Modifier = Modifier) {
    Row(modifier.fillMaxHeight().background(Sx.p.canvas)) {
        Column(Modifier.width(88.dp).padding(top = 48.dp), verticalArrangement = Arrangement.spacedBy(8.dp), horizontalAlignment = Alignment.CenterHorizontally) {
            for (it in items) NavCell(it, Modifier.height(64.dp).fillMaxWidth())
        }
        VerticalDivider(thickness = 1.dp, color = Sx.p.border)
    }
}

@Composable
private fun NavCell(it: NavItem, modifier: Modifier) {
    val color = if (it.selected) Sx.p.primary else Sx.p.text2
    Column(modifier.defaultMinSize(minWidth = 56.dp, minHeight = 48.dp).clip(Corner.control).clickable(role = Role.Tab, onClick = it.onClick),
        horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.Center) {
        GlyphIcon(it.glyph, color, 20.dp)
        Text(it.word, Modifier.padding(top = 5.dp), style = Type.labelUi.copy(fontWeight = if (it.selected) FontWeight.SemiBold else FontWeight.Normal), color = color)
        Box(Modifier.padding(top = 5.dp).size(4.dp).clip(CircleShape).background(if (it.selected) Sx.p.primary else Color.Transparent))
    }
}

/** Sphinx's line icons, the mockup's, drawn on a 24-unit grid with a 1.6 px stroke. */
enum class Glyph { CODES, KEYS, LAPTOPS, SETTINGS, LOCK }

@Composable
fun GlyphIcon(g: Glyph, tint: Color, size: Dp = 24.dp) = Canvas(Modifier.size(size)) { glyph(g, tint) }

private fun DrawScope.glyph(g: Glyph, c: Color) {
    val u = size.width / 24f
    val w = 1.6f * density
    val stroke = Stroke(w, cap = StrokeCap.Round)
    fun line(x1: Float, y1: Float, x2: Float, y2: Float) = drawLine(c, Offset(x1 * u, y1 * u), Offset(x2 * u, y2 * u), w, StrokeCap.Round)
    when (g) {
        Glyph.CODES -> { drawRoundRect(c, Offset(3f * u, 7f * u), Size(18f * u, 10f * u), CornerRadius(5f * u), style = stroke); line(17f, 9f, 17f, 15f) }
        Glyph.KEYS -> drawPath(Path().apply {
            moveTo(12f * u, 3f * u); lineTo(19f * u, 6f * u); lineTo(19f * u, 11f * u)
            cubicTo(19f * u, 16f * u, 16f * u, 19f * u, 12f * u, 21f * u); cubicTo(8f * u, 19f * u, 5f * u, 16f * u, 5f * u, 11f * u)
            lineTo(5f * u, 6f * u); close()
        }, c, style = stroke)
        Glyph.LAPTOPS -> { drawRoundRect(c, Offset(4f * u, 5f * u), Size(16f * u, 11f * u), CornerRadius(1.5f * u), style = stroke); line(2f, 19f, 22f, 19f) }
        Glyph.SETTINGS -> {
            drawCircle(c, 3f * u, Offset(12f * u, 12f * u), style = stroke)
            line(12f, 2f, 12f, 5f); line(12f, 19f, 12f, 22f); line(2f, 12f, 5f, 12f); line(19f, 12f, 22f, 12f)
            line(5f, 5f, 7f, 7f); line(17f, 17f, 19f, 19f); line(5f, 19f, 7f, 17f); line(17f, 7f, 19f, 5f)
        }
        Glyph.LOCK -> {
            drawRoundRect(c, Offset(5.5f * u, 10.5f * u), Size(13f * u, 9.5f * u), CornerRadius(2f * u), style = stroke)
            drawArc(c, 180f, 180f, false, Offset(8.5f * u, 4f * u), Size(7f * u, 7f * u), style = stroke)
            line(8.5f, 7.5f, 8.5f, 10.5f); line(15.5f, 7.5f, 15.5f, 10.5f); line(12f, 14f, 12f, 16.5f)
        }
    }
}

/** The silhouette from the mockup (viewBox 0 112 200 76): a couchant Sphinx, its eye at (129, 137). */
private val MarkBody: Path = Path().apply {
    moveTo(6f, 184f); cubicTo(26f, 172f, 52f, 168f, 74f, 170f); lineTo(90f, 150f)
    cubicTo(94f, 132f, 108f, 120f, 126f, 122f); cubicTo(140f, 124f, 148f, 136f, 146f, 150f); lineTo(154f, 160f)
    cubicTo(166f, 162f, 178f, 168f, 188f, 176f); lineTo(196f, 184f); close()
}

/**
 * The Sphinx mark, [width] wide (76:200 tall). [ghost]: the big faint one behind the approval question, whose eye
 * pulses slowly; otherwise the eye blinks (scaleY) every 7 s. Still when animations are off.
 */
@Composable
fun SphinxMark(width: Dp, body: Color = Sx.p.mark, ghost: Boolean = false, modifier: Modifier = Modifier) {
    val eye = Sx.p.primary
    val moving = Sx.motion
    val t = rememberInfiniteTransition(label = "eye")
    val blink by if (moving && !ghost) t.animateFloat(1f, 1f, infiniteRepeatable(keyframes {
        durationMillis = 7000; 1f at 6580; 0.1f at 6790; 1f at 7000
    }), label = "blink") else remember { androidx.compose.runtime.mutableFloatStateOf(1f) }
    val glow by if (moving && ghost) t.animateFloat(0.8f, 0.25f, infiniteRepeatable(tween(1750, easing = FastOutSlowInEasing), RepeatMode.Reverse), label = "glow")
        else remember { androidx.compose.runtime.mutableFloatStateOf(0.8f) }
    Canvas(modifier.size(width, width * 0.38f)) {
        val s = size.width / 200f
        scale(s, s, Offset.Zero) {
            translate(0f, -112f) {
                drawPath(MarkBody, body)
                scale(1f, blink, Offset(129f, 137f)) { drawCircle(eye.copy(alpha = if (ghost) glow else 1f), 4f, Offset(129f, 137f)) }
            }
        }
    }
}

/** Rows rise and fade in the first time they show (6 px, 0.5 s), unless animations are off. */
@Composable
fun Modifier.riseIn(): Modifier {
    if (!Sx.motion) return this
    val a = remember { Animatable(0f) }
    LaunchedEffect(Unit) { a.animateTo(1f, tween(500, easing = CubicBezierEasing(0.2f, 0.8f, 0.2f, 1f))) }
    return this.graphicsLayer { alpha = a.value; translationY = (1f - a.value) * 6.dp.toPx() }
}

/** A note at the top of a tab (the result of the last action). */
@Composable
fun NoteCard(text: String, modifier: Modifier = Modifier) = NoteLine(text, modifier)

/** A note under a section: muted, or red when it is a problem. */
@Composable
fun Note(text: String?, error: Boolean = false, modifier: Modifier = Modifier) {
    text?.let { Text(it, modifier.padding(top = 8.dp, start = 4.dp, end = 4.dp), style = Type.bodySm, color = if (error) Sx.p.danger else Sx.p.text2) }
}

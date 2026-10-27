import groovy.json.JsonSlurper
import java.util.Properties
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

// AGP 9 compiles Kotlin itself, so there is no kotlin-android plugin here.
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

val local = Properties().apply { rootProject.file("local.properties").takeIf { it.exists() }?.reader()?.use { load(it) } }
fun setting(prop: String, env: String): String? = (local.getProperty(prop) ?: System.getenv(env))?.takeIf { it.isNotBlank() }

// The release key lives outside the repo (kept outside the repo): local.properties (or the environment) names the keystore and
// the file holding its password, never the password itself. Without them assembleRelease gives an unsigned APK.
val store = setting("sphinx.keystore", "SPHINX_KEYSTORE")?.let { file(it) }?.takeIf { it.exists() }
val storePass = setting("sphinx.keystore.passfile", "SPHINX_KEYSTORE_PASS_FILE")?.let { file(it) }?.takeIf { it.exists() }?.readText()?.trim()

// Firebase Cloud Messaging is how a request reaches the phone. app/google-services.json (git-ignored) becomes the
// resources FirebaseInitProvider reads, as the google-services plugin would make them. Debug builds and unit tests work
// without it (the app then can't pair); a release build refuses to start without it (below). No google-services
// plugin, so nothing else of Firebase comes in.
val firebase: Map<String, String> = file("google-services.json").takeIf { it.exists() }?.let { f ->
    @Suppress("UNCHECKED_CAST")
    val root = JsonSlurper().parse(f) as Map<String, Any?>
    val project = root["project_info"] as Map<String, Any?>
    val clients = root["client"] as List<Map<String, Any?>>
    val client = clients.firstOrNull { ((it["client_info"] as Map<String, Any?>)["android_client_info"] as Map<String, Any?>)["package_name"] == "dev.sphinx" }
        ?: error("google-services.json has no Android app dev.sphinx")
    mapOf(
        "google_app_id" to (client["client_info"] as Map<String, Any?>)["mobilesdk_app_id"] as String,
        "gcm_defaultSenderId" to project["project_number"] as String,
        "project_id" to project["project_id"] as String,
        "google_api_key" to ((client["api_key"] as List<Map<String, Any?>>).first()["current_key"] as String),
    ) + ((project["storage_bucket"] as String?)?.let { mapOf("google_storage_bucket" to it) } ?: emptyMap())
} ?: emptyMap()

android {
    namespace = "dev.sphinx"
    compileSdk = 35

    defaultConfig {
        applicationId = "dev.sphinx"
        minSdk = 31
        targetSdk = 35
        versionCode = 11
        versionName = "1.3.5"
        firebase.forEach { (k, v) -> resValue("string", k, v) }
        // Where a new phone looks for the backup (Restore offers it, editable): local.properties sphinx.relay, else empty (typed on the phone).
        resValue("string", "sphinx_relay", setting("sphinx.relay", "SPHINX_RELAY") ?: "")
        // His relay's registration value, read at build time from a file outside the repo (local.properties
        // sphinx.relayTokenFile, outside the repo): pairing and the first backup use it when the laptop's QR carries
        // none (owner, 2026-10-26: pairing failed with 403). Empty when not set.
        resValue("string", "sphinx_relay_token", setting("sphinx.relayTokenFile", "SPHINX_RELAY_TOKEN_FILE")?.let { file(it).takeIf { f -> f.exists() }?.readText()?.trim() } ?: "")
    }

    signingConfigs {
        if (store != null && storePass != null) create("release") {
            storeFile = store
            storePassword = storePass
            keyAlias = setting("sphinx.keyalias", "SPHINX_KEY_ALIAS") ?: "sphinx"
            keyPassword = storePass
        }
    }
    buildTypes {
        getByName("release") {
            // No R8: Jackson reads the stored accounts by reflection and would need keep rules.
            isMinifyEnabled = false
            if (store != null && storePass != null) signingConfig = signingConfigs.getByName("release")
        }
    }

    buildFeatures { compose = true; resValues = true }
    // Screenshot path: Robolectric renders the screens to PNG (app/build/shots). Every screen is FLAG_SECURE, so the
    // phone's own screenshots are black. Test-only.
    testOptions { unitTests.isIncludeAndroidResources = true }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin { compilerOptions { jvmTarget.set(JvmTarget.JVM_17) } }

// Laptop requests reach the phone only through FCM, so a release without google-services.json could never be woken.
val hasFirebase = firebase.isNotEmpty()
tasks.configureEach {
    if (name == "preReleaseBuild") doFirst {
        if (!hasFirebase) throw GradleException("A release build needs app/google-services.json (kept outside the repo): Sphinx is woken only through FCM.")
    }
}

dependencies {
    implementation(platform("androidx.compose:compose-bom:2025.04.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.10.1")
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    // The clipboard clear that survives the process going away, and the 15-minute heartbeat.
    implementation("androidx.work:work-runtime-ktx:2.10.1")
    // The accounts and pairings, as JSON inside the sealed prefs.
    implementation("com.fasterxml.jackson.core:jackson-databind:2.19.4")
    // Google's code scanner: the camera runs in Play services' own process and hands back the text, so Sphinx needs
    // no camera permission.
    implementation("com.google.android.gms:play-services-code-scanner:16.1.0")
    // The wake: FCM data messages only ({"t": "sync"} and the sealed blobs).
    implementation("com.google.firebase:firebase-messaging:24.1.1")
    // Argon2id for the backup passcode (memory-hard). Bouncy Castle's provider jar, pinned and hash-checked like the rest.
    implementation("org.bouncycastle:bcprov-jdk18on:1.80")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.robolectric:robolectric:4.15.1")
    testImplementation("androidx.compose.ui:ui-test-junit4")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
}

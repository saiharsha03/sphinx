package dev.sphinx

import java.net.IDN

/**
 * The Public Suffix List (publicsuffix.org, bundled as a resource: sphinx/public_suffix_list.dat, the same file the
 * extension ships), ICANN and private sections, wildcard and exception rules. Used only to refuse a saved site that is
 * a public suffix (`co.uk`, `co.id`, `eu.org`, `github.io`), so a saved entry can never open every site under one.
 */
class Psl(text: String) {
    private val rules = HashSet<String>()
    private val wild = HashSet<String>()
    private val except = HashSet<String>()
    /** Every host some rule sits under (the base of a `*.` rule included): `*.host` there would cover public suffixes. */
    private val parents = HashSet<String>()

    init {
        for (raw in text.lineSequence()) {
            val r = raw.trim().substringBefore(' ').lowercase()
            if (r.isEmpty() || r.startsWith("//")) continue
            fun ascii(s: String) = runCatching { IDN.toASCII(s, IDN.ALLOW_UNASSIGNED) }.getOrDefault(s)
            when {
                r.startsWith("!") -> except += ascii(r.drop(1))
                r.startsWith("*.") -> wild += ascii(r.drop(2))
                else -> rules += ascii(r)
            }
        }
        fun up(h: String) { var x = h; while ('.' in x) { x = x.substringAfter('.'); parents += x } }
        rules.forEach(::up); except.forEach(::up); wild.forEach { parents += it; up(it) }
    }

    val size: Int get() = rules.size + wild.size + except.size

    /** The public suffix of [host] (longest rule; an exception rule wins; the default rule is the last label). */
    fun suffix(host: String): String {
        val labels = host.split('.')
        for (i in labels.indices) {
            val c = labels.subList(i, labels.size).joinToString(".")
            if (c in except) return labels.subList(i + 1, labels.size).joinToString(".")
            if (c in rules) return c
            if (i + 1 < labels.size && labels.subList(i + 1, labels.size).joinToString(".") in wild) return c
        }
        return labels.last()
    }

    fun isSuffix(host: String): Boolean = suffix(host) == host

    /** True when some public suffix lies under [host] (`compute.amazonaws.com`, `kawasaki.jp`): `*.host` can't be saved. */
    fun coversSuffixes(host: String): Boolean = host in parents

    /** The registrable domain (the suffix and one more label), or null when the host is itself a suffix. */
    fun registrable(host: String): String? {
        val s = suffix(host)
        if (s == host) return null
        val rest = host.removeSuffix(".$s").substringAfterLast('.')
        return "$rest.$s"
    }

    companion object {
        val bundled: Psl by lazy {
            Psl(Psl::class.java.getResourceAsStream("/sphinx/public_suffix_list.dat")!!.use { it.readBytes().toString(Charsets.UTF_8) })
        }
    }
}

/**
 * The phishing guard. An account fills only on the sites you saved for it. By default a saved site is one exact host
 * (`github.com` fills on `github.com`, and its `www.`, nowhere else); `*.example.com` opts that site's subdomains in, on
 * purpose, per site. Never `github.com.evil.io`, `evilgithub.com` or `github.co`. A saved site may not be a public
 * suffix (the bundled Public Suffix List), so `*.github.io`, `co.id` or `eu.org` can't be saved. The laptop checks the
 * same rule before it asks, and the phone checks it again, for the tab and the frame, against one account's sites.
 */
object Domains {
    private val LABEL = Regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
    var psl: Psl? = null
    private fun psl() = psl ?: Psl.bundled

    /** "https://WWW.GitHub.com/login" -> "github.com". Null when it isn't a host at all. */
    /** The site a host belongs to (eTLD+1: `us-east-1.signin.aws.amazon.com` -> `amazon.com`), or the host itself. */
    fun site(host: String): String = psl().registrable(host) ?: host

    fun normalize(input: String): String? {
        var h = input.trim().lowercase()
        h = h.substringAfter("://").substringBefore('/').substringBefore('?').substringBefore('#').substringAfterLast('@').substringBefore(':').trimEnd('.')
        if (h.startsWith("www.")) h = h.removePrefix("www.")
        val labels = h.split('.')
        return h.takeIf { labels.size >= 2 && labels.all { LABEL.matches(it) } && labels.last().any { !it.isDigit() } }
    }

    /** A site you may save: an exact host, or `*.host` for it and its subdomains; never a public suffix. */
    fun savable(input: String): String? {
        val t = input.trim().lowercase()
        val sub = t.startsWith("*.")
        val host = normalize(t.removePrefix("*.")) ?: return null
        if (psl().isSuffix(host)) return null
        // `*.host` must not reach a public suffix below it (a wildcard rule's parent, or any rule's).
        if (sub && psl().coversSuffixes(host)) return null
        return if (sub) "*.$host" else host
    }

    /** The page's host is the saved host, or (for a `*.` entry) a subdomain of it. */
    fun matches(host: String, saved: String): Boolean {
        val h = normalize(host) ?: return false
        val d = savable(saved) ?: return false
        return if (d.startsWith("*.")) d.removePrefix("*.").let { h == it || h.endsWith(".$it") } else h == d
    }

    /** Accounts that may fill here: the tab's host and the frame's host must both be one account's sites. */
    fun <T> candidates(host: String, accounts: List<T>, frame: String = host, domains: (T) -> List<String>): List<T> =
        accounts.filter { a -> domains(a).any { matches(host, it) } && domains(a).any { matches(frame, it) } }

    /** The Chrome match patterns for a saved site: the host and its www (and `*.host` when subdomains are opted in). */
    fun patterns(saved: String): List<String> {
        val d = savable(saved) ?: return emptyList()
        return if (d.startsWith("*.")) d.removePrefix("*.").let { listOf("https://$it/*", "https://*.$it/*") } else listOf("https://$d/*", "https://www.$d/*")
    }

    /**
     * With several accounts for one site: the one whose account name is the user name on the page (the whole name, or
     * the part before @, case-insensitive). Null: the phone asks which.
     */
    fun <T> pick(found: List<T>, hint: String?, name: (T) -> String): T? {
        if (found.size == 1) return found.single()
        val h = hint?.trim()?.lowercase()?.takeIf { it.length >= 2 } ?: return null
        // "GitHub:alex" (an authenticator label) and "alex@example.com" both match a hint of alex.
        fun keys(s: String) = s.trim().lowercase().substringAfterLast(':').trim().let { setOf(it, it.substringBefore('@')) }.filter { it.isNotEmpty() }
        val hk = keys(h)
        return found.filter { a -> keys(name(a)).any { it in hk } }.singleOrNull()
    }

    /**
     * Well-known issuers' single-owner login hosts, exact. Issuers whose sign-in lives on a customer's own subdomain
     * (Okta, Slack workspaces, Atlassian sites, Salesforce My Domain, Zoom vanity hosts, Sentry and Datadog orgs) start
     * with their vendor-owned login host when there is one, else none: you type the exact tenant host.
     */
    private val ONE = mapOf(
        "github" to "github.com", "gitlab" to "gitlab.com", "google" to "accounts.google.com", "gmail" to "accounts.google.com",
        "google account" to "accounts.google.com", "youtube" to "accounts.google.com",
        "amazon" to "amazon.com", "amazon web services" to "signin.aws.amazon.com", "aws" to "signin.aws.amazon.com", "discord" to "discord.com",
        "apple" to "appleid.apple.com", "apple id" to "appleid.apple.com", "icloud" to "appleid.apple.com",
        "dropbox" to "dropbox.com", "facebook" to "facebook.com", "meta" to "facebook.com", "instagram" to "instagram.com", "twitter" to "x.com", "x" to "x.com",
        "linkedin" to "linkedin.com", "reddit" to "reddit.com", "atlassian" to "id.atlassian.com", "jira" to "id.atlassian.com",
        "bitbucket" to "id.atlassian.com", "trello" to "id.atlassian.com", "cloudflare" to "dash.cloudflare.com", "digitalocean" to "cloud.digitalocean.com",
        "hetzner" to "accounts.hetzner.com", "hetzner cloud" to "accounts.hetzner.com", "hetzner online" to "accounts.hetzner.com", "heroku" to "id.heroku.com",
        "vercel" to "vercel.com", "netlify" to "app.netlify.com", "npm" to "npmjs.com", "npmjs" to "npmjs.com", "pypi" to "pypi.org",
        "docker" to "login.docker.com", "docker hub" to "login.docker.com",
        "salesforce" to "login.salesforce.com", "paypal" to "paypal.com", "coinbase" to "coinbase.com", "epic games" to "epicgames.com",
        "steam" to "store.steampowered.com", "twitch" to "twitch.tv", "proton" to "account.proton.me", "protonmail" to "account.proton.me", "proton mail" to "account.proton.me",
        "bitwarden" to "vault.bitwarden.com", "1password" to "my.1password.com", "namecheap" to "namecheap.com", "godaddy" to "sso.godaddy.com",
        "openai" to "auth.openai.com", "chatgpt" to "auth.openai.com", "anthropic" to "console.anthropic.com", "claude" to "claude.ai",
        "notion" to "notion.so", "figma" to "figma.com",
        "datadog" to "app.datadoghq.com", "circleci" to "app.circleci.com", "stripe" to "dashboard.stripe.com", "shopify" to "accounts.shopify.com",
        "wordpress" to "wordpress.com", "tailscale" to "login.tailscale.com", "twilio" to "login.twilio.com", "sendgrid" to "app.sendgrid.com",
        "mailchimp" to "login.mailchimp.com", "zoho" to "accounts.zoho.com", "kraken" to "kraken.com", "binance" to "accounts.binance.com",
        "robinhood" to "robinhood.com", "nintendo" to "accounts.nintendo.com", "playstation" to "id.sonyentertainmentnetwork.com",
        "ubisoft" to "account.ubisoft.com", "battle.net" to "account.battle.net", "blizzard" to "account.battle.net",
        "snapchat" to "accounts.snapchat.com", "tiktok" to "tiktok.com", "pinterest" to "pinterest.com", "yahoo" to "login.yahoo.com",
        "fastmail" to "app.fastmail.com", "backblaze" to "secure.backblaze.com", "linode" to "login.linode.com", "vultr" to "my.vultr.com",
        "ovh" to "ovh.com", "ovhcloud" to "ovh.com", "porkbun" to "porkbun.com", "gandi" to "account.gandi.net", "expo" to "expo.dev",
        "jetbrains" to "account.jetbrains.com", "unity" to "id.unity.com", "adobe" to "account.adobe.com", "evernote" to "evernote.com",
        "wise" to "wise.com", "revolut" to "app.revolut.com", "kickstarter" to "kickstarter.com", "patreon" to "patreon.com",
        "mega" to "mega.nz", "hubspot" to "app.hubspot.com", "asana" to "app.asana.com", "miro" to "miro.com", "canva" to "canva.com",
        "replit" to "replit.com", "huggingface" to "huggingface.co", "hugging face" to "huggingface.co",
    )

    /** The few that sign in on more than one vendor-owned host (each exact). */
    private val MANY = mapOf(
        "microsoft" to listOf("login.microsoftonline.com", "login.live.com"),
        "microsoft account" to listOf("login.live.com"), "outlook" to listOf("login.live.com"), "xbox" to listOf("login.live.com"),
        "azure" to listOf("login.microsoftonline.com"), "office 365" to listOf("login.microsoftonline.com"), "microsoft 365" to listOf("login.microsoftonline.com"),
    )

    /** Every issuer and its exact login hosts (tests check each against the Public Suffix List). */
    val ISSUERS: Map<String, List<String>> = ONE.mapValues { listOf(it.value) } + MANY

    /** The issuer's apps on the phone, for the "code" notification when one shows a 2FA screen. */
    private val APPS = mapOf(
        "github.com" to listOf("com.github.android"), "gitlab.com" to listOf("com.gitlab.android"), "discord.com" to listOf("com.discord"),
        "dropbox.com" to listOf("com.dropbox.android"), "facebook.com" to listOf("com.facebook.katana"), "instagram.com" to listOf("com.instagram.android"),
        "x.com" to listOf("com.twitter.android"), "linkedin.com" to listOf("com.linkedin.android"), "reddit.com" to listOf("com.reddit.frontpage"),
        "paypal.com" to listOf("com.paypal.android.p2pmobile"), "coinbase.com" to listOf("com.coinbase.android"),
        "twitch.tv" to listOf("tv.twitch.android.app"), "store.steampowered.com" to listOf("com.valvesoftware.android.steam.community"),
        "epicgames.com" to listOf("com.epicgames.portal"), "account.proton.me" to listOf("ch.protonmail.android"), "vault.bitwarden.com" to listOf("com.x8bit.bitwarden"),
        "dash.cloudflare.com" to listOf("com.cloudflare.onedotonedotonedotone"), "notion.so" to listOf("notion.id"), "figma.com" to listOf("com.figma.mirror"),
        "signin.aws.amazon.com" to listOf("com.amazon.aws.console.mobile"), "amazon.com" to listOf("com.amazon.mShop.android.shopping"),
    )

    private val CORP = Regex("""\s+(inc|llc|ltd|limited|gmbh|corp|corporation|co|plc|sa|ag|bv|oy|ab)\.?$""")

    /** "GitHub, Inc." / "Google LLC" / "Dropbox Online GmbH" / "Microsoft (work)" -> the key [ISSUERS] uses. */
    fun issuerKey(issuer: String): String = issuer.trim().lowercase()
        .replace(Regex("""\(.*?\)"""), " ").replace(',', ' ').replace(Regex("""\s+"""), " ").trim()
        .replace(CORP, "").trim().trimEnd('.')

    /** The sites to start with for an imported account: its exact login hosts, or the issuer when it is itself a host. */
    fun forIssuer(issuer: String): List<String> {
        val raw = issuer.trim().lowercase()
        (ISSUERS[raw] ?: ISSUERS[issuerKey(issuer)])?.let { return it }
        return listOfNotNull(if ('.' in raw && ' ' !in raw) savable(raw)?.takeIf { !it.startsWith("*.") } else null)
    }

    fun appsFor(domains: List<String>): List<String> = domains.flatMap { APPS[it].orEmpty() }.distinct()

    /** A 2FA screen's notification: a verification or sign-in code is wanted (not a marketing line). */
    private val TWO_FA = Regex(
        """(?i)\b(2fa|two[- ]factor|2-step|two[- ]step|verification code|security code|authenticat(e|ion|or)( app| code)?|one[- ]time (pass)?code|otp|sign[- ]in code|login code|enter (the|your) code)\b""",
    )

    fun looksLike2fa(title: String, text: String): Boolean = TWO_FA.containsMatchIn("$title\n$text")

    /**
     * The apps a texted or mailed code comes from: SMS and email only, never a chat app or the site's own app (those are
     * the Copy-code path above).
     */
    val TEXT_APPS = setOf(
        "com.google.android.apps.messaging", "com.samsung.android.messaging", "com.android.mms", "com.android.messaging",
        "com.motorola.messaging", "com.google.android.gm", "com.google.android.gm.lite", "com.microsoft.office.outlook",
        "com.samsung.android.email.provider", "com.yahoo.mobile.client.android.mail", "ch.protonmail.android", "com.fsck.k9",
        "com.fastmail.app",
    )

    /** "Your code is", "code: 4829", "use 4829 to sign in": a plain code line in a text, besides [TWO_FA]'s wording. */
    // "this code" and "Code 123456" too: a bank's "DO NOT share this code ... Code 123456."
    private val TEXT_WORDS = Regex("""(?i)\b((your|the|this) ([\w-]+ ){0,3}(code|passcode|pin)\b|code( is|:)|code \d{4,8}\b|passcode|to (sign|log) ?in|to verify)""")
    /** Codes that aren't a sign-in: a promo, a parcel, a payment. */
    private val TEXT_NOT = Regex("""(?i)\b(promo|coupon|discount|voucher|gift card|tracking|shipment|delivery|referral|rs|inr|usd)\b|[$₹€£]""")
    private val DIGITS = Regex("""(?<![\d.,:/-])\d{4,8}(?!\d)(?![.,:/-]\d)""")

    /**
     * The one 4-8 digit code in a 2FA-worded SMS or email notification from [TEXT_APPS], else null. Two different
     * numbers (a code and an account's last four) are null too: you'd be asked about a number that may be wrong.
     */
    fun textCode(pkg: String, title: String, text: String): String? {
        if (pkg !in TEXT_APPS) return null
        val all = "$title\n$text"
        if (!(TWO_FA.containsMatchIn(all) || TEXT_WORDS.containsMatchIn(all)) || TEXT_NOT.containsMatchIn(all)) return null
        // A title that is only a number is the sender's short code ("55501" for a bank), never the code itself.
        val digitsIn = if (title.trim().all { it.isDigit() }) text else all
        return DIGITS.findAll(digitsIn).map { it.value }.distinct().toList().singleOrNull()
    }
}

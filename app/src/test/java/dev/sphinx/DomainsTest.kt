package dev.sphinx

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class DomainsTest {
    @Test fun anExactHostByDefault() {
        for (h in listOf("github.com", "www.github.com", "GITHUB.COM", "https://github.com/login", "github.com.")) assertTrue(h, Domains.matches(h, "github.com"))
        for (h in listOf("gist.github.com", "github.com.evil.io", "evilgithub.com", "github.co", "github-com.net", "githubcom", "xn--gthub-cta.com", "github.io", "localhost", "10.0.0.1", ""))
            assertFalse(h, Domains.matches(h, "github.com"))
    }

    @Test fun subdomainsOnlyWhenTheSiteOptsIn() {
        assertTrue(Domains.matches("gist.github.com", "*.github.com"))
        assertTrue(Domains.matches("github.com", "*.github.com"))
        assertFalse(Domains.matches("github.com.evil.io", "*.github.com"))
        assertEquals(listOf("https://github.com/*", "https://www.github.com/*"), Domains.patterns("github.com"))
        assertEquals(listOf("https://example.com/*", "https://*.example.com/*"), Domains.patterns("*.example.com"))
    }

    @Test fun theRealPublicSuffixListPrivateAndExceptionRulesIncluded() {
        for (d in listOf("co.uk", "co.id", "eu.org", "github.io", "*.github.io", "vercel.app", "com", "s3.amazonaws.com", "foo.ck", "*.co.id", "127.0.0.1"))
            assertNull(d, Domains.savable(d))
        assertEquals("someone.github.io", Domains.savable("https://someone.github.io/"))
        assertEquals("bbc.co.uk", Domains.savable("www.bbc.co.uk"))
        assertEquals("example.eu.org", Domains.savable("example.eu.org"))
        assertEquals("city.kawasaki.jp", Domains.savable("city.kawasaki.jp"))       // an exception rule (!city.kawasaki.jp)
        assertEquals("wordpress.com", Domains.savable("wordpress.com"))             // not a suffix: its own login host
        val psl = Psl.bundled
        assertTrue(psl.size > 9000)
        assertEquals("kawasaki.jp", psl.suffix("city.kawasaki.jp"))
        assertEquals("foo.kawasaki.jp", psl.suffix("foo.kawasaki.jp"))              // *.kawasaki.jp
        assertEquals("example.co.id", psl.registrable("www.example.co.id"))
        assertNull(psl.registrable("eu.org"))
        assertFalse(Domains.matches("someone.github.io", "github.io"))
        assertFalse(Domains.matches("other.github.io", "someone.github.io"))
        // *. may not reach over a public suffix below it: a wildcard rule's base, or any rule's parent.
        for (d in listOf("*.compute.amazonaws.com", "*.kawasaki.jp", "*.amazonaws.com", "*.blogspot.com")) assertNull(d, Domains.savable(d))
        assertEquals("kawasaki.jp", Domains.savable("kawasaki.jp"))
        assertEquals("*.github.com", Domains.savable("*.github.com"))
        assertTrue(psl.coversSuffixes("compute.amazonaws.com"))
        assertFalse(psl.coversSuffixes("github.com"))
    }

    @Test fun theSuffixListIsTheExtensionsFile() {
        val app = File("src/main/resources/sphinx/public_suffix_list.dat").readText().replace("\r", "")
        val ext = File("../extension/public_suffix_list.dat").readText().replace("\r", "")
        assertEquals(ext, app)
        assertTrue(app.contains("// ===BEGIN PRIVATE DOMAINS==="))
    }

    @Test fun issuersStartWithSingleOwnerLoginHostsOnly() {
        assertEquals(listOf("github.com"), Domains.forIssuer("GitHub"))
        assertEquals(listOf("id.atlassian.com"), Domains.forIssuer("Jira"))
        assertEquals(listOf("login.salesforce.com"), Domains.forIssuer("Salesforce"))
        assertEquals(listOf("app.datadoghq.com"), Domains.forIssuer("Datadog"))
        assertEquals(listOf("wordpress.com"), Domains.forIssuer("WordPress"))
        for (tenant in listOf("Okta", "Slack", "Zoom", "Sentry", "Acme")) assertEquals(tenant, emptyList<String>(), Domains.forIssuer(tenant))
        assertEquals(listOf("accounts.zoho.com"), Domains.forIssuer("accounts.zoho.com"))
        assertEquals(emptyList<String>(), Domains.forIssuer("eu.org"))
        // No seeded site is a public suffix, a wildcard, or a multi-tenant parent.
        for (i in listOf("google", "atlassian", "okta", "slack", "zoom", "sentry", "datadog", "salesforce", "wordpress", "shopify", "heroku")) {
            for (d in Domains.forIssuer(i)) { assertFalse(d, d.startsWith("*.")); assertEquals(d, d, Domains.savable(d)) }
            assertFalse(i, Domains.forIssuer(i).any { it in setOf("atlassian.net", "okta.com", "salesforce.com", "slack.com", "zoom.us", "sentry.io", "datadoghq.com", "myshopify.com") })
        }
        assertEquals(listOf("com.github.android"), Domains.appsFor(listOf("github.com")))
    }

    private data class A(val id: String, val name: String, val domains: List<String>)

    @Test fun severalAccountsOnOneSite() {
        val work = A("w", "alex-work", listOf("github.com"))
        val home = A("h", "alex@example.com", listOf("github.com"))
        val other = A("o", "me", listOf("gitlab.com"))
        val all = listOf(work, home, other)
        val found = Domains.candidates("github.com", all) { it.domains }
        assertEquals(listOf(work, home), found)
        assertEquals(work, Domains.pick(found, "Alex-Work") { it.name })
        assertEquals(home, Domains.pick(found, "alex") { it.name })
        assertNull(Domains.pick(found, "someone-else") { it.name })
        assertNull(Domains.pick(found, null) { it.name })
        assertEquals(other, Domains.pick(listOf(other), null) { it.name })
        // Authenticator labels ("GitHub:user") match the user name typed on the sign-in page.
        val a1 = A("1", "GitHub:alex03", listOf("github.com")); val a2 = A("2", "GitHub:alex-work", listOf("github.com"))
        assertEquals(a1, Domains.pick(listOf(a1, a2), "alex03") { it.name })
        assertTrue(Domains.candidates("github.com.evil.io", all) { it.domains }.isEmpty())
        // The tab and the frame must be one account's sites.
        assertTrue(Domains.candidates("github.com", all, frame = "gitlab.com") { it.domains }.isEmpty())
        assertEquals(listOf(A("x", "x", listOf("github.com", "gitlab.com"))), Domains.candidates("github.com", listOf(A("x", "x", listOf("github.com", "gitlab.com"))), frame = "gitlab.com") { it.domains })
    }

    @Test fun twoFactorNotifications() {
        assertTrue(Domains.looksLike2fa("GitHub", "Enter your two-factor authentication code"))
        assertTrue(Domains.looksLike2fa("Sign in", "Open your authenticator app to get a verification code"))
        assertFalse(Domains.looksLike2fa("GitHub", "someone starred your repo"))
        assertFalse(Domains.looksLike2fa("Discord", "Sam: send me the code for the game"))
    }
}

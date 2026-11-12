/*
 * Copyright 2022-Present Okta, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.okta.authfoundation.credential.kmp

import com.okta.authfoundation.InternalAuthFoundationApi
import com.okta.authfoundation.api.http.KtorHttpExecutor
import com.okta.authfoundation.client.Cache
import com.okta.authfoundation.client.OAuth2ClientConfiguration
import com.okta.authfoundation.client.OidcClock
import com.okta.authfoundation.client.kmp.OAuth2Client
import com.okta.authfoundation.credential.InMemoryDefaultCredentialIdStore
import com.okta.authfoundation.credential.kmp.storage.RoomTokenStorage
import com.okta.authfoundation.credential.kmp.storage.TokenDatabase
import com.okta.authfoundation.credential.kmp.storage.createInMemoryTokenDatabase
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Regression tests for GitHub issue #461: sequential token refreshes must send the credential's
 * *current* (rotated) refresh token, never an already-consumed one.
 *
 * These tests exercise the real SDK implementation end to end — [TokenCredentialManager],
 * [CredentialImpl], [CredentialDataSource], [CoalescingOrchestrator][com.okta.authfoundation.util.CoalescingOrchestrator],
 * [OAuth2Client], [KtorHttpExecutor] — against a MockWebServer that behaves like an authorization
 * server with refresh token rotation: a reused refresh token is rejected with HTTP 400
 * `invalid_grant`. Nothing in the refresh or storage-update path is mocked.
 */
@OptIn(InternalAuthFoundationApi::class)
class RefreshTokenRotationRegressionTest {
    private companion object {
        const val CREDENTIAL_ID = "test-credential-id"
        const val T0 = 1_000_000L
    }

    private class TestClock(
        var time: Long,
    ) : OidcClock {
        override fun currentTimeEpochSecond(): Long = time
    }

    private object NoOpCache : Cache {
        override fun get(key: String): String? = null

        override fun set(
            key: String,
            value: String,
        ) {}

        override fun clear() {}
    }

    private class PassthroughEncryptionHandler : TokenEncryptionHandler {
        override suspend fun encrypt(plaintext: ByteArray): EncryptionResult = EncryptionResult(ciphertext = plaintext)

        override suspend fun decrypt(
            ciphertext: ByteArray,
            encryptionExtras: Map<String, String>,
        ): ByteArray = ciphertext
    }

    /**
     * A rotating authorization server stand-in. Records every token request body, rotates the
     * refresh token on each accepted grant, and (when [rejectReusedRefreshToken] is set) rejects
     * an already-consumed refresh token with HTTP 400 `invalid_grant`, like Okta with rotation
     * enabled.
     */
    private class RotatingTokenDispatcher(
        private val baseUrl: String,
    ) : Dispatcher() {
        val tokenRequestBodies = CopyOnWriteArrayList<String>()
        var currentRefreshToken: String = "RT1"
        var rejectReusedRefreshToken: Boolean = true
        var returnNewRefreshToken: Boolean = true
        private var rotation = 2

        override fun dispatch(request: RecordedRequest): MockResponse {
            val path = request.path ?: return MockResponse().setResponseCode(404)
            return when {
                path.endsWith("/.well-known/openid-configuration") ->
                    jsonResponse(
                        buildJsonObject {
                            put("issuer", baseUrl)
                            put("authorization_endpoint", "$baseUrl/authorize")
                            put("token_endpoint", "$baseUrl/token")
                            put("userinfo_endpoint", "$baseUrl/userinfo")
                            put("jwks_uri", "$baseUrl/keys")
                            put("introspection_endpoint", "$baseUrl/introspect")
                            put("revocation_endpoint", "$baseUrl/revoke")
                            put("end_session_endpoint", "$baseUrl/logout")
                        }.toString()
                    )

                path.endsWith("/token") -> {
                    val body = request.body.readUtf8()
                    tokenRequestBodies.add(body)
                    val sentRefreshToken = formValue(body, "refresh_token")
                    if (rejectReusedRefreshToken && sentRefreshToken != currentRefreshToken) {
                        return jsonResponse(
                            """{"error":"invalid_grant","error_description":"The refresh token was already used."}""",
                            statusCode = 400
                        )
                    }
                    val n = rotation++
                    val refreshPart = if (returnNewRefreshToken) ""","refresh_token":"RT$n"""" else ""
                    if (returnNewRefreshToken) currentRefreshToken = "RT$n"
                    jsonResponse("""{"token_type":"Bearer","expires_in":3600,"access_token":"AT$n"$refreshPart,"scope":"openid"}""")
                }

                else -> MockResponse().setResponseCode(404)
            }
        }

        private fun jsonResponse(
            body: String,
            statusCode: Int = 200,
        ): MockResponse =
            MockResponse()
                .setResponseCode(statusCode)
                .setHeader("Content-Type", "application/json")
                .setBody(body)
    }

    private class Fixture {
        val clock = TestClock(T0)
        val server = MockWebServer()
        val dispatcher: RotatingTokenDispatcher
        val config: OAuth2ClientConfiguration
        val client: OAuth2Client
        val database: TokenDatabase = createInMemoryTokenDatabase()
        val storage: TokenStorage
        val defaultIdStore = InMemoryDefaultCredentialIdStore()
        val manager: TokenCredentialManager

        init {
            server.start()
            val baseUrl = server.url("/").toString().trimEnd('/')
            dispatcher = RotatingTokenDispatcher(baseUrl)
            server.dispatcher = dispatcher
            config =
                OAuth2ClientConfiguration(
                    clientId = "test-client-id",
                    defaultScope = listOf("openid"),
                    issuerUrl = baseUrl,
                    apiExecutor = KtorHttpExecutor(),
                    clock = clock,
                    json = Json { ignoreUnknownKeys = true },
                    cache = NoOpCache,
                    authorizationServerId = null,
                    clientSecret = "",
                    acrValues = null
                )
            client = OAuth2Client.createFromConfiguration(config)
            storage = RoomTokenStorage(database, PassthroughEncryptionHandler(), config)
            manager = TokenCredentialManager(client, storage, defaultIdStore)
        }

        suspend fun storeInitialCredential() {
            val token =
                TokenData(
                    id = CREDENTIAL_ID,
                    tokenType = "Bearer",
                    expiresIn = 3600,
                    accessToken = "AT1",
                    scope = "openid",
                    refreshToken = "RT1",
                    idToken = null,
                    deviceSecret = null,
                    issuedTokenType = null,
                    configuration = config,
                    issuedAt = clock.time
                )
            val credential = manager.store(token).getOrThrow()
            manager.setDefault(credential).getOrThrow()
        }

        fun close() {
            server.shutdown()
            database.close()
        }
    }

    /**
     * The full reproduction from GitHub issue #461: a first refresh consumes RT1 and persists RT2,
     * but a second sequential refresh (after re-retrieving the credential) must send RT2 — not the
     * already-consumed RT1. Covers the second and third refreshes and a reload from storage.
     */
    @Test
    fun sequentialRefresh_SendsCurrentRotatedRefreshToken() =
        runTest {
            val fixture = Fixture()
            try {
                fixture.storeInitialCredential()
                val credential = fixture.manager.getDefault().getOrThrow()!!

                // 1. First refresh sends RT1; the server rotates to RT2.
                val afterFirst = credential.refreshToken().getOrThrow()
                assertEquals("RT1", formValue(fixture.dispatcher.tokenRequestBodies[0], "refresh_token"))

                // 2. Persistent storage and the in-memory credential both contain RT2.
                assertEquals("RT2", afterFirst.token.refreshToken)
                assertEquals("RT2", fixture.manager.getDefault().getOrThrow()!!.token.refreshToken)
                assertEquals("RT2", fixture.storage.getToken(CREDENTIAL_ID).getOrThrow().refreshToken)

                // 3. Expire the access token using the controlled test clock, and retrieve the
                // credential again — a fresh snapshot carrying RT2.
                fixture.clock.time = T0 + 10_000
                val fresh = fixture.manager.getDefault().getOrThrow()!!
                assertNull(fresh.accessTokenIfNotExpired())
                assertEquals("RT2", fresh.token.refreshToken)

                // 4. The second request must send RT2.
                val afterSecond = fresh.refreshIfExpired().getOrThrow()
                assertEquals("RT2", formValue(fixture.dispatcher.tokenRequestBodies[1], "refresh_token"))
                assertEquals("RT3", afterSecond.token.refreshToken)
                assertEquals("RT3", fixture.storage.getToken(CREDENTIAL_ID).getOrThrow().refreshToken)
                assertEquals("RT3", fixture.manager.getDefault().getOrThrow()!!.token.refreshToken)

                // 5. A third refresh must send RT3.
                fixture.clock.time = T0 + 20_000
                val afterThird = fixture.manager.getDefault().getOrThrow()!!.refreshIfExpired().getOrThrow()
                assertEquals("RT3", formValue(fixture.dispatcher.tokenRequestBodies[2], "refresh_token"))
                assertEquals("RT4", afterThird.token.refreshToken)

                // 6. Reloading the credential from storage (fresh manager, empty cache) sees RT4
                // and the fourth refresh sends RT4.
                val reloadedManager = TokenCredentialManager(fixture.client, fixture.storage, fixture.defaultIdStore)
                fixture.clock.time = T0 + 30_000
                val fromStorage = reloadedManager.getDefault().getOrThrow()!!
                assertEquals("RT4", fromStorage.token.refreshToken)
                val afterFourth = fromStorage.refreshIfExpired().getOrThrow()
                assertEquals("RT4", formValue(fixture.dispatcher.tokenRequestBodies[3], "refresh_token"))
                assertEquals("RT5", afterFourth.token.refreshToken)
                assertEquals(4, fixture.dispatcher.tokenRequestBodies.size)
            } finally {
                fixture.close()
            }
        }

    /**
     * Concurrent refreshes of the same credential must still coalesce into a single token request,
     * and every caller must observe the rotated token.
     */
    @Test
    fun concurrentRefresh_CoalescesIntoSingleRequest() =
        runTest {
            val fixture = Fixture()
            try {
                fixture.storeInitialCredential()
                val first = fixture.manager.getDefault().getOrThrow()!!
                val second = fixture.manager.getDefault().getOrThrow()!!

                val (result1, result2) =
                    coroutineScope {
                        val a = async { first.refreshToken() }
                        val b = async { second.refreshToken() }
                        a.await() to b.await()
                    }

                assertEquals(1, fixture.dispatcher.tokenRequestBodies.size)
                assertEquals("RT1", formValue(fixture.dispatcher.tokenRequestBodies[0], "refresh_token"))
                assertEquals("RT2", result1.getOrThrow().token.refreshToken)
                assertEquals("RT2", result2.getOrThrow().token.refreshToken)
                assertEquals("RT2", fixture.storage.getToken(CREDENTIAL_ID).getOrThrow().refreshToken)
            } finally {
                fixture.close()
            }
        }

    /**
     * A stale snapshot whose refresh token has already been rotated away must not resurrect the
     * consumed token: even when the server stops rotating (response carries no `refresh_token`),
     * the refresh must send and persist the credential's current refresh token.
     */
    @Test
    fun staleSnapshotRefresh_WithExtraParams_UsesCurrentRefreshToken() =
        runTest {
            val fixture = Fixture()
            try {
                fixture.storeInitialCredential()
                val stale = fixture.manager.getDefault().getOrThrow()!!

                // Rotate RT1 -> RT2 through the normal orchestrated path.
                val afterFirst = stale.refreshToken().getOrThrow()
                assertEquals("RT2", afterFirst.token.refreshToken)

                // The server stops rotating: responses carry no refresh_token and any valid
                // refresh token is accepted.
                fixture.dispatcher.returnNewRefreshToken = false
                fixture.dispatcher.rejectReusedRefreshToken = false

                val result = stale.refreshToken(mapOf("acr_values" to "urn:okta:loa:2fa:any"))
                assertTrue(result.isSuccess)
                assertEquals("RT2", formValue(fixture.dispatcher.tokenRequestBodies[1], "refresh_token"))
                assertEquals("RT2", fixture.storage.getToken(CREDENTIAL_ID).getOrThrow().refreshToken)
                assertEquals("RT2", fixture.manager.getDefault().getOrThrow()!!.token.refreshToken)
            } finally {
                fixture.close()
            }
        }
}

private fun formValue(
    body: String,
    key: String,
): String? =
    body
        .split("&")
        .map { it.split("=", limit = 2) }
        .firstOrNull { it.first() == key }
        ?.getOrNull(1)

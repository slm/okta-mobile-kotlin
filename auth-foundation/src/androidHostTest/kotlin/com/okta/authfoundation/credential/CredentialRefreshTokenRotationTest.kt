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
package com.okta.authfoundation.credential

import androidx.biometric.BiometricPrompt
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.common.truth.Truth.assertThat
import com.okta.authfoundation.AuthFoundation
import com.okta.authfoundation.client.ApplicationContextHolder
import com.okta.authfoundation.client.EndpointsFactory
import com.okta.authfoundation.client.OAuth2ClientResult
import com.okta.testhelpers.MockAesEncryptionHandler
import com.okta.testhelpers.OktaRule
import com.okta.testhelpers.RequestMatchers.method
import com.okta.testhelpers.RequestMatchers.path
import io.mockk.coEvery
import io.mockk.every
import io.mockk.just
import io.mockk.mockkObject
import io.mockk.runs
import io.mockk.unmockkAll
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.After
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Sequential refresh behavior for the deprecated Android [Credential] / [CredentialDataSource]
 * surface (GitHub issue #461 scope verification): a second sequential refresh in the same process
 * must send the rotated refresh token, not the already-consumed one.
 *
 * The refresh and storage-update paths run against the real implementation and a MockWebServer
 * that rotates refresh tokens; only framework singletons ([CredentialDataSource.getInstance],
 * [DefaultCredentialIdDataStore.instance]) are redirected to real in-memory instances.
 */
@RunWith(AndroidJUnit4::class)
class CredentialRefreshTokenRotationTest {
    @get:Rule val oktaRule = OktaRule()

    private lateinit var storage: InMemoryTokenStorage
    private lateinit var credentialDataSource: CredentialDataSource
    private lateinit var defaultCredentialIdDataStore: DefaultCredentialIdDataStore
    private val sentBodies = mutableListOf<String>()

    @Before
    fun setUp() {
        mockkObject(CredentialDataSource)
        mockkObject(ApplicationContextHolder)
        every { ApplicationContextHolder.appContext } returns ApplicationProvider.getApplicationContext()
        mockkObject(DefaultCredentialIdDataStore)
        defaultCredentialIdDataStore = DefaultCredentialIdDataStore(MockAesEncryptionHandler.getInstance())
        every { DefaultCredentialIdDataStore.instance } returns defaultCredentialIdDataStore
        mockkObject(AuthFoundation)
        coEvery { AuthFoundation.initializeStorage() } just runs
        EndpointsFactory.reset()
        storage = InMemoryTokenStorage()
        credentialDataSource = CredentialDataSource(storage)
        coEvery { CredentialDataSource.getInstance() } returns credentialDataSource
    }

    @After
    fun tearDown() {
        EndpointsFactory.reset()
        unmockkAll()
    }

    @Test
    fun sequentialRefresh_SendsCurrentRotatedRefreshToken(): Unit =
        runBlocking {
            val baseUrl = oktaRule.baseUrl.toString().removeSuffix("/")
            oktaRule.enqueue(method("GET"), path("/.well-known/openid-configuration")) { response ->
                response.setBody(discoveryJson(baseUrl))
            }
            oktaRule.enqueue(method("POST"), path("/v1/token")) { request, response ->
                sentBodies.add(request.bodyText)
                response.setBody(tokenResponse("AT2", "RT2"))
            }
            oktaRule.enqueue(method("POST"), path("/v1/token")) { request, response ->
                sentBodies.add(request.bodyText)
                response.setBody(tokenResponse("AT3", "RT3"))
            }

            val token =
                createToken(
                    id = "id",
                    accessToken = "AT1",
                    refreshToken = "RT1",
                    oidcConfiguration = oktaRule.configuration
                )
            val credential = credentialDataSource.createCredential(token)
            Credential.default = credential

            // 1. First refresh sends RT1; the server rotates to RT2.
            val first = Credential.default!!.refreshToken()
            assertThat(first).isInstanceOf(OAuth2ClientResult.Success::class.java)
            assertThat(sentBodies[0]).contains("refresh_token=RT1")

            // 2. Persistent storage and the in-memory credential both contain RT2.
            assertThat(storage.getToken("id").refreshToken).isEqualTo("RT2")
            assertThat(Credential.default!!.token.refreshToken).isEqualTo("RT2")

            // 3. Second refresh on the re-retrieved default credential sends RT2.
            val second = Credential.default!!.refreshToken()
            assertThat(second).isInstanceOf(OAuth2ClientResult.Success::class.java)
            assertThat(sentBodies[1]).contains("refresh_token=RT2")
            assertThat(storage.getToken("id").refreshToken).isEqualTo("RT3")
            assertThat(Credential.default!!.token.refreshToken).isEqualTo("RT3")
            assertThat(sentBodies).hasSize(2)
        }

    private fun discoveryJson(baseUrl: String): String =
        buildJsonObject {
            put("issuer", baseUrl)
            put("authorization_endpoint", "$baseUrl/v1/authorize")
            put("token_endpoint", "$baseUrl/v1/token")
            put("userinfo_endpoint", "$baseUrl/v1/userinfo")
            put("jwks_uri", "$baseUrl/v1/keys")
            put("introspection_endpoint", "$baseUrl/v1/introspect")
            put("revocation_endpoint", "$baseUrl/v1/revoke")
            put("end_session_endpoint", "$baseUrl/v1/logout")
            put("device_authorization_endpoint", "$baseUrl/v1/device/authorize")
        }.toString()

    private fun tokenResponse(
        accessToken: String,
        refreshToken: String,
    ): String = """{"token_type":"Bearer","expires_in":3600,"access_token":"$accessToken","refresh_token":"$refreshToken","scope":"openid"}"""

    private class InMemoryTokenStorage : TokenStorage {
        private val tokens = mutableMapOf<String, Token>()
        private val metadata = mutableMapOf<String, Token.Metadata>()

        override suspend fun allIds(): List<String> = tokens.keys.toList()

        override suspend fun metadata(id: String): Token.Metadata? = metadata[id]

        override suspend fun setMetadata(metadata: Token.Metadata) {
            this.metadata[metadata.id] = metadata
        }

        override suspend fun add(
            token: Token,
            metadata: Token.Metadata,
            security: Credential.Security,
        ) {
            tokens[token.id] = token
            this.metadata[token.id] = metadata
        }

        override suspend fun remove(id: String) {
            tokens.remove(id)
            metadata.remove(id)
        }

        override suspend fun replace(token: Token) {
            if (!tokens.containsKey(token.id)) {
                throw NoSuchElementException("No token with id ${token.id}")
            }
            tokens[token.id] = token
        }

        override suspend fun getToken(
            id: String,
            promptInfo: BiometricPrompt.PromptInfo?,
        ): Token = tokens[id] ?: throw NoSuchElementException("No token with id $id")
    }
}

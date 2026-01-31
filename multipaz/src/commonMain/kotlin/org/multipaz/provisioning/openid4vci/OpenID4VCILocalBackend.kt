package org.multipaz.provisioning.openid4vci

import org.multipaz.crypto.AsymmetricKey
import org.multipaz.provisioning.CredentialKeyAttestation
import org.multipaz.securearea.KeyAttestation

/**
 * An implementation of [OpenID4VCIBackend] where the back-end is implemented locally.
 *
 * This is intended only for test apps.
 *
 * @property clientAssertionKey the key used to mint client assertions.
 * @property attestationKey  the key used to mint key attestations.
 * @property clientId value for `client_id` that this back-end will use.
 * @property walletName the name of the wallet.
 * @property walletLink an URL with information about the wallet.
 */
class OpenID4VCILocalBackend(
    val clientAssertionKey: AsymmetricKey,
    val attestationKey: AsymmetricKey,
    val clientId: String,
    val walletName: String,
    val walletLink: String
): OpenID4VCIBackend {
    override suspend fun getClientId(): String = clientId

    override suspend fun createJwtClientAssertion(authorizationServerIdentifier: String): String =
        OpenID4VCIBackendUtil.createJwtClientAssertion(
            signingKey = clientAssertionKey,
            clientId = clientId,
            authorizationServerIdentifier = authorizationServerIdentifier,
        )

    override suspend fun createJwtWalletAttestation(keyAttestation: KeyAttestation): String =
        OpenID4VCIBackendUtil.createWalletAttestation(
            signingKey = attestationKey,
            clientId = clientId,
            attestationIssuer = attestationKey.subject,
            attestedKey = keyAttestation.publicKey,
            nonce = null,
            walletName = walletName,
            walletLink = walletLink
        )

    override suspend fun createJwtKeyAttestation(
        credentialKeyAttestations: List<CredentialKeyAttestation>,
        challenge: String,
        userAuthentication: List<String>?,
        keyStorage: List<String>?
    ): String = OpenID4VCIBackendUtil.createJwtKeyAttestation(
        signingKey = attestationKey,
        attestationIssuer = attestationKey.subject,
        keysToAttest = credentialKeyAttestations,
        challenge = challenge,
        userAuthentication = userAuthentication,
        keyStorage = keyStorage,
    )
}
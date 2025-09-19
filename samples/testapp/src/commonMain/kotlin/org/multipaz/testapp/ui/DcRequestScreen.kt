package org.multipaz.testapp.ui

import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import io.ktor.utils.io.core.toByteArray
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.io.bytestring.ByteString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.multipaz.cbor.Bstr
import org.multipaz.cbor.Cbor
import org.multipaz.cbor.DataItem
import org.multipaz.cbor.Tagged
import org.multipaz.cbor.buildCborArray
import org.multipaz.compose.rememberUiBoundCoroutineScope
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.Crypto
import org.multipaz.crypto.EcCurve
import org.multipaz.crypto.EcPrivateKey
import org.multipaz.crypto.X509CertChain
import org.multipaz.documenttype.DocumentCannedRequest
import org.multipaz.documenttype.DocumentType
import org.multipaz.mdoc.connectionmethod.MdocConnectionMethod
import org.multipaz.mdoc.connectionmethod.MdocConnectionMethodBle
import org.multipaz.mdoc.connectionmethod.MdocConnectionMethodNfc
import org.multipaz.mdoc.engagement.Capability
import org.multipaz.mdoc.engagement.DeviceEngagement
import org.multipaz.mdoc.nfc.scanNfcMdocReader
import org.multipaz.mdoc.role.MdocRole
import org.multipaz.mdoc.sessionencryption.SessionEncryption
import org.multipaz.mdoc.transport.MdocTransport
import org.multipaz.mdoc.transport.MdocTransportOptions
import org.multipaz.mdoc.zkp.ZkSystemRepository
import org.multipaz.models.digitalcredentials.DigitalCredentials
import org.multipaz.models.verification.MdocApiDcResponse
import org.multipaz.models.verification.OpenID4VPDcResponse
import org.multipaz.request.JsonRequestedClaim
import org.multipaz.request.MdocRequestedClaim
import org.multipaz.testapp.App
import org.multipaz.testapp.TestAppUtils
import org.multipaz.testapp.getAppToAppOrigin
import org.multipaz.util.Logger
import org.multipaz.models.verification.VerificationUtil
import org.multipaz.testapp.TestAppSettingsModel
import org.multipaz.util.Constants
import org.multipaz.util.UUID
import org.multipaz.util.toBase64Url
import kotlin.random.Random

private const val TAG = "DcRequestScreen"

private data class RequestEntry(
    val displayName: String,
    val documentType: DocumentType,
    val sampleRequest: DocumentCannedRequest
)

private enum class RequestProtocol(
    val displayName: String,
    val exchangeProtocolNames: List<String>,
    val signRequest: Boolean,
) {
    W3C_DC_OPENID4VP_29(
        displayName = "OpenID4VP 1.0",
        exchangeProtocolNames = listOf("openid4vp-v1-signed"),
        signRequest = true,
    ),
    W3C_DC_OPENID4VP_29_UNSIGNED(
        displayName = "OpenID4VP 1.0 (Unsigned)",
        exchangeProtocolNames = listOf("openid4vp-v1-unsigned"),
        signRequest = false,
    ),
    W3C_DC_OPENID4VP_24(
        displayName = "OpenID4VP Draft 24",
        exchangeProtocolNames = listOf("openid4vp"),
        signRequest = true,
    ),
    W3C_DC_OPENID4VP_24_UNSIGNED(
        displayName = "OpenID4VP Draft 24 (Unsigned)",
        exchangeProtocolNames = listOf("openid4vp"),
        signRequest = false,
    ),
    W3C_DC_MDOC_API(
        displayName = "ISO 18013-7 Annex C",
        exchangeProtocolNames = listOf("org-iso-mdoc"),
        signRequest = true
    ),
    W3C_DC_MDOC_API_UNSIGNED(
        displayName = "ISO 18013-7 Annex C (Unsigned)",
        exchangeProtocolNames = listOf("org-iso-mdoc"),
        signRequest = false
    ),

    W3C_DC_MDOC_API_AND_OPENID4VP_29(
        displayName = "ISO 18013-7 Annex C + OpenID4VP 1.0",
        exchangeProtocolNames = listOf("org-iso-mdoc", "openid4vp-v1-signed"),
        signRequest = true
    ),
    W3C_DC_MDOC_API_AND_OPENID4VP_29_UNSIGNED(
        displayName = "ISO 18013-7 Annex C + OpenID4VP 1.0 (Unsigned)",
        exchangeProtocolNames = listOf("org-iso-mdoc", "openid4vp-v1-unsigned"),
        signRequest = false
    ),
    W3C_DC_MDOC_API_AND_OPENID4VP_24(
        displayName = "ISO 18013-7 Annex C + OpenID4VP Draft 24",
        exchangeProtocolNames = listOf("org-iso-mdoc", "openid4vp"),
        signRequest = true
    ),
    W3C_DC_MDOC_API_AND_OPENID4VP_24_UNSIGNED(
        displayName = "ISO 18013-7 Annex C + OpenID4VP Draft 24 (Unsigned)",
        exchangeProtocolNames = listOf("org-iso-mdoc", "openid4vp"),
        signRequest = false
    ),

    OPENID4VP_29_AND_W3C_DC_MDOC_API(
        displayName = "OpenID4VP 1.0 + ISO 18013-7 Annex C",
        exchangeProtocolNames = listOf("openid4vp-v1-signed", "org-iso-mdoc"),
        signRequest = true
    ),
    OPENID4VP_29_UNSIGNED_AND_W3C_DC_MDOC_API(
        displayName = "OpenID4VP 1.0 + ISO 18013-7 Annex C (Unsigned)",
        exchangeProtocolNames = listOf("openid4vp-v1-unsigned", "org-iso-mdoc"),
        signRequest = false
    ),
    OPENID4VP_24_AND_W3C_DC_MDOC_API(
        displayName = "OpenID4VP Draft 24 + ISO 18013-7 Annex C",
        exchangeProtocolNames = listOf("openid4vp", "org-iso-mdoc"),
        signRequest = true
    ),
    OPENID4VP_24_UNSIGNED_AND_W3C_DC_MDOC_API(
        displayName = "OpenID4VP Draft 24 + ISO 18013-7 Annex C (Unsigned)",
        exchangeProtocolNames = listOf("openid4vp", "org-iso-mdoc"),
        signRequest = false
    ),
}

private enum class CredentialFormat(
    val displayName: String,
) {
    ISO_MDOC("ISO mdoc"),
    IETF_SDJWT("IETF SD-JWT"),
}

private var lastRequest: Int = 0
private var lastProtocol: Int = 0
private var lastFormat: Int = 0

@OptIn(ExperimentalMaterial3Api::class, ExperimentalCoroutinesApi::class)
@Composable
fun DcRequestScreen(
    app: App,
    showToast: (message: String) -> Unit,
    showResponse: (vpToken: JsonObject?, deviceResponse: DataItem?, sessionTranscript: DataItem, nonce: ByteString?) -> Unit
) {
    val requestOptions = mutableListOf<RequestEntry>()
    for (documentType in TestAppUtils.provisionedDocumentTypes) {
        for (sampleRequest in documentType.cannedRequests) {
            requestOptions.add(RequestEntry(
                displayName = "${documentType.displayName}: ${sampleRequest.displayName}",
                documentType = documentType,
                sampleRequest = sampleRequest
            ))
        }
    }
    val requestDropdownExpanded = remember { mutableStateOf(false) }
    val requestSelected = remember { mutableStateOf(requestOptions[lastRequest]) }
    val protocolOptions = RequestProtocol.entries
    val protocolDropdownExpanded = remember { mutableStateOf(false) }
    val protocolSelected = remember { mutableStateOf(protocolOptions[lastProtocol]) }
    val formatOptions = CredentialFormat.entries
    val formatDropdownExpanded = remember { mutableStateOf(false) }
    val formatSelected = remember { mutableStateOf(formatOptions[lastFormat]) }
    val coroutineScope = rememberUiBoundCoroutineScope { app.promptModel }

    LazyColumn(
        modifier = Modifier.padding(8.dp)
    ) {
        item {
            ComboBox(
                headline = "Claims to request",
                availableRequests = requestOptions,
                comboBoxSelected = requestSelected,
                comboBoxExpanded = requestDropdownExpanded,
                getDisplayName = { it.displayName },
                onSelected = { index, value -> lastRequest = index }
            )
        }
        item {
            ComboBox(
                headline = "W3C Digital Credentials Protocol(s)",
                availableRequests = protocolOptions,
                comboBoxSelected = protocolSelected,
                comboBoxExpanded = protocolDropdownExpanded,
                getDisplayName = { it.displayName },
                onSelected = { index, value -> lastProtocol = index }
            )
        }
        item {
            ComboBox(
                headline = "Credential Format",
                availableRequests = formatOptions,
                comboBoxSelected = formatSelected,
                comboBoxExpanded = formatDropdownExpanded,
                getDisplayName = { it.displayName },
                onSelected = { index, value -> lastFormat = index }
            )
        }
        item {
            TextButton(
                onClick = {
                    coroutineScope.launch {
                        try {
                            doDcRequestFlowLocalApi(
                                appReaderKey = app.readerKey,
                                appReaderCertChain = X509CertChain(certificates = listOf(app.readerCert, app.readerRootCert)),
                                request = requestSelected.value.sampleRequest,
                                protocol = protocolSelected.value,
                                format = formatSelected.value,
                                zkSystemRepository = app.zkSystemRepository,
                                showResponse = showResponse
                            )
                        } catch (error: Throwable) {
                            Logger.e(TAG, "Error requesting credentials", error)
                            showToast("Error: ${error.message}")
                        }
                    }
                },
                content = { Text("Request via local DC API") }
            )
        }
        item {
            TextButton(
                onClick = {
                    coroutineScope.launch {
                        try {
                            doDcRequestFlowNfcOver18013(
                                settingsModel = app.settingsModel,
                                appReaderKey = app.readerKey,
                                appReaderCertChain = X509CertChain(certificates = listOf(app.readerCert, app.readerRootCert)),
                                request = requestSelected.value.sampleRequest,
                                protocol = protocolSelected.value,
                                format = formatSelected.value,
                                zkSystemRepository = app.zkSystemRepository,
                                showToast = showToast,
                                showResponse = showResponse
                            )
                        } catch (error: Throwable) {
                            Logger.e(TAG, "Error requesting credentials", error)
                            showToast("Error: ${error.message}")
                        }
                    }
                },
                content = { Text("NFC engagement with DC API over ISO/IEC 18013-5") }
            )
        }
    }
}

private suspend fun doDcRequestFlowLocalApi(
    appReaderKey: EcPrivateKey,
    appReaderCertChain: X509CertChain,
    request: DocumentCannedRequest,
    protocol: RequestProtocol,
    format: CredentialFormat,
    zkSystemRepository: ZkSystemRepository,
    showResponse: (vpToken: JsonObject?, deviceResponse: DataItem?, sessionTranscript: DataItem, nonce: ByteString?) -> Unit
) {
    val origin = getAppToAppOrigin()
    doDcRequestFlow(
        origin = origin,
        appReaderKey = appReaderKey,
        appReaderCertChain = appReaderCertChain,
        request = request,
        protocol = protocol,
        format = format,
        zkSystemRepository = zkSystemRepository,
        showResponse = showResponse,
        getCredential = { request ->
            DigitalCredentials.Default.request(request)
        }
    )
}

private suspend fun doDcRequestFlow(
    origin: String,
    appReaderKey: EcPrivateKey,
    appReaderCertChain: X509CertChain,
    request: DocumentCannedRequest,
    protocol: RequestProtocol,
    format: CredentialFormat,
    zkSystemRepository: ZkSystemRepository,
    showResponse: (vpToken: JsonObject?, deviceResponse: DataItem?, sessionTranscript: DataItem, nonce: ByteString?) -> Unit,
    getCredential: suspend (request: JsonObject) -> JsonObject,
) {
    when (format) {
        CredentialFormat.ISO_MDOC -> {
            require(request.mdocRequest != null) { "No ISO mdoc format in request" }
        }

        CredentialFormat.IETF_SDJWT -> {
            require(request.jsonRequest != null) { "No IETF SD-JWT format in request" }
        }
    }

    val nonce = ByteString(Random.Default.nextBytes(16))
    val responseEncryptionKey = Crypto.createEcPrivateKey(EcCurve.P256)
    val (readerKey, readerCertChain) = if (protocol.signRequest) {
        Pair(appReaderKey, appReaderCertChain)
    } else {
        Pair(null, null)
    }
    // According to OpenID4VP, Client ID must be set for signed requests and not for unsigned requests
    val clientId = "web-origin:$origin"

    val dcRequestObject = when (format) {
        CredentialFormat.ISO_MDOC -> {
            val claims = mutableListOf<MdocRequestedClaim>()
            request.mdocRequest!!.namespacesToRequest.forEach { namespaceRequest ->
                namespaceRequest.dataElementsToRequest.forEach { (mdocDataElement, intentToRetain) ->
                    claims.add(
                        MdocRequestedClaim(
                            namespaceName = namespaceRequest.namespace,
                            dataElementName = mdocDataElement.attribute.identifier,
                            intentToRetain = intentToRetain
                        )
                    )
                }
            }
            VerificationUtil.generateDcRequestMdoc(
                exchangeProtocols = protocol.exchangeProtocolNames,
                docType = request.mdocRequest!!.docType,
                claims = claims,
                nonce = nonce,
                origin = origin,
                clientId = clientId,
                responseEncryptionKey = responseEncryptionKey.publicKey,
                readerAuthenticationKey = readerKey,
                readerAuthenticationCertChain = readerCertChain,
                zkSystemSpecs = if (request.mdocRequest!!.useZkp) {
                    zkSystemRepository.getAllZkSystemSpecs()
                } else {
                    emptyList()
                }
            )
        }

        CredentialFormat.IETF_SDJWT -> {
            val claims = request.jsonRequest!!.claimsToRequest.map { documentAttribute ->
                val path = mutableListOf<JsonElement>()
                documentAttribute.parentAttribute?.let {
                    path.add(JsonPrimitive(it.identifier))
                }
                path.add(JsonPrimitive(documentAttribute.identifier))
                JsonRequestedClaim(
                    claimPath = JsonArray(path),
                )
            }
            VerificationUtil.generateDcRequestSdJwt(
                exchangeProtocols = protocol.exchangeProtocolNames,
                vct = listOf(request.jsonRequest!!.vct),
                claims = claims,
                nonce = nonce,
                origin = origin,
                clientId = clientId,
                responseEncryptionKey = responseEncryptionKey.publicKey,
                readerAuthenticationKey = readerKey,
                readerAuthenticationCertChain = readerCertChain,
            )
        }
    }

    Logger.i(TAG, "clientId: $clientId")
    Logger.iJson(TAG, "Request", dcRequestObject)
    val dcResponseObject = getCredential(dcRequestObject)
    Logger.iJson(TAG, "Response", dcResponseObject)

    val dcResponse = VerificationUtil.decryptDcResponse(
        response = dcResponseObject,
        nonce = nonce,
        origin = origin,
        responseEncryptionKey = responseEncryptionKey,
    )
    when (dcResponse) {
        is MdocApiDcResponse -> {
            showResponse(null, dcResponse.deviceResponse, dcResponse.sessionTranscript, nonce)
        }
        is OpenID4VPDcResponse -> {
            showResponse(dcResponse.vpToken, null, dcResponse.sessionTranscript, nonce)
        }
    }
}

private suspend fun doDcRequestFlowNfcOver18013(
    settingsModel: TestAppSettingsModel,
    appReaderKey: EcPrivateKey,
    appReaderCertChain: X509CertChain,
    request: DocumentCannedRequest,
    protocol: RequestProtocol,
    format: CredentialFormat,
    zkSystemRepository: ZkSystemRepository,
    showResponse: (vpToken: JsonObject?, deviceResponse: DataItem?, sessionTranscript: DataItem, nonce: ByteString?) -> Unit,
    showToast: (String) -> Unit
) {
    val negotiatedHandoverConnectionMethods = mutableListOf<MdocConnectionMethod>()
    val bleUuid = UUID.randomUUID()
    if (settingsModel.readerBleCentralClientModeEnabled.value) {
        negotiatedHandoverConnectionMethods.add(
            MdocConnectionMethodBle(
                supportsPeripheralServerMode = false,
                supportsCentralClientMode = true,
                peripheralServerModeUuid = null,
                centralClientModeUuid = bleUuid,
            )
        )
    }
    if (settingsModel.readerBlePeripheralServerModeEnabled.value) {
        negotiatedHandoverConnectionMethods.add(
            MdocConnectionMethodBle(
                supportsPeripheralServerMode = true,
                supportsCentralClientMode = false,
                peripheralServerModeUuid = bleUuid,
                centralClientModeUuid = null,
            )
        )
    }
    if (settingsModel.readerNfcDataTransferEnabled.value) {
        negotiatedHandoverConnectionMethods.add(
            MdocConnectionMethodNfc(
                commandDataFieldMaxLength = 0xffff,
                responseDataFieldMaxLength = 0x10000
            )
        )
    }
    if (!scanNfcMdocReader(
            message = "Hold near credential holder's phone.",
            options = MdocTransportOptions(
                bleUseL2CAP = settingsModel.readerBleL2CapEnabled.value
            ),
            selectConnectionMethod = { connectionMethods ->
                showToast("Auto-selected first from $connectionMethods")
                connectionMethods[0]
            },
            negotiatedHandoverConnectionMethods = negotiatedHandoverConnectionMethods,
            onHandover = { transport, encodedDeviceEngagement, handover, updateMessage ->
                Logger.iCbor(TAG, "DeviceEngagement", encodedDeviceEngagement.toByteArray())
                val deviceEngagement = DeviceEngagement.fromDataItem(Cbor.decode(encodedDeviceEngagement.toByteArray()))
                val dcProtocolsSupported = deviceEngagement.capabilities[Capability.DC_API_SUPPORT]?.asArray?.map { it.asTstr }
                if (dcProtocolsSupported == null) {
                    showToast("Wallet doesn't have DC API capability")
                    transport.close()
                }
                if (dcProtocolsSupported!!.intersect(protocol.exchangeProtocolNames).isEmpty()) {
                    showToast("No overlap between supported protocols ($dcProtocolsSupported) and requested protocols" +
                            " (${protocol.exchangeProtocolNames})")
                    transport.close()
                }

                val eReaderKey = Crypto.createEcPrivateKey(deviceEngagement.eDeviceKey.curve)
                val encodedEReaderKey = Cbor.encode(eReaderKey.publicKey.toCoseKey().toDataItem())
                val sessionTranscript = buildCborArray {
                    add(Tagged(Tagged.ENCODED_CBOR, Bstr(encodedDeviceEngagement.toByteArray())))
                    add(Tagged(Tagged.ENCODED_CBOR, Bstr(encodedEReaderKey)))
                    add(handover)
                }
                val encodedSessionTranscript = Cbor.encode(sessionTranscript)
                val origin = "iso-18013-5://${Crypto.digest(Algorithm.SHA256, encodedSessionTranscript).toBase64Url()}"

                doDcRequestFlow(
                    origin = origin,
                    appReaderKey = appReaderKey,
                    appReaderCertChain = appReaderCertChain,
                    request = request,
                    protocol = protocol,
                    format = format,
                    zkSystemRepository = zkSystemRepository,
                    showResponse = showResponse,
                    getCredential = { request ->
                        doDcFlowOver18013(
                            request = request,
                            transport = transport,
                            eReaderKey = eReaderKey,
                            encodedSessionTranscript = encodedSessionTranscript,
                            deviceEngagement = deviceEngagement,
                            showToast = showToast
                        )
                    }
                )
                transport.close()
            }
        )
    ) {
        // User canceled dialog
    }
}

private suspend fun doDcFlowOver18013(
    request: JsonObject,
    transport: MdocTransport,
    eReaderKey: EcPrivateKey,
    encodedSessionTranscript: ByteArray,
    deviceEngagement: DeviceEngagement,
    showToast: (String) -> Unit
): JsonObject {
    val sessionEncryption = SessionEncryption(
        role = MdocRole.MDOC_READER,
        eSelfKey = eReaderKey,
        remotePublicKey = deviceEngagement.eDeviceKey,
        encodedSessionTranscript = encodedSessionTranscript,
        selectDcApi = true
    )
    transport.open(deviceEngagement.eDeviceKey)
    transport.sendMessage(
        sessionEncryption.encryptMessage(
            messagePlaintext = Json.encodeToString(request).toByteArray(),
            statusCode = null
        )
    )
    val sessionData = transport.waitForMessage()
    if (sessionData.isEmpty()) {
        showToast("Received transport-specific session termination message from holder")
        transport.close()
        throw IllegalStateException("Received transport-specific session termination message from holder")
    }
    val (message, status) = sessionEncryption.decryptMessage(sessionData)
    Logger.i(TAG, "Holder sent ${message?.size} bytes status $status")
    if (message == null) {
        transport.close()
        throw IllegalStateException("Did not receive a response from the holder")
    }
    if (status == Constants.SESSION_DATA_STATUS_SESSION_TERMINATION) {
        showToast("Received session termination message from holder")
        transport.close()
    } else {
        transport.sendMessage(SessionEncryption.encodeStatus(Constants.SESSION_DATA_STATUS_SESSION_TERMINATION))
        transport.close()
    }
    return Json.decodeFromString<JsonObject>(message.decodeToString())
}

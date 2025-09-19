package org.multipaz.mdoc.engagement

/**
 * Capabilities conveyed during the engagement phase.
 *
 * @param identifier the numerical identifier of the capability, as defined by ISO 18013-5.
 */
enum class Capability(
    val identifier: Int,
) {
    HANDOVER_SESSION_ESTABLISHMENT_SUPPORT(2),
    READER_AUTH_ALL_SUPPORT(3),
    EXTENDED_REQUEST_SUPPORT(4),

    // Support for DC API over 18013-5 Session Encryption.
    //
    //   ; List of W3C DC API protocols supported by the wallet.
    //   DcApiSupport = [ DcProtocol ]
    //
    //   ; e.g. "openid4vp", "openid4vp-v1-signed", "openid4vp-v1-unsigned", "org-iso-mdoc"
    //   DcProtocol = tstr
    //
    // If a wallet advertises DcApiSupport as a capability they signal that they support
    // using another protocol than DeviceRequest / DeviceResponse as the payloads sent
    // back and forth in SessionData / SessionEstablishment.
    //
    // If a reader opts to use the DC API instead of the usual DeviceRequest / DeviceResponse
    // mechanism must indicate this in the SessionEstablishment message by setting the
    // key `dcApiSelected` to true in the map for this message.
    //
    // The origin to be used when using this protocol is defined as
    //
    //  iso-18013-5://<sha256-of-encoded-session-transcript>
    //
    // NOTE: Identifiers are marked in 18013-5 Second Edition draft as RFU meaning
    //   that only SC17 WG10 can add identifiers. As such, this should never be merged
    //   to the main Multipaz branch or be used in production. It's made available only for
    //   the purpose of discussion.
    //
    DC_API_SUPPORT(0x44437631)  // "DCv1"
}

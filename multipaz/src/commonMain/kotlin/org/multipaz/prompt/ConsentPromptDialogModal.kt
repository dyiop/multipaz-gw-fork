package org.multipaz.prompt

import org.multipaz.document.Document
import org.multipaz.presentment.CredentialPresentmentData
import org.multipaz.presentment.CredentialPresentmentSelection
import org.multipaz.request.Requester
import org.multipaz.trustmanagement.TrustMetadata
import org.multipaz.trustmanagement.TrustPoint

/**
 * [PromptDialogModel] to display a consent dialog.
 *
 * See [PromptModel.requestConsent] as a thin wrapper for this class.
 */
class ConsentPromptDialogModal():
    PromptDialogModel<ConsentPromptDialogModal.Parameters, CredentialPresentmentSelection>() {

    override val dialogType: PromptDialogModel.DialogType<ConsentPromptDialogModal>
        get() = DialogType

    object DialogType : PromptDialogModel.DialogType<ConsentPromptDialogModal>

    /**
     * Parameters used for the consent dialog.
     *
     * @property requester the relying party which is requesting the data.
     * @property trustPoint if the requester is in a trust-list, the [TrustPoint] indicating this
     * @property credentialPresentmentData the combinations of credentials and claims that the user can select.
     * @property preselectedDocuments the list of documents the user may have preselected earlier (for
     *   example an OS-provided credential picker like Android's Credential Manager) or the empty list
     *   if the user didn't preselect.
     * @property dynamicMetadataResolver a function which can be used to calculate [TrustMetadata] on a
     *   per-request basis, which may used in credential prompts.
     */
    data class Parameters(
        val requester: Requester,
        val trustPoint: TrustPoint?,
        val credentialPresentmentData: CredentialPresentmentData,
        val preselectedDocuments: List<Document>,
        val dynamicMetadataResolver: (requester: Requester) -> TrustMetadata?,
    )
}
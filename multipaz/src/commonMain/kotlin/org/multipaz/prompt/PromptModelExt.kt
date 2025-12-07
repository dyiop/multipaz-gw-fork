package org.multipaz.prompt

import org.multipaz.document.Document
import org.multipaz.presentment.CredentialPresentmentData
import org.multipaz.presentment.CredentialPresentmentSelection
import org.multipaz.request.Requester
import org.multipaz.securearea.PassphraseConstraints
import org.multipaz.trustmanagement.TrustMetadata
import org.multipaz.trustmanagement.TrustPoint

/**
 * Prompts user for authentication through a passphrase.
 *
 * If [passphraseEvaluator] is not `null`, it is called every time the user inputs a passphrase with
 * the user input as a parameter. It should return [PassphraseEvaluation.OK] to
 * indicate the passphrase is correct otherwise [PassphraseEvaluation.TryAgain] with optional number
 * of remaining attempts, or [PassphraseEvaluation.TooManyAttempts].
 *
 * To dismiss the prompt programmatically, cancel the job the coroutine was launched in.
 *
 * To obtain [title] and [subtitle] back-end code generally should create a [Reason] object and
 * use [PromptModel.toHumanReadable] to convert it to human-readable form. This gives
 * application code a chance to customize user-facing messages.
 *
 * @param title the title for the passphrase prompt.
 * @param subtitle the subtitle for the passphrase prompt.
 * @param passphraseConstraints the [PassphraseConstraints] for the passphrase.
 * @param passphraseEvaluator an optional function to evaluate the passphrase and give the user feedback.
 * @return the passphrase entered by the user.
 * @throws IllegalStateException if [PromptModel] does not have [PassphrasePromptDialogModel] registered
 * @throws PromptDismissedException if user dismissed passphrase prompt dialog.
 * @throws PromptModelNotAvailableException if `coroutineContext` does not have [PromptModel].
 * @throws PromptUiNotAvailableException if the UI layer hasn't bound any UI for [PromptModel].
 */
suspend fun PromptModel.requestPassphrase(
    title: String,
    subtitle: String,
    passphraseConstraints: PassphraseConstraints,
    passphraseEvaluator: (suspend (enteredPassphrase: String) -> PassphraseEvaluation)?
): String {
    return getDialogModel(PassphrasePromptDialogModel.DialogType).displayPrompt(
        PassphrasePromptDialogModel.PassphraseRequest(
            title,
            subtitle,
            passphraseConstraints,
            passphraseEvaluator
        )
    )
}

/**
 * Prompts the user for consent to release a set of credentials with selectively disclosable
 * claims to a relying party.
 *
 * @param requester the relying party which is requesting the data.
 * @param trustPoint if the requester is in a trust-list, the [TrustPoint] indicating this
 * @param credentialPresentmentData the combinatinos of credentials and claims that the user can select.
 * @param preselectedDocuments the list of documents the user may have preselected earlier (for
 *   example an OS-provided credential picker like Android's Credential Manager) or the empty list
 *   if the user didn't preselect.
 * @param dynamicMetadataResolver a function which can be used to calculate [TrustMetadata] on a
 *   per-request basis, which may used in credential prompts.
 * @return the credentials that the user consented to release.
 * @throws IllegalStateException if [PromptModel] does not have [ConsentPromptDialogModal] registered
 * @throws PromptDismissedException if user dismissed consent dialog.
 * @throws PromptModelNotAvailableException if `coroutineContext` does not have [PromptModel].
 * @throws PromptUiNotAvailableException if the UI layer hasn't bound any UI for [PromptModel].
 */
suspend fun PromptModel.requestConsent(
    requester: Requester,
    trustPoint: TrustPoint?,
    credentialPresentmentData: CredentialPresentmentData,
    preselectedDocuments: List<Document>,
    dynamicMetadataResolver: (requester: Requester) -> TrustMetadata?
): CredentialPresentmentSelection {
    return getDialogModel(ConsentPromptDialogModal.DialogType).displayPrompt(
        ConsentPromptDialogModal.Parameters(
            requester,
            trustPoint,
            credentialPresentmentData,
            preselectedDocuments,
            dynamicMetadataResolver
        )
    )
}
package org.multipaz.compose.prompt

import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.painter.Painter
import coil3.ImageLoader
import org.multipaz.prompt.AndroidPromptModel
import org.multipaz.prompt.BiometricPromptDialogModel
import org.multipaz.prompt.ConsentPromptDialogModal
import org.multipaz.prompt.PassphrasePromptDialogModel
import org.multipaz.prompt.PromptModel
import org.multipaz.prompt.ScanNfcPromptDialogModel

@Composable
actual fun PromptDialogs(
    promptModel: PromptModel,
    imageLoader: ImageLoader,
    appName: String?,
    appIconPainter: Painter?,
    showCancelAsBack: Boolean,
) {
    val model = promptModel as AndroidPromptModel
    ScanNfcTagPromptDialog(model.getDialogModel(ScanNfcPromptDialogModel.DialogType))
    BiometricPromptDialog(model.getDialogModel(BiometricPromptDialogModel.DialogType))
    PassphrasePromptDialog(model.getDialogModel(PassphrasePromptDialogModel.DialogType))
    ConsentPromptDialog(
        model = model.getDialogModel(ConsentPromptDialogModal.DialogType),
        imageLoader = imageLoader,
        appName = appName,
        appIconPainter = appIconPainter,
        showCancelAsBack = showCancelAsBack,
    )
}
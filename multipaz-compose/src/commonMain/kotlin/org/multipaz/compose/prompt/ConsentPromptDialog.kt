package org.multipaz.compose.prompt

import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.graphics.painter.Painter
import coil3.ImageLoader
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import org.multipaz.compose.presentment.CredentialPresentmentModalBottomSheet
import org.multipaz.presentment.CredentialPresentmentSelection
import org.multipaz.prompt.ConsentPromptDialogModal
import org.multipaz.prompt.PromptDialogModel
import org.multipaz.prompt.PromptDismissedException

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConsentPromptDialog(
    model: PromptDialogModel<ConsentPromptDialogModal.Parameters, CredentialPresentmentSelection>,
    imageLoader: ImageLoader,
    appName: String?,
    appIconPainter: Painter?,
    showCancelAsBack: Boolean,
) {
    val dialogState = model.dialogState.collectAsState(PromptDialogModel.NoDialogState())
    val coroutineScope = rememberCoroutineScope()
    val showKeyboard = MutableStateFlow<Boolean>(false)
    val sheetState = rememberModalBottomSheetState(
        skipPartiallyExpanded = true,
        confirmValueChange = { value ->
            showKeyboard.value = true
            true
        }
    )
    val dialogStateValue = dialogState.value
    if (dialogStateValue is PromptDialogModel.DialogShownState) {
        CredentialPresentmentModalBottomSheet(
            sheetState = sheetState,
            requester = dialogStateValue.parameters.requester,
            trustPoint = dialogStateValue.parameters.trustPoint,
            credentialPresentmentData = dialogStateValue.parameters.credentialPresentmentData,
            preselectedDocuments = dialogStateValue.parameters.preselectedDocuments,
            imageLoader = imageLoader,
            dynamicMetadataResolver = dialogStateValue.parameters.dynamicMetadataResolver,
            appName = appName,
            appIconPainter = appIconPainter,
            onConfirm = { selection ->
                coroutineScope.launch {
                    dialogStateValue.resultChannel.send(selection)
                }
            },
            onCancel = {
                coroutineScope.launch {
                    dialogStateValue.resultChannel.close(PromptDismissedException())
                }
            },
            showCancelAsBack = showCancelAsBack
        )
    }
}

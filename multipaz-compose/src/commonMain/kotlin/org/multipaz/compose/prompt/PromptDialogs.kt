package org.multipaz.compose.prompt

import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.painter.Painter
import coil3.ImageLoader
import org.multipaz.prompt.PromptModel
import org.multipaz.request.Requester
import org.multipaz.trustmanagement.TrustMetadata

/**
 * A composable which shows dialogs on demand.
 *
 * @param promptModel the [PromptModel] this should show dialogs for.
 */
@Composable
expect fun PromptDialogs(
    promptModel: PromptModel,
    imageLoader: ImageLoader,
    appName: String? = null,
    appIconPainter: Painter? = null,
    showCancelAsBack: Boolean = false
)

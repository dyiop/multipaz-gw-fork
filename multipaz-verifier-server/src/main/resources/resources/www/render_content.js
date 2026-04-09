function renderContent(div, label, data, depth) {
    if (Array.isArray(data)) {
        depth++;
        const container = document.createElement('div');
        container.setAttribute("class", "cred_data nest" + depth);
        div.appendChild(container);
        if (label) {
            const title = document.createElement("h4");
            title.textContent = label;
            container.appendChild(title);
        }
        for (let item of data) {
            renderContent(container, "", item, depth);
        }
    } else if (typeof data == 'object') {
        depth++;
        const container = document.createElement('div');
        container.setAttribute("class", "cred_data nest" + depth);
        div.appendChild(container);
        if (label) {
            const title = document.createElement("h4");
            title.textContent = label;
            container.appendChild(title);
        }
        for (let l in data) {
            renderContent(container, l, data[l], depth);
        }
    } else if (isImageData(data)) {
        const container = document.createElement('div');
        container.setAttribute("class", "image nest" + depth);
        div.appendChild(container);
        if (label) {
            const title = document.createElement("h4");
            title.textContent = label;
            container.appendChild(title);
        }
        const image = document.createElement("img");
        image.src = toDataUrl(data);
        container.appendChild(image);
    } else {
        const container = document.createElement('p');
        container.setAttribute("class", "simple");
        div.appendChild(container);
        if (label) {
            const title = document.createElement("b");
            title.textContent = label + ": ";
            container.appendChild(title);
        }
        container.appendChild(document.createTextNode(data + ""));
    }
}

// Checks if this looks like base64-encode image (JPEG or PNG) data
function isImageData(data) {
    return typeof data == 'string' && data.length >= 200 && data.length % 4 != 1 &&
        data.match(/^(_9j_|iVBORw0)[0-9a-zA-Z_-]*$/);
}

const jpegUrlPrefix = "data:image/jpeg;base64,";
const pngUrlPrefix = "data:image/png;base64,";

function toDataUrl(data) {
    const prefix = data.startsWith("_9j_") ? jpegUrlPrefix : pngUrlPrefix;
    const padLen = (-data.length) & 3;
    // Data URL uses Base64 encoding, NOT Base64Url encoding (that would have been too easy).
    return prefix + data.replaceAll('_', '/').replaceAll('-', '+') + "==".substring(0, padLen);
}

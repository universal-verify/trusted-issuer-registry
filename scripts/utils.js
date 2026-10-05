export const base64ToUint8Array = (base64) => {
    if(typeof Buffer === 'function') {
        return new Uint8Array(Buffer.from(base64, 'base64'));
    }

    if(typeof atob !== 'function') {
        throw new Error('No base64 decoder available in this environment');
    }

    const raw = atob(base64);
    const bytes = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) {
        bytes[i] = raw.charCodeAt(i);
    }
    return bytes;
};

export const uint8ArrayToBase64 = (bytes) => {
    if(typeof Buffer === 'function') {
        return Buffer.from(bytes).toString('base64');
    }

    if(typeof btoa !== 'function') {
        throw new Error('No base64 encoder available in this environment');
    }

    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
};

export const bufferToBase64Url = (bufferSource) => {
    const bytes = bufferSource instanceof Uint8Array
        ? bufferSource
        : ArrayBuffer.isView(bufferSource)
            ? new Uint8Array(bufferSource.buffer, bufferSource.byteOffset, bufferSource.byteLength)
            : new Uint8Array(bufferSource);

    return uint8ArrayToBase64(bytes)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
};

export const padOrTrimUint8Array = (bytes, length) => {
    if (bytes.length === length) return bytes;
    if (bytes.length > length) return bytes.slice(bytes.length - length);

    const padded = new Uint8Array(length);
    padded.set(bytes, length - bytes.length);
    return padded;
};

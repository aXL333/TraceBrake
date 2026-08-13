// Persisted extension settings (chrome.storage.local — extension-scoped, not readable by web pages or other
// extensions). The token + pairedOrigin are written by the pairing flow; host/port default to TraceBrake's loopback.
const DEFAULTS = {
    host: '127.0.0.1',
    port: 54321,
    token: '',
    pairedOrigin: '',
    harnessId: 'browser-extension',
};

export async function loadSettings() {
    const s = await chrome.storage.local.get(DEFAULTS);
    return { ...DEFAULTS, ...s };
}

export async function saveSettings(patch) {
    await chrome.storage.local.set(patch);
}

export function onSettingsChanged(cb) {
    chrome.storage.onChanged.addListener((changes, area) => {
        if (area === 'local') cb(changes);
    });
}

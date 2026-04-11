/**
 * Config Module - Handles settings, rules, and blocklists
 */
import * as api from './api.js';
import * as helpers from './ui_helpers.js';

export async function saveConfig(currentConfig) {
    try {
        await api.apiFetch(api.endpoints.config, {
            method: 'POST',
            body: JSON.stringify(currentConfig)
        });
        return true;
    } catch (e) {
        helpers.showAlert('Failed to save config: ' + e.message);
        return false;
    }
}

export function filterConfigByPreset(config, preset) {
    // Logic for presets
}

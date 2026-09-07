/**
 * Settings Form & Save Logic
 */
import * as api from '../services/api.js';
import * as helpers from './helpers.js';
import { state, getEl } from '../core/state.js';
import { renderConfig } from './renderers.js';

export function setSettingsDirty(dirty) {
    state.isDirty = dirty;
    const footer = document.querySelector('.settings-save-footer');
    const status = getEl('settings-save-status');
    if (!footer) return;

    if (dirty) {
        footer.classList.add('visible');
        if (status) {
            status.innerHTML = `<strong>UNSAVED</strong> Configuration changed. Please save to apply.`;
            status.classList.add('dirty');
        }
    } else {
        footer.classList.remove('visible');
        if (status) {
            status.classList.remove('dirty');
            status.innerHTML = `All changes must be saved. Reboot might be required for core changes.`;
        }
    }
}

export async function saveConfig(fetchConfig) {
    const saveBtn = document.querySelector('#settings-form button[type="submit"]');
    helpers.setBtnLoading(saveBtn, true, 'Saving...');

    const upstreams = getEl('upstreams-input')?.value.split(',').map(s => s.trim()).filter(Boolean);
    const dotUpstreams = getEl('dot-upstreams-input')?.value.split(',').map(s => s.trim()).filter(Boolean);
    
    const newConfig = {
        ...state.currentConfig,
        upstreams,
        upstream_dot: dotUpstreams,
        prefer_encrypted: getEl('prefer-encrypted-check')?.checked,
        doh3_enabled: getEl('doh3-enabled-check')?.checked,
        ech_optimization_enabled: getEl('ech-optimization-check')?.checked,
        admin_domain: getEl('admin-domain-input')?.value.trim() || state.currentConfig.admin_domain,
        block_page_ip: getEl('block-ip-input')?.value.trim() || state.currentConfig.block_page_ip,
        debug_mode: getEl('debug-mode-check')?.checked,
        sign_mobileconfig: getEl('sign-mobileconfig-check')?.checked,
        abuse_detection_enabled: getEl('abuse-detection-check')?.checked,
        dnssec_enabled: getEl('dnssec-check')?.checked,
        serve_stale: getEl('serve-stale-check')?.checked,
        use_fastest_upstream: getEl('smart-upstream-check')?.checked,
        smart_selection_policy: getEl('smart-selection-policy-input')?.value || 'fastest',
        latency_test_interval: parseInt(getEl('latency-interval-input')?.value) || 10,
        diagnostics_refresh_interval: parseInt(getEl('diagnostics-interval-input')?.value) || 600,
        retention_days: parseInt(getEl('retention-input')?.value) || 30,
        doh_rate_limit: parseInt(getEl('doh-rate-limit-input')?.value) || 30,
        rate_limit_rate: parseInt(getEl('rate-limit-rate-input')?.value) !== undefined ? parseInt(getEl('rate-limit-rate-input')?.value) : 100,
        rate_limit_burst: parseInt(getEl('rate-limit-burst-input')?.value) !== undefined ? parseInt(getEl('rate-limit-burst-input')?.value) : 250,
        abuse_dga_threshold: parseFloat(getEl('abuse-dga-threshold-input')?.value) || 3.8,
        abuse_dga_min_len: parseInt(getEl('abuse-dga-min-len-input')?.value) || 8,
        malicious_ip_blocking_enabled: getEl('malicious-check')?.checked,
        malicious_ip_interval: parseInt(getEl('malicious-interval-input')?.value) || 8,
        verify_upstream_tls: getEl('verify-upstream-tls-check')?.checked,
        mcp_server_enabled: getEl('mcp-server-enabled-check')?.checked,
        server_country: getEl('manual-server-country-select')?.value || '',
        update_channel: getEl('update-channel')?.value || 'stable',
        auto_update_enabled: getEl('auto-update-enabled')?.checked,
        auto_update_hour: parseInt(getEl('auto-update-hour')?.value) !== undefined ? parseInt(getEl('auto-update-hour')?.value) : 3,
        anonymize_client_ips: getEl('anonymize-client-ips-check')?.checked,
        dns_rebinding_protection: getEl('dns-rebinding-protection-check')?.checked,
        strip_ecs: getEl('strip-ecs-check')?.checked
    };

    try {
        await api.apiFetch(api.endpoints.config, {
            method: 'POST',
            body: JSON.stringify(newConfig)
        });
        state.currentConfig = newConfig;
        helpers.showToast('Configuration saved successfully!');
        setSettingsDirty(false);
        renderConfig(state.currentConfig);
    } catch (e) {
        helpers.showAlert('Failed to save configuration: ' + e.message);
    } finally {
        helpers.setBtnLoading(saveBtn, false);
    }
}

export function initSettingsEvents(fetchConfig) {
    let activeSettingsTab = 'all';

    const filterSettings = () => {
        const query = getEl('settings-search-input')?.value.toLowerCase().trim() || '';
        const sections = document.querySelectorAll('#settings-form .settings-section, #settings .settings-section');

        sections.forEach(section => {
            const category = section.getAttribute('data-category');
            const matchesTab = (activeSettingsTab === 'all' || category === activeSettingsTab || query !== '');
            
            if (!matchesTab) {
                section.style.display = 'none';
                return;
            }

            let sectionHasMatch = false;
            const groups = section.querySelectorAll('.form-group, .checkbox-group, .table-header-actions, .card.overflow-x');
            const h2 = section.querySelector('h2');
            const titleMatch = h2 && h2.textContent.toLowerCase().includes(query);

            if (titleMatch && query !== '') {
                sectionHasMatch = true;
                groups.forEach(g => g.style.display = '');
            } else {
                groups.forEach(group => {
                    const text = group.textContent.toLowerCase();
                    const isMatch = (query === '' || text.includes(query));
                    group.style.display = isMatch ? '' : 'none';
                    if (isMatch) sectionHasMatch = true;
                });
            }

            section.style.display = sectionHasMatch ? '' : 'none';
        });
    };

    const tabNav = getEl('settings-tabs-nav');
    tabNav?.querySelectorAll('.settings-tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            tabNav.querySelectorAll('.settings-tab-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            activeSettingsTab = btn.getAttribute('data-tab') || 'all';

            const searchInput = getEl('settings-search-input');
            if (searchInput && searchInput.value) {
                searchInput.value = '';
            }
            filterSettings();
        });
    });

    const settingsSearchInput = getEl('settings-search-input');
    settingsSearchInput?.addEventListener('input', () => {
        filterSettings();
    });

    const settingsPresetSelector = getEl('settings-preset-selector');
    settingsPresetSelector?.addEventListener('change', (e) => {
        const val = e.target.value;
        if (!val) return;
        
        const host = window.location.hostname || 'shielddns.local';
        
        if (val === 'shielddns') {
            state.currentConfig.upstreams = ["86.54.11.100", "1.1.1.1", "9.9.9.9", "8.8.8.8", "1.0.0.1"];
            state.currentConfig.upstream_dot = ["unfiltered.joindns4.eu", "dns.quad9.net", "one.one.one.one", "dns.google"];
            state.currentConfig.prefer_encrypted = true;
            state.currentConfig.admin_domain = host;
            state.currentConfig.block_page_ip = host;
            state.currentConfig.sign_mobileconfig = true;
            state.currentConfig.abuse_detection_enabled = true;
            state.currentConfig.dnssec_enabled = true;
            state.currentConfig.serve_stale = true;
            state.currentConfig.use_fastest_upstream = true;
            state.currentConfig.smart_selection_policy = "fastest";
            state.currentConfig.latency_test_interval = 10;
            state.currentConfig.diagnostics_refresh_interval = 30;
            state.currentConfig.retention_days = 30;
            state.currentConfig.malicious_ip_blocking_enabled = true;
            state.currentConfig.malicious_ip_interval = 8;
            state.currentConfig.verify_upstream_tls = true;
            state.currentConfig.blocked_countries = [];
        } else if (val === 'minimal') {
            state.currentConfig.upstreams = ["86.54.11.100", "1.1.1.1", "9.9.9.9", "8.8.8.8", "1.0.0.1"];
            state.currentConfig.upstream_dot = ["unfiltered.joindns4.eu", "dns.quad9.net", "one.one.one.one", "dns.google"];
            state.currentConfig.prefer_encrypted = true;
            state.currentConfig.admin_domain = host;
            state.currentConfig.block_page_ip = host;
            state.currentConfig.sign_mobileconfig = false;
            state.currentConfig.abuse_detection_enabled = false;
            state.currentConfig.dnssec_enabled = true;
            state.currentConfig.serve_stale = true;
            state.currentConfig.use_fastest_upstream = true;
            state.currentConfig.smart_selection_policy = "fastest";
            state.currentConfig.latency_test_interval = 10;
            state.currentConfig.diagnostics_refresh_interval = 60;
            state.currentConfig.retention_days = 7;
            state.currentConfig.malicious_ip_blocking_enabled = false;
            state.currentConfig.malicious_ip_interval = 24;
            state.currentConfig.verify_upstream_tls = true;
            state.currentConfig.blocked_countries = [];
        } else if (val === 'maxperf') {
            state.currentConfig.upstreams = ["86.54.11.100", "1.1.1.1", "9.9.9.9", "8.8.8.8", "1.0.0.1"];
            state.currentConfig.upstream_dot = ["unfiltered.joindns4.eu", "dns.quad9.net", "one.one.one.one", "dns.google"];
            state.currentConfig.prefer_encrypted = true;
            state.currentConfig.admin_domain = host;
            state.currentConfig.block_page_ip = host;
            state.currentConfig.sign_mobileconfig = true;
            state.currentConfig.abuse_detection_enabled = true;
            state.currentConfig.dnssec_enabled = true;
            state.currentConfig.serve_stale = true;
            state.currentConfig.use_fastest_upstream = true;
            state.currentConfig.smart_selection_policy = "fastest";
            state.currentConfig.latency_test_interval = 5;
            state.currentConfig.diagnostics_refresh_interval = 300;
            state.currentConfig.retention_days = 14;
            state.currentConfig.malicious_ip_blocking_enabled = true;
            state.currentConfig.malicious_ip_interval = 12;
            state.currentConfig.verify_upstream_tls = true;
            state.currentConfig.blocked_countries = [];
        } else if (val === 'faserf') {
            state.currentConfig.upstreams = ["86.54.11.100", "9.9.9.9", "1.1.1.1", "8.8.8.8", "1.0.0.1"];
            state.currentConfig.upstream_dot = ["unfiltered.joindns4.eu", "dns.quad9.net", "one.one.one.one", "dns.google"];
            state.currentConfig.prefer_encrypted = true;
            state.currentConfig.admin_domain = "dns.fabiseitz.de";
            state.currentConfig.block_page_ip = "89.168.74.120";
            state.currentConfig.sign_mobileconfig = true;
            state.currentConfig.abuse_detection_enabled = true;
            state.currentConfig.dnssec_enabled = false;
            state.currentConfig.serve_stale = true;
            state.currentConfig.use_fastest_upstream = true;
            state.currentConfig.smart_selection_policy = "fastest";
            state.currentConfig.latency_test_interval = 15;
            state.currentConfig.diagnostics_refresh_interval = 300;
            state.currentConfig.retention_days = 90;
            state.currentConfig.malicious_ip_blocking_enabled = true;
            state.currentConfig.malicious_ip_interval = 12;
            state.currentConfig.verify_upstream_tls = true;
            state.currentConfig.blocked_countries = ["CN", "RU", "IR", "KP", "VN", "BR", "BY", "IQ", "UA"];
        }
        
        renderConfig(state.currentConfig);
        setSettingsDirty(true);
        helpers.showToast(`Loaded preset: ${val}`);
        settingsPresetSelector.value = "";
    });

    const settingsForm = getEl('settings-form');
    settingsForm?.addEventListener('submit', async (e) => {
        e.preventDefault();
        saveConfig(fetchConfig);
    });

    settingsForm?.addEventListener('input', () => setSettingsDirty(true));
    settingsForm?.addEventListener('change', () => setSettingsDirty(true));

    const settingsContainer = getEl('settings');
    if (settingsContainer) {
        ['input', 'change'].forEach(evt => {
            settingsContainer.addEventListener(evt, (e) => {
                if (e.target.id === 'settings-search-input') return;
                setSettingsDirty(true);
            });
        });
        settingsContainer.addEventListener('reset', () => setSettingsDirty(false));
    }

    window.setSettingsDirty = setSettingsDirty;
}

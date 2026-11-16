/**
 * Guided Help Drawer & Visual DNS Packet Flow System
 * Provides plain-English explanations, practical examples, cautions, and inline SVG diagrams.
 */

export const HELP_TOPICS = {
    'how-it-works': {
        title: 'How ShieldDNS answers a question',
        term: 'DNS Resolution Pipeline',
        summary: 'Every device asks ShieldDNS where a domain lives; it answers from memory, local rules, a block, or an encrypted upstream resolver.',
        when: 'Read this first: every other setting adjusts one stage of this packet path.',
        example: 'Your Smart TV requests ads.example.com: it matches a blocklist, so ShieldDNS replies with 0.0.0.0 and the ad never loads.',
        caution: 'Devices only use ShieldDNS if your router or device DNS settings point to this server.',
        flowPath: 'upstream'
    },
    'explain': {
        title: 'See why a domain was allowed or blocked',
        term: 'Decision Attribution & Explain Engine',
        summary: 'Traces every rule layer—client policies, SafeSearch, custom lists, blocklists, and routing—to show exactly which rule won.',
        when: 'A website or app is unexpectedly blocked, or you want to verify why an ad slipped through.',
        example: 'Enter "api.tiktok.com" and your phone IP to confirm whether TikTok is blocked by a Service Preset or a HaGeZi list.',
        caution: 'Evaluating a name does not change any rules or cache entries.',
        flowPath: 'blocked'
    },
    'simulate': {
        title: 'Preview impact before saving a rule',
        term: '24h Historical Query Replay',
        summary: 'Replays a proposed block, allow, or service toggle against your last 24 hours of real network queries.',
        when: 'Before blocking a broad domain or enabling a strict list that might affect shared devices.',
        example: 'Simulate blocking "amazonaws.com" to discover it would interrupt 450 queries from your smart speakers and TV.',
        caution: 'Requires query logging to be enabled; only replays recorded queries within the lookback window.',
        flowPath: 'blocked'
    },
    'safesearch': {
        title: 'Filter explicit search & video results',
        term: 'SafeSearch CNAME / VIP Enforcement',
        summary: 'Redirects supported search engines and YouTube domains to each provider\'s official strict SafeSearch server IP.',
        when: 'On family networks or children\'s devices where adult search results and comments should be filtered automatically.',
        example: 'Enabling SafeSearch maps www.google.com and www.bing.com to their strict VIPs without needing browser extensions.',
        caution: 'YouTube Strict mode also hides comments and restricts many music/gaming videos; Moderate is softer.',
        flowPath: 'local'
    },
    'blocked-services': {
        title: 'Block entire apps or platforms in one click',
        term: 'Service Bundle Filtering',
        summary: 'Applies curated multi-domain rules for popular apps (TikTok, Steam, Roblox, Discord, Netflix) without finding external lists.',
        when: 'You want quick parental controls or distraction blocking across all devices.',
        example: 'Toggle "Roblox" and "TikTok" on during homework hours to block app APIs and CDNs simultaneously.',
        caution: 'Some platforms share CDNs with other apps; use Simulate Impact first if unsure.',
        flowPath: 'blocked'
    },
    'beaconing': {
        title: 'Spot automated heartbeats & malware chatter',
        term: 'Periodic Beaconing & DGA Detection',
        summary: 'Detects devices contacting the same domain on a steady timer (e.g., every 60s), high-entropy DGA names, or sudden block storms.',
        when: 'Review Diagnostics periodically to catch misbehaving IoT firmware or potential C2 beaconing.',
        example: 'An unnamed sensor querying an external domain every 60 seconds with 98% regularity appears as a Periodic Beacon.',
        caution: 'Legitimate NTP or smart-home heartbeats can look periodic; use Acknowledge or Mute for known safe devices.',
        flowPath: 'upstream'
    },
    'ai-guardian': {
        title: 'Let AI analyze suspicious domains',
        term: 'Omniroute / OpenAI Threat Triage',
        summary: 'Connects to your Omniroute or OpenAI-compatible model to classify unknown domains, assess simulation risk, and identify unknown devices.',
        when: 'You want semantic threat triage beyond static blocklists and regex heuristics.',
        example: 'Ask AI Guardian inside Explain Decision whether an unfamiliar telemetry domain is harmless analytics or phishing.',
        caution: 'Only domain names and anonymized telemetry are sent to your configured AI endpoint; set a confidence threshold >= 80% for auto-blocking.',
        flowPath: 'route'
    },
    'dnssec': {
        title: 'Verify DNS answers are authentic',
        term: 'DNSSEC Validation (RFC 4033-4035)',
        summary: 'Cryptographically checks upstream DNS signatures to block spoofed or tampered responses.',
        when: 'Recommended ON for standard internet privacy and integrity.',
        example: 'If an attacker spoofs an A record on an untrusted path, CoreDNS rejects the bogus signature with SERVFAIL.',
        caution: 'Misconfigured local or corporate internal zones without valid signatures may fail unless routed separately.',
        flowPath: 'upstream'
    }
};

export function renderFlowSVG(activePath = 'upstream', deviceLabel = 'Device', domainLabel = 'example.com') {
    const isActive = (p) => activePath === p;
    const stroke = (p) => isActive(p) ? '#6366f1' : 'rgba(148, 163, 184, 0.35)';
    const fill = (p) => isActive(p) ? 'rgba(99, 102, 241, 0.18)' : 'rgba(148, 163, 184, 0.08)';
    const esc = (s) => String(s || '').replace(/[<>&"']/g, c => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&#39;' }[c]));

    return `
    <svg class="explain-flow-svg" viewBox="0 0 640 130" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="DNS packet flow diagram">
        <defs>
            <marker id="flow-arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                <path d="M 0 1 L 10 5 L 0 9 z" fill="#6366f1"/>
            </marker>
        </defs>
        <!-- Client -->
        <rect x="10" y="42" width="120" height="46" rx="10" fill="rgba(59,130,246,0.14)" stroke="#3b82f6" stroke-width="1.5"/>
        <text x="70" y="61" text-anchor="middle" fill="currentColor" font-size="11" font-weight="600">${esc(deviceLabel.slice(0, 16))}</text>
        <text x="70" y="77" text-anchor="middle" fill="#94a3b8" font-size="9">${esc(domainLabel.slice(0, 18))}</text>

        <line x1="130" y1="65" x2="172" y2="65" stroke="#6366f1" stroke-width="2" marker-end="url(#flow-arrow)"/>

        <!-- ShieldDNS Policy Engine -->
        <rect x="176" y="38" width="140" height="54" rx="10" fill="rgba(99,102,241,0.14)" stroke="#6366f1" stroke-width="1.5"/>
        <text x="246" y="61" text-anchor="middle" fill="currentColor" font-size="11" font-weight="600">ShieldDNS Filter</text>
        <text x="246" y="78" text-anchor="middle" fill="#94a3b8" font-size="9">Rules • Lists • Cache</text>

        <!-- Branches -->
        <path d="M 316 50 C 350 50, 355 24, 396 24" fill="none" stroke="${stroke('blocked')}" stroke-width="${isActive('blocked') || isActive('refused') ? 2.5 : 1.5}"/>
        <path d="M 316 65 L 396 65" fill="none" stroke="${stroke('local')}" stroke-width="${isActive('local') || isActive('cache') ? 2.5 : 1.5}"/>
        <path d="M 316 80 C 350 80, 355 106, 396 106" fill="none" stroke="${stroke('upstream')}" stroke-width="${isActive('upstream') || isActive('route') ? 2.5 : 1.5}"/>

        <!-- Blocked Outcome -->
        <rect x="400" y="6" width="228" height="34" rx="8" fill="${isActive('blocked') || isActive('refused') ? 'rgba(239,68,68,0.18)' : fill('blocked')}" stroke="${isActive('blocked') || isActive('refused') ? '#ef4444' : stroke('blocked')}" stroke-width="1.5"/>
        <text x="514" y="27" text-anchor="middle" fill="currentColor" font-size="11" font-weight="${isActive('blocked') || isActive('refused') ? '700' : '500'}">Blocked / Sinkholed (0.0.0.0)</text>

        <!-- Local / SafeSearch Outcome -->
        <rect x="400" y="48" width="228" height="34" rx="8" fill="${isActive('local') || isActive('cache') ? 'rgba(16,185,129,0.18)' : fill('local')}" stroke="${isActive('local') || isActive('cache') ? '#10b981' : stroke('local')}" stroke-width="1.5"/>
        <text x="514" y="69" text-anchor="middle" fill="currentColor" font-size="11" font-weight="${isActive('local') || isActive('cache') ? '700' : '500'}">Local Answer / SafeSearch / Cache</text>

        <!-- Upstream Outcome -->
        <rect x="400" y="90" width="228" height="34" rx="8" fill="${fill('upstream')}" stroke="${isActive('route') ? '#f59e0b' : stroke('upstream')}" stroke-width="1.5"/>
        <text x="514" y="111" text-anchor="middle" fill="currentColor" font-size="11" font-weight="${isActive('upstream') || isActive('route') ? '700' : '500'}">${isActive('route') ? 'Custom / VPN Route' : 'Encrypted Upstream (DoT/DoH)'}</text>
    </svg>`;
}

export function openHelpTopic(topicId) {
    const topic = HELP_TOPICS[topicId] || HELP_TOPICS['how-it-works'];
    const drawer = document.getElementById('guided-help-drawer');
    if (!drawer) return;

    const setElText = (id, val) => {
        const el = document.getElementById(id);
        if (el) el.textContent = val || '';
    };

    setElText('help-drawer-title', topic.title);
    setElText('help-drawer-term', topic.term);
    setElText('help-drawer-summary', topic.summary);
    setElText('help-drawer-when', topic.when);
    setElText('help-drawer-example', topic.example);
    setElText('help-drawer-caution', topic.caution);

    const diagBox = document.getElementById('help-drawer-diagram');
    if (diagBox) {
        diagBox.innerHTML = renderFlowSVG(topic.flowPath, 'Home Device', 'example.com');
    }

    drawer.classList.remove('hidden');
    drawer.classList.add('open');
}

export function closeHelpDrawer() {
    const drawer = document.getElementById('guided-help-drawer');
    if (!drawer) return;
    drawer.classList.remove('open');
    drawer.classList.add('hidden');
}

export function initHelpDrawer() {
    window.openHelpTopic = openHelpTopic;
    window.closeHelpDrawer = closeHelpDrawer;

    document.addEventListener('click', (e) => {
        const trigger = e.target.closest('[data-help-topic]');
        if (trigger) {
            e.preventDefault();
            e.stopPropagation();
            openHelpTopic(trigger.getAttribute('data-help-topic'));
        }
    });

    document.getElementById('help-drawer-close')?.addEventListener('click', closeHelpDrawer);
    document.getElementById('guided-help-backdrop')?.addEventListener('click', closeHelpDrawer);
}

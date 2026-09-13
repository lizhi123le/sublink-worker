
import { SING_BOX_CONFIG, generateRuleSets, generateRules, getOutbounds, PREDEFINED_RULE_SETS, DIRECT_DEFAULT_RULES, REJECT_ACTION_RULES } from '../config/index.js';
import { BaseConfigBuilder } from './BaseConfigBuilder.js';
import { deepCopy, groupProxiesByCountry } from '../utils.js';
import { addProxyWithDedup } from './helpers/proxyHelpers.js';
import { buildSelectorMembers as buildSelectorMemberList, buildNodeSelectMembers, buildCustomRuleMembers, uniqueNames } from './helpers/groupBuilder.js';
import { normalizeGroupName } from './helpers/groupNameUtils.js';

// Feature tiers, oldest to newest. Each tier only adds or drops fields, and a
// client rejects any field it does not know as an unknown-field error.
const TIER_ORDER = ['1.11', '1.12', '1.14', '1.15'];
const normalizeTier = (tier) => (TIER_ORDER.includes(tier) ? tier : '1.12');
const tierAtLeast = (tier, minimum) => TIER_ORDER.indexOf(tier) >= TIER_ORDER.indexOf(minimum);

const RULE_SET_HTTP_CLIENT_TAG = 'rule-set-download';
const PROXY_DNS_SERVER_TAG = 'dns_proxy';
const DIRECT_OUTBOUND_TAG = 'DIRECT';

const ANYTLS_OPTION_KEYS = {
    'idle-session-check-interval': 'idle_session_check_interval',
    'idle-session-timeout': 'idle_session_timeout',
    'min-idle-session': 'min_idle_session'
};

// Only these DNS servers dial an upstream through an outbound, so only they can
// carry a detour; setting it on local/hosts/fakeip makes system resolution
// depend on the proxy whose own address still needs to be resolved.
const REMOTE_DNS_SERVER_TYPES = new Set(['udp', 'tcp', 'tls', 'https', 'quic', 'h3']);

// sing-box rejects an http_client detour that points at a direct outbound without
// options ("detour to an empty direct outbound makes no sense") and omitting the
// detour already dials directly, so such detours have to be dropped.
const isEmptyDirectOutbound = (outbound) => outbound?.type === 'direct'
    && Object.keys(outbound).every(key => key === 'type' || key === 'tag');

export class SingboxConfigBuilder extends BaseConfigBuilder {
    constructor(inputString, selectedRules, customRules, baseConfig, lang, userAgent, groupByCountry = false, enableClashUI = false, externalController, externalUiDownloadUrl, singboxVersion = '1.14', includeAutoSelect = true) {
        const resolvedBaseConfig = baseConfig ?? SING_BOX_CONFIG;
        super(inputString, resolvedBaseConfig, lang, userAgent, groupByCountry, includeAutoSelect);

        this.selectedRules = selectedRules;
        this.customRules = customRules;
        this.countryGroupNames = [];
        this.manualGroupName = null;
        this.enableClashUI = enableClashUI;
        this.externalController = externalController;
        this.externalUiDownloadUrl = externalUiDownloadUrl;
        this.singboxVersion = normalizeTier(singboxVersion);  // '1.11' | '1.12' | '1.14' | '1.15'

        this.stripProviderFields();
        this.applyVersionCompatibility();
        this.configureProxyDnsDetour();
    }

    /**
     * Drop fields older sing-box versions reject as unknown: strict JSON decoding
     * fails the whole config, so one shared modern template cannot carry them.
     */
    applyVersionCompatibility() {
        if (!tierAtLeast(this.singboxVersion, '1.14')) {
            delete this.config.http_clients;
            if (this.config.route) {
                delete this.config.route.default_http_client;
            }
            if (this.config.experimental?.cache_file) {
                delete this.config.experimental.cache_file.store_dns;
            }
        }

        if (tierAtLeast(this.singboxVersion, '1.15')) {
            // 1.15 replaced the tun stack option with sing-tun's own stack: keeping
            // it only warns on 1.15 and needs ENABLE_DEPRECATED_TUN_STACK on 1.16.
            (this.config.inbounds || []).forEach(inbound => {
                if (inbound?.type === 'tun') {
                    delete inbound.stack;
                }
            });
        }
    }

    /**
     * Point the proxy DNS server at the node selector. local/hosts/fakeip stay
     * untouched: routing them through a proxy re-enters DNS resolution for that
     * proxy's own domain, which surfaces as startup "lookup <node domain>:
     * context deadline exceeded" and stalls rule-set initialization.
     */
    configureProxyDnsDetour() {
        const servers = this.config?.dns?.servers;
        if (!Array.isArray(servers) || servers.length === 0) return;

        const target = servers.find(server => server?.tag === PROXY_DNS_SERVER_TAG)
            ?? servers.find(server => REMOTE_DNS_SERVER_TYPES.has(server?.type))
            // Legacy servers (sing-box <= 1.11) are identified by address only.
            ?? servers.find(server => server?.type === undefined);

        if (target) {
            target.detour = this.t('outboundNames.Node Select');
        }
    }

    /**
     * sing-box has no provider concept: neither `outbound_providers` nor a group
     * `providers` field exists in its schema, and strict decoding rejects the
     * whole config with "json: unknown field". Subscription content is always
     * inlined as regular outbounds, so drop anything a stored base config
     * (or an outdated UI state) still carries.
     */
    stripProviderFields() {
        delete this.config.outbound_providers;
        (this.config.outbounds || []).forEach(outbound => {
            delete outbound.providers;
        });
    }

    getProxies() {
        return this.config.outbounds.filter(outbound => outbound?.server != undefined);
    }

    getProxyName(proxy) {
        return proxy.tag;
    }

    convertProxy(proxy) {
        // Create a shallow copy to avoid mutating the original
        const sanitized = { ...proxy };

        // URI and Clash inputs use Mihomo's kebab-case names, while sing-box
        // rejects those keys and requires its native snake_case options.
        if (sanitized.type === 'anytls') {
            Object.entries(ANYTLS_OPTION_KEYS).forEach(([sourceKey, targetKey]) => {
                if (sanitized[sourceKey] !== undefined && sanitized[targetKey] === undefined) {
                    sanitized[targetKey] = sanitized[sourceKey];
                }
                delete sanitized[sourceKey];
            });
            // sing-box types the two idle intervals as Duration strings ("30s"),
            // while share links and Mihomo carry plain seconds
            ['idle_session_check_interval', 'idle_session_timeout'].forEach((key) => {
                if (typeof sanitized[key] === 'number') {
                    sanitized[key] = `${sanitized[key]}s`;
                }
            });
        }

        // Strip Clash-only / mis-typed fields that conflict with sing-box semantics.
        // `udp` is Clash-only. Top-level `network` in sing-box is a TCP/UDP allowlist
        // (NetworkList in option/types.go); a stray "tcp" silently disables UDP for
        // every group that selects this node — including DNS hijack and fakeip.
        delete sanitized.udp;
        delete sanitized.network;

        // Remove 'alpn' from root level - it should only exist inside 'tls' object for sing-box
        // For protocols like vless/vmess, alpn belongs inside the tls configuration
        if (sanitized.alpn && sanitized.tls) {
            // Move alpn into tls if tls exists and doesn't have alpn
            if (!sanitized.tls.alpn) {
                sanitized.tls = { ...sanitized.tls, alpn: sanitized.alpn };
            }
            delete sanitized.alpn;
        } else if (sanitized.alpn && !sanitized.tls) {
            // No TLS, remove alpn entirely
            delete sanitized.alpn;
        }

        // Remove packet_encoding for now - it's version-specific in sing-box
        // xudp is default in newer versions
        delete sanitized.packet_encoding;

        if (sanitized.type === 'hysteria2') {
            // sing-box names port-hopping/bandwidth fields differently from the
            // share-link shape, and rejects unknown fields outright
            if (sanitized.ports) {
                const ranges = String(sanitized.ports).split(',')
                    .map(range => range.trim().replace('-', ':'))
                    .filter(Boolean);
                if (ranges.length > 0) {
                    sanitized.server_ports = ranges;
                }
            }
            delete sanitized.ports;
            if (typeof sanitized.hop_interval === 'number') {
                sanitized.hop_interval = `${sanitized.hop_interval}s`;
            }
            // sing-box types up_mbps/down_mbps as int, while share links and Clash
            // YAML carry either plain numbers or bandwidth strings ("200 Mbps")
            const toMbps = (value) => {
                if (typeof value === 'number') {
                    return Number.isFinite(value) ? Math.round(value) : undefined;
                }
                const match = String(value ?? '').trim().match(/^([\d.]+)\s*(k|m|g)?(?:bps|b\/s|b)?$/i);
                if (!match) return undefined;
                const amount = Number.parseFloat(match[1]);
                if (!Number.isFinite(amount)) return undefined;
                const scale = { k: 1 / 1000, m: 1, g: 1000 }[(match[2] || 'm').toLowerCase()] ?? 1;
                return Math.round(amount * scale);
            };
            if (sanitized.up !== undefined) {
                const upMbps = toMbps(sanitized.up);
                if (upMbps !== undefined) {
                    sanitized.up_mbps = upMbps;
                }
                delete sanitized.up;
            }
            if (sanitized.down !== undefined) {
                const downMbps = toMbps(sanitized.down);
                if (downMbps !== undefined) {
                    sanitized.down_mbps = downMbps;
                }
                delete sanitized.down;
            }
            delete sanitized.auth;
            delete sanitized.recv_window_conn;
            delete sanitized.fast_open;
        }

        return sanitized;
    }

    addProxyToConfig(proxy) {
        this.config.outbounds = this.config.outbounds || [];
        addProxyWithDedup(this.config.outbounds, proxy, {
            getName: (item) => item?.tag,
            setName: (item, name) => {
                if (item) item.tag = name;
            },
            isSame: (existing = {}, incoming = {}) => {
                const { tag: _incomingTag, ...restIncoming } = incoming;
                const { tag: _existingTag, ...restExisting } = existing;
                return JSON.stringify(restIncoming) === JSON.stringify(restExisting);
            }
        });
    }

    hasOutboundTag(tag) {
        const target = normalizeGroupName(tag);
        return (this.config.outbounds || []).some(outbound => normalizeGroupName(outbound?.tag) === target);
    }

    hasAutoSelectCandidates(proxyList = this.getProxyList()) {
        return Array.isArray(proxyList) && proxyList.length > 0;
    }

    addAutoSelectGroup(proxyList) {
        if (!this.includeAutoSelect) return;
        this.config.outbounds = this.config.outbounds || [];
        const tag = this.t('outboundNames.Auto Select');
        if (this.hasOutboundTag(tag)) return;
        const autoSelectMembers = deepCopy(uniqueNames(proxyList));
        if (autoSelectMembers.length === 0) return;

        this.config.outbounds.unshift({
            type: "urltest",
            tag,
            outbounds: autoSelectMembers
        });
    }

    addNodeSelectGroup(proxyList) {
        this.config.outbounds = this.config.outbounds || [];
        const tag = this.t('outboundNames.Node Select');
        if (this.hasOutboundTag(tag)) return;
        const includeAutoSelect = this.includeAutoSelect && this.hasAutoSelectCandidates(proxyList);
        const members = buildNodeSelectMembers({
            proxyList,
            translator: this.t,
            groupByCountry: this.groupByCountry,
            manualGroupName: this.manualGroupName,
            countryGroupNames: this.countryGroupNames,
            includeAutoSelect,
            includeReject: false
        });

        this.config.outbounds.unshift({
            type: "selector",
            tag,
            outbounds: members
        });
    }

    buildSelectorMembers(proxyList = []) {
        return buildSelectorMemberList({
            proxyList,
            translator: this.t,
            groupByCountry: this.groupByCountry,
            manualGroupName: this.manualGroupName,
            countryGroupNames: this.countryGroupNames,
            includeAutoSelect: this.includeAutoSelect && this.hasAutoSelectCandidates(proxyList),
            includeReject: false
        });
    }

    addOutboundGroups(outbounds, proxyList) {
        outbounds.forEach(outbound => {
            if (outbound !== this.t('outboundNames.Node Select')) {
                if (REJECT_ACTION_RULES.has(outbound)) return;
                let selectorMembers = this.buildSelectorMembers(proxyList);
                const tag = this.t(`outboundNames.${outbound}`);
                if (this.hasOutboundTag(tag)) {
                    return;
                }
                // For rules that should default to DIRECT, move DIRECT to the front
                if (DIRECT_DEFAULT_RULES.has(outbound)) {
                    selectorMembers = ['DIRECT', ...selectorMembers.filter(p => p !== 'DIRECT')];
                }
                this.config.outbounds.push({
                    type: "selector",
                    tag,
                    outbounds: selectorMembers
                });
            }
        });
    }

    addCustomRuleGroups(proxyList) {
        if (Array.isArray(this.customRules)) {
            this.customRules.forEach(rule => {
                const includeAutoSelect = this.includeAutoSelect && this.hasAutoSelectCandidates(proxyList);
                const selectorMembers = buildCustomRuleMembers({
                    proxyList,
                    translator: this.t,
                    manualGroupName: this.manualGroupName,
                    includeAutoSelect,
                    includeReject: false
                });
                if (this.hasOutboundTag(rule.name)) return;
                this.config.outbounds.push({
                    type: "selector",
                    tag: rule.name,
                    outbounds: selectorMembers
                });
            });
        }
    }

    addFallBackGroup(proxyList) {
        const selectorMembers = this.buildSelectorMembers(proxyList);
        if (this.hasOutboundTag(this.t('outboundNames.Fall Back'))) return;
        this.config.outbounds.push({
            type: "selector",
            tag: this.t('outboundNames.Fall Back'),
            outbounds: selectorMembers
        });
    }

    addCountryGroups() {
        const proxies = this.getProxies();
        const countryGroups = groupProxiesByCountry(proxies, {
            getName: proxy => this.getProxyName(proxy)
        });

        const existingTags = new Set((this.config.outbounds || []).map(o => normalizeGroupName(o?.tag)).filter(Boolean));

        const manualProxyNames = proxies.map(p => p?.tag).filter(Boolean);
        const manualGroupName = manualProxyNames.length > 0 ? this.t('outboundNames.Manual Switch') : null;
        if (manualGroupName) {
            const manualNorm = normalizeGroupName(manualGroupName);
            if (!existingTags.has(manualNorm)) {
                this.config.outbounds.push({
                    type: 'selector',
                    tag: manualGroupName,
                    outbounds: manualProxyNames
                });
                existingTags.add(manualNorm);
            }
        }

        const countries = Object.keys(countryGroups).sort((a, b) => a.localeCompare(b));
        const countryGroupNames = [];
        const includeAutoSelect = this.includeAutoSelect && this.hasAutoSelectCandidates();

        countries.forEach(country => {
            const { emoji, name, proxies: countryProxies } = countryGroups[country];
            if (!countryProxies || countryProxies.length === 0) {
                return;
            }
            const groupName = `${emoji} ${name}`;
            const norm = normalizeGroupName(groupName);
            if (!existingTags.has(norm)) {
                this.config.outbounds.push({
                    tag: groupName,
                    type: 'urltest',
                    outbounds: countryProxies
                });
                existingTags.add(norm);
            }
            countryGroupNames.push(groupName);
        });

        const nodeSelectTag = this.t('outboundNames.Node Select');
        const nodeSelectGroup = this.config.outbounds.find(o => normalizeGroupName(o?.tag) === normalizeGroupName(nodeSelectTag));
        if (nodeSelectGroup && Array.isArray(nodeSelectGroup.outbounds)) {
            const rebuilt = buildNodeSelectMembers({
                proxyList: [],
                translator: this.t,
                groupByCountry: true,
                manualGroupName,
                countryGroupNames,
                includeAutoSelect,
                includeReject: false
            });
            nodeSelectGroup.outbounds = rebuilt;
        }

        this.countryGroupNames = countryGroupNames;
        this.manualGroupName = manualGroupName;
    }

    /**
     * Merge user-defined proxy groups (selector/urltest outbounds) with system-generated ones
     * Handles same-tag groups by merging their outbounds
     * @param {Array} userGroups - User-defined proxy groups from input config (converted to Clash format)
     */
    mergeUserProxyGroups(userGroups) {
        if (!Array.isArray(userGroups)) return;

        const proxyList = this.getProxyList();

        // Build valid reference set (proxy tags, group tags, special names)
        const groupTags = new Set(
            (this.config.outbounds || [])
                .filter(o => o.type === 'selector' || o.type === 'urltest')
                .map(o => normalizeGroupName(o?.tag))
                .filter(Boolean)
        );
        const validRefs = new Set(['DIRECT', 'direct']);
        proxyList.forEach(n => validRefs.add(n));
        groupTags.forEach(n => validRefs.add(n));

        userGroups.forEach(userGroup => {
            if (!userGroup?.name) return;

            // Find existing outbound by normalized tag/name
            const existingIndex = (this.config.outbounds || []).findIndex(o =>
                normalizeGroupName(o?.tag) === normalizeGroupName(userGroup.name)
            );

            if (existingIndex >= 0) {
                // Merge with existing system group
                const existing = this.config.outbounds[existingIndex];

                // Merge 'outbounds' field (equivalent to Clash 'proxies')
                if (Array.isArray(userGroup.proxies) && userGroup.proxies.length > 0) {
                    const validUserOutbounds = userGroup.proxies.filter(p => validRefs.has(p));
                    existing.outbounds = [...new Set([
                        ...(existing.outbounds || []),
                        ...validUserOutbounds
                    ])];
                }

                // Preserve user's custom settings
                if (userGroup.url) existing.url = userGroup.url;
                if (typeof userGroup.interval === 'number') {
                    existing.interval = `${userGroup.interval}s`;
                }
            } else {
                // New user-defined group - convert from Clash format and add
                const newOutbound = {
                    type: userGroup.type === 'url-test' ? 'urltest' : 'selector',
                    tag: userGroup.name
                };

                // Validate outbounds references
                if (Array.isArray(userGroup.proxies)) {
                    newOutbound.outbounds = userGroup.proxies.filter(p => validRefs.has(p));
                }

                // Only add if it references something sing-box can actually dial
                if (newOutbound.outbounds?.length > 0) {
                    this.config.outbounds.push(newOutbound);
                }
            }
        });
    }

    /**
     * Validate outbounds before final output
     * Ensures urltest groups have outbounds, fills empty ones with all proxy tags
     */
    validateOutbounds() {
        const proxyList = this.getProxyList();
        const invalidTags = new Set();

        (this.config.outbounds || []).forEach(outbound => {
            // For urltest groups, ensure they have outbounds
            if (outbound.type === 'urltest' &&
                (!outbound.outbounds || outbound.outbounds.length === 0)) {
                // Fill with all available proxy tags
                outbound.outbounds = [...proxyList];
                if (!outbound.outbounds || outbound.outbounds.length === 0) {
                    invalidTags.add(normalizeGroupName(outbound.tag));
                }
            }
        });

        if (invalidTags.size > 0) {
            this.config.outbounds = (this.config.outbounds || [])
                .filter(outbound => !invalidTags.has(normalizeGroupName(outbound?.tag)))
                .map(outbound => {
                    if (Array.isArray(outbound.outbounds)) {
                        outbound.outbounds = outbound.outbounds.filter(tag => !invalidTags.has(normalizeGroupName(tag)));
                    }
                    return outbound;
                });
        }
    }

    sanitizeLegacySpecialOutbounds() {
        const legacyTags = new Set(
            (this.config.outbounds || [])
                .filter(outbound => outbound?.type === 'block' || outbound?.type === 'dns')
                .map(outbound => normalizeGroupName(outbound?.tag))
                .filter(Boolean)
        );
        legacyTags.add(normalizeGroupName('REJECT'));

        this.config.outbounds = (this.config.outbounds || [])
            .filter(outbound => !legacyTags.has(normalizeGroupName(outbound?.tag)))
            .map(outbound => {
                if (Array.isArray(outbound.outbounds)) {
                    outbound.outbounds = outbound.outbounds.filter(tag => !legacyTags.has(normalizeGroupName(tag)));
                }
                return outbound;
            })
            .filter(outbound => {
                if (outbound?.type !== 'selector' && outbound?.type !== 'urltest') return true;
                return outbound.outbounds?.length > 0;
            });
    }

    buildRouteTarget(rule) {
        if (REJECT_ACTION_RULES.has(rule?.outbound) || rule?.outbound === 'REJECT') {
            return { action: 'reject' };
        }
        return { outbound: this.t(`outboundNames.${rule.outbound}`) };
    }

    /**
     * Drop http_client detours that point at an option-less direct outbound.
     * sing-box refuses them at dial time ("detour to an empty direct outbound
     * makes no sense") and the direct dialer is the default anyway, so legacy
     * templates carrying `detour: "DIRECT"` must not survive into the output.
     */
    sanitizeHttpClientDetours() {
        const clients = this.config.http_clients;
        if (!Array.isArray(clients)) return;

        clients.forEach(client => {
            if (!client?.detour) return;
            const outbound = (this.config.outbounds || []).find(item => item?.tag === client.detour);
            if (isEmptyDirectOutbound(outbound)) {
                delete client.detour;
            }
        });
    }

    /**
     * Pin remote rule-set downloads to DIRECT. Both the implicit default HTTP
     * client (<= 1.13) and the first `http_clients` entry connect through a proxy
     * outbound, which cannot work before that proxy resolves its own server
     * domain, so startup lookups deadlock. sing-box 1.14 replaced
     * `download_detour` with `http_clients` + `route.default_http_client`; older
     * clients reject those two as unknown fields.
     */
    configureRuleSetDownload() {
        const remoteRuleSets = (this.config.route?.rule_set || []).filter(ruleSet => ruleSet?.type === 'remote');

        if (!tierAtLeast(this.singboxVersion, '1.14')) {
            remoteRuleSets.forEach(ruleSet => {
                if (!ruleSet.download_detour) {
                    ruleSet.download_detour = DIRECT_OUTBOUND_TAG;
                }
            });
            return;
        }

        // download_detour is deprecated in 1.14; default_http_client replaces it.
        remoteRuleSets.forEach(ruleSet => {
            delete ruleSet.download_detour;
        });
        this.sanitizeHttpClientDetours();

        if (this.config.route.default_http_client) return;

        // A client without a detour dials directly, which is what a rule-set
        // download needs: `detour: "DIRECT"` is rejected by sing-box at dial time.
        const clients = Array.isArray(this.config.http_clients) ? this.config.http_clients : [];
        const directClient = clients.find(client => client?.tag && !client.detour);
        if (directClient) {
            this.config.route.default_http_client = directClient.tag;
            return;
        }

        const usedTags = new Set(clients.map(client => client?.tag).filter(Boolean));
        let tag = RULE_SET_HTTP_CLIENT_TAG;
        let suffix = 2;
        while (usedTags.has(tag)) {
            tag = `${RULE_SET_HTTP_CLIENT_TAG}-${suffix}`;
            suffix += 1;
        }

        this.config.http_clients = [...clients, { tag }];
        this.config.route.default_http_client = tag;
    }

    formatConfig() {
        const rules = generateRules(this.selectedRules, this.customRules);
        const { site_rule_sets, ip_rule_sets } = generateRuleSets(this.selectedRules, this.customRules);

        this.config.route.rule_set = [...site_rule_sets, ...ip_rule_sets];
        this.configureRuleSetDownload();

        // Validate outbounds: fill empty urltest groups with all proxies
        this.validateOutbounds();
        this.sanitizeLegacySpecialOutbounds();

        const attachProtocolIfNeeded = (entry, rule) => {
            if (Array.isArray(rule?.protocol) && rule.protocol.length > 0) {
                entry.protocol = rule.protocol;
            }
            return entry;
        };

        const hasMatchValues = (value) => {
            if (Array.isArray(value)) return value.length > 0;
            if (typeof value === 'string') return value.trim() !== '';
            return false;
        };

        rules.filter(rule => Array.isArray(rule.src_ip_cidr) && rule.src_ip_cidr.length > 0).map(rule => {
            this.config.route.rules.push(attachProtocolIfNeeded({
                source_ip_cidr: rule.src_ip_cidr,
                ...this.buildRouteTarget(rule)
            }, rule));
        });

        rules.filter(rule => hasMatchValues(rule.domain_suffix) || hasMatchValues(rule.domain_keyword)).map(rule => {
            const entry = {
                ...this.buildRouteTarget(rule)
            };

            if (hasMatchValues(rule.domain_suffix)) entry.domain_suffix = rule.domain_suffix;
            if (hasMatchValues(rule.domain_keyword)) entry.domain_keyword = rule.domain_keyword;

            this.config.route.rules.push(attachProtocolIfNeeded(entry, rule));
        });

        rules.filter(rule => !!rule.site_rules[0]).map(rule => {
            this.config.route.rules.push(attachProtocolIfNeeded({
                rule_set: [
                    ...(rule.site_rules.length > 0 && rule.site_rules[0] !== '' ? rule.site_rules : []),
                ],
                ...this.buildRouteTarget(rule)
            }, rule));
        });

        rules.filter(rule => !!rule.ip_rules[0]).map(rule => {
            this.config.route.rules.push(attachProtocolIfNeeded({
                rule_set: [
                    ...(rule.ip_rules
                        .map(ip => ip.trim())
                        .filter(ip => ip !== '')
                        .map(ip => `${ip}-ip`))
                ],
                ...this.buildRouteTarget(rule)
            }, rule));
        });

        rules.filter(rule => hasMatchValues(rule.ip_cidr)).map(rule => {
            this.config.route.rules.push(attachProtocolIfNeeded({
                ip_cidr: rule.ip_cidr,
                ...this.buildRouteTarget(rule)
            }, rule));
        });

        // Order matters: sniff first so downstream rules can match on protocol;
        // hijack-dns before clash_mode so DNS never escapes into a selector when
        // the user toggles global mode (selectors only support TCP+UDP if the
        // currently selected node does, which is fragile).
        this.config.route.rules.unshift(
            { inbound: ['tun-in', 'mixed-in'], action: 'sniff' },
            { type: 'logical', mode: 'or', rules: [{ port: 53 }, { protocol: 'dns' }], action: 'hijack-dns' },
            { clash_mode: 'direct', outbound: 'DIRECT' },
            { clash_mode: 'global', outbound: this.t('outboundNames.Node Select') }
        );

        this.config.route.auto_detect_interface = true;
        this.config.route.final = this.t('outboundNames.Fall Back');
        // 如果启用了 Clash UI，添加配置
        // 如果启用 Clash UI 或传入了自定义参数，添加/覆盖 Clash API 配置
        if (this.enableClashUI || this.externalController || this.externalUiDownloadUrl) {
            const defaultExternalController = "0.0.0.0:9090";
            const defaultExternalUiDownloadUrl = "https://gh-proxy.com/https://github.com/Zephyruso/zashboard/archive/refs/heads/gh-pages.zip";
            const defaultExternalUi = "./ui";
            const defaultSecret = "";
            const defaultDownloadDetour = "DIRECT";
            const defaultClashMode = "rule";

            this.config.experimental = this.config.experimental || {};
            const existingClashApi = this.config.experimental.clash_api || {};

            const externalController = this.externalController || existingClashApi.external_controller || defaultExternalController;
            const externalUiDownloadUrl = this.externalUiDownloadUrl || existingClashApi.external_ui_download_url || defaultExternalUiDownloadUrl;
            const externalUi = existingClashApi.external_ui || defaultExternalUi;
            const secret = existingClashApi.secret ?? defaultSecret;
            const externalUiDownloadDetour = existingClashApi.external_ui_download_detour || defaultDownloadDetour;
            const clashMode = existingClashApi.default_mode || defaultClashMode;

            this.config.experimental.clash_api = {
                ...existingClashApi,
                external_controller: externalController,
                external_ui: externalUi,
                external_ui_download_url: externalUiDownloadUrl,
                external_ui_download_detour: externalUiDownloadDetour,
                secret,
                default_mode: clashMode
            };
        }
        return this.config;
    }
}

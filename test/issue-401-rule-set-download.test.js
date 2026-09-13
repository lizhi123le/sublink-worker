import { describe, it, expect } from 'vitest';
import { SingboxConfigBuilder } from '../src/builders/SingboxConfigBuilder.js';
import { SING_BOX_CONFIG, SING_BOX_CONFIG_V1_11 } from '../src/config/index.js';
import { createApp } from '../src/app/createApp.jsx';
import { MemoryKVAdapter } from '../src/adapters/kv/memoryKv.js';

/**
 * Issues #401/#408: remote rule-sets must not be downloaded through a proxy.
 * Both the implicit default HTTP client (sing-box <= 1.13) and the first
 * `http_clients` entry connect through a proxy outbound, which cannot work
 * before that proxy resolves its own server domain, so startup lookups deadlock
 * ("lookup <node domain>: context deadline exceeded") and rule-set init stalls.
 *
 * sing-box 1.14 replaced `download_detour` with `http_clients` +
 * `route.default_http_client`, and those two are unknown fields on older
 * clients (strict decoding fails the whole config), so the tiers differ.
 */

const vlessUrl = 'vless://12345678-1234-1234-1234-123456789abc@example.com:443?security=tls&sni=example.com#TestVless';
const vmessUrl = 'vmess://ew0KICAidiI6ICIyIiwNCiAgInBzIjogInRlc3QiLA0KICAiYWRkIjogIjEuMS4xLjEiLA0KICAicG9ydCI6ICI0NDMiLA0KICAiaWQiOiAiYWRkNjY2NjYtODg4OC04ODg4LTg4ODgtODg4ODg4ODg4ODg4IiwNCiAgImFpZCI6ICIwIiwNCiAgInNjeSI6ICJhdXRvIiwNCiAgIm5ldCI6ICJ3cyIsDQogICJ0eXBlIjogIm5vbmUiLA0KICAiaG9zdCI6ICIiLA0KICAicGF0aCI6ICIvIiwNCiAgInRscyI6ICJ0bHMiDQp9';

const cloneConfig = (config) => JSON.parse(JSON.stringify(config));

const buildWithVersion = async (singboxVersion, baseConfig = null) => {
    const builder = new SingboxConfigBuilder(
        vlessUrl, [], [], baseConfig, 'zh-CN', null, false,
        false, undefined, undefined, singboxVersion
    );
    return builder.build();
};

describe('sing-box 1.14 remote rule-set downloads', () => {
    it('uses the DIRECT shared HTTP client on the 1.14 tier', async () => {
        const result = await buildWithVersion('1.14');

        result.route.rule_set.forEach(ruleSet => {
            expect(ruleSet).not.toHaveProperty('download_detour');
            expect(ruleSet).not.toHaveProperty('http_client');
        });

        expect(result.route.default_http_client).toBe('direct');
        expect(result.http_clients).toEqual([
            { tag: 'default', detour: '🚀 节点选择' },
            { tag: 'direct', detour: 'DIRECT' }
        ]);
    });

    it('creates a dedicated DIRECT client when the base config has none', async () => {
        const baseConfig = cloneConfig(SING_BOX_CONFIG);
        delete baseConfig.http_clients;

        const result = await buildWithVersion('1.14', baseConfig);

        expect(result.http_clients).toEqual([{ tag: 'rule-set-download', detour: 'DIRECT' }]);
        expect(result.route.default_http_client).toBe('rule-set-download');
    });

    it('keeps an explicit default_http_client from the base config', async () => {
        const baseConfig = cloneConfig(SING_BOX_CONFIG);
        baseConfig.route.default_http_client = 'custom-client';

        const result = await buildWithVersion('1.14', baseConfig);

        expect(result.route.default_http_client).toBe('custom-client');
    });

    it('drops 1.14-only fields and pins download_detour on the 1.12 tier', async () => {
        const result = await buildWithVersion('1.12');

        expect(result.http_clients).toBeUndefined();
        expect(result.route.default_http_client).toBeUndefined();
        expect(result.experimental?.cache_file?.store_dns).toBeUndefined();
        result.route.rule_set.forEach(ruleSet => {
            expect(ruleSet.download_detour).toBe('DIRECT');
            expect(ruleSet).not.toHaveProperty('http_client');
        });
    });

    it('pins download_detour on the 1.11 tier without 1.14 fields', async () => {
        const result = await buildWithVersion('1.11', SING_BOX_CONFIG_V1_11);

        expect(result.http_clients).toBeUndefined();
        expect(result.route.default_http_client).toBeUndefined();
        result.route.rule_set.forEach(ruleSet => {
            expect(ruleSet.download_detour).toBe('DIRECT');
        });
    });
});

describe('sing-box DNS resolver detour stays direct', () => {
    it('does not route the local resolver through the node selector', async () => {
        for (const version of ['1.14', '1.12']) {
            const result = await buildWithVersion(version);
            const local = result.dns.servers.find(server => server.tag === 'local');
            const proxy = result.dns.servers.find(server => server.tag === 'dns_proxy');

            expect(local).toBeDefined();
            expect(local).not.toHaveProperty('detour');
            expect(proxy.detour).toBe('🚀 节点选择');
        }
    });
});

describe('sing-box version tier resolution', () => {
    const createTestApp = () => createApp({
        kv: new MemoryKVAdapter(),
        assetFetcher: null,
        logger: console,
        config: { configTtlSeconds: 60, shortLinkTtlSeconds: null }
    });

    const fetchConfig = (query = '', headers) => {
        const app = createTestApp();
        return app.request(`http://localhost/singbox?config=${encodeURIComponent(vmessUrl)}${query}`, { headers });
    };

    it('returns the 1.14 shape for sb_ver=1.14', async () => {
        const res = await fetchConfig('&sb_ver=1.14');
        expect(res.status).toBe(200);
        const json = await res.json();
        expect(json.route.default_http_client).toBe('direct');
    });

    it('returns the 1.14 shape for a sing-box 1.14 user-agent', async () => {
        const res = await fetchConfig('', {
            'User-Agent': 'SFA/1.14.0 (100; sing-box 1.14.0; language zh_Hans_CN)'
        });
        expect(res.status).toBe(200);
        const json = await res.json();
        expect(json.route.default_http_client).toBe('direct');
    });

    it('maps sb_ver=latest to the newest tier', async () => {
        const res = await fetchConfig('&sb_ver=latest');
        expect(res.status).toBe(200);
        const json = await res.json();
        expect(json.route.default_http_client).toBe('direct');
    });

    it('keeps the 1.12 tier for sing-box 1.13 user-agents', async () => {
        const res = await fetchConfig('', {
            'User-Agent': 'SFI/1.14.0 (20; sing-box 1.13.0; language zh_CN)'
        });
        expect(res.status).toBe(200);
        const json = await res.json();
        expect(json).not.toHaveProperty('http_clients');
        expect(json.route).not.toHaveProperty('default_http_client');
        json.route.rule_set.forEach(ruleSet => {
            if (ruleSet.type === 'remote') {
                expect(ruleSet.download_detour).toBe('DIRECT');
            }
        });
    });

    it('falls back to the safe 1.12 tier when no version is detectable', async () => {
        const res = await fetchConfig();
        expect(res.status).toBe(200);
        const json = await res.json();
        expect(json).not.toHaveProperty('http_clients');
        expect(json.route).not.toHaveProperty('default_http_client');
    });
});

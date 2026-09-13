import { describe, it, expect } from 'vitest';
import { SingboxConfigBuilder } from '../src/builders/SingboxConfigBuilder.js';
import { SING_BOX_CONFIG_V1_11 } from '../src/config/index.js';
import { createApp } from '../src/app/createApp.jsx';
import { MemoryKVAdapter } from '../src/adapters/kv/memoryKv.js';

/**
 * sing-box 1.15 deprecates the TUN `stack` option (removed in 1.17, and the 1.16
 * command-line client only accepts it with ENABLE_DEPRECATED_TUN_STACK=true),
 * because sing-tun now ships its own TCP/IP stack.
 *
 * Tiers before 1.15 keep the field: on 1.14 and older `stack` is optional and
 * still selects the gvisor/system implementation.
 */

const vlessUrl = 'vless://12345678-1234-1234-1234-123456789abc@example.com:443?security=tls&sni=example.com#TestVless';
const vmessUrl = 'vmess://ew0KICAidiI6ICIyIiwNCiAgInBzIjogInRlc3QiLA0KICAiYWRkIjogIjEuMS4xLjEiLA0KICAicG9ydCI6ICI0NDMiLA0KICAiaWQiOiAiYWRkNjY2NjYtODg4OC04ODg4LTg4ODgtODg4ODg4ODg4ODg4IiwNCiAgImFpZCI6ICIwIiwNCiAgInNjeSI6ICJhdXRvIiwNCiAgIm5ldCI6ICJ3cyIsDQogICJ0eXBlIjogIm5vbmUiLA0KICAiaG9zdCI6ICIiLA0KICAicGF0aCI6ICIvIiwNCiAgInRscyI6ICJ0bHMiDQp9';

const buildWithVersion = async (singboxVersion, baseConfig = null) => {
    const builder = new SingboxConfigBuilder(
        vlessUrl, [], [], baseConfig, 'zh-CN', null, false,
        false, undefined, undefined, singboxVersion
    );
    return builder.build();
};

const tunInbound = (config) => config.inbounds.find(inbound => inbound.type === 'tun');

describe('sing-box 1.15 TUN stack', () => {
    it('drops stack on the 1.15 tier while keeping the 1.14 features', async () => {
        const result = await buildWithVersion('1.15');

        expect(tunInbound(result)).toBeDefined();
        expect(tunInbound(result)).not.toHaveProperty('stack');
        expect(result.route.default_http_client).toBe('direct');
        expect(result.http_clients).toHaveLength(2);
        result.route.rule_set.forEach(ruleSet => {
            expect(ruleSet).not.toHaveProperty('download_detour');
        });
    });

    it('keeps stack on the 1.14 and 1.12 tiers', async () => {
        for (const version of ['1.14', '1.12']) {
            const result = await buildWithVersion(version);
            expect(tunInbound(result).stack).toBe('system');
        }
    });

    it('keeps the 1.11 template stack value', async () => {
        const result = await buildWithVersion('1.11', SING_BOX_CONFIG_V1_11);
        expect(tunInbound(result).stack).toBe('mixed');
    });

    it('drops stack from a user base config on the 1.15 tier', async () => {
        const baseConfig = {
            inbounds: [{ type: 'tun', tag: 'tun-in', address: ['172.19.0.0/30'], stack: 'mixed' }],
            outbounds: [{ type: 'direct', tag: 'DIRECT' }],
            route: { rule_set: [], rules: [] }
        };

        const result = await buildWithVersion('1.15', baseConfig);
        expect(tunInbound(result)).not.toHaveProperty('stack');
    });

    it('falls back to the 1.12 shape for an unknown tier', async () => {
        const result = await buildWithVersion('1.13');

        expect(tunInbound(result).stack).toBe('system');
        expect(result.http_clients).toBeUndefined();
        expect(result.route.default_http_client).toBeUndefined();
    });
});

describe('sing-box 1.15 tier resolution', () => {
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

    it('drops stack for a sing-box 1.15 user-agent', async () => {
        const res = await fetchConfig('', {
            'User-Agent': 'SFA/1.15.0 (100; sing-box 1.15.0; language zh_Hans_CN)'
        });
        expect(res.status).toBe(200);
        const json = await res.json();
        expect(tunInbound(json)).not.toHaveProperty('stack');
        expect(json.route.default_http_client).toBe('direct');
    });

    it('keeps stack for a sing-box 1.14 user-agent', async () => {
        const res = await fetchConfig('', {
            'User-Agent': 'SFA/1.14.0 (100; sing-box 1.14.0; language zh_Hans_CN)'
        });
        expect(res.status).toBe(200);
        const json = await res.json();
        expect(tunInbound(json).stack).toBe('system');
    });

    it('maps sb_ver=1.15 and sb_ver=latest to the 1.15 shape', async () => {
        for (const query of ['&sb_ver=1.15', '&sb_ver=latest']) {
            const res = await fetchConfig(query);
            expect(res.status).toBe(200);
            const json = await res.json();
            expect(tunInbound(json), `query ${query}`).not.toHaveProperty('stack');
        }
    });
});

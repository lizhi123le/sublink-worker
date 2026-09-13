import { describe, it, expect } from 'vitest';
import { SingboxConfigBuilder } from '../src/builders/SingboxConfigBuilder.js';

/**
 * sing-box types hysteria2 up_mbps/down_mbps as int, while share links carry
 * "up=100" (a string) and Clash YAML carries "200 Mbps". Both shapes used to
 * reach the outbound unchanged and made sing-box reject the whole config with
 * "cannot unmarshal string into Go struct field ...up_mbps of type int".
 */

const buildHysteria2 = async (input, tier = '1.14') => {
    const builder = new SingboxConfigBuilder(input, [], [], null, 'zh-CN', null, false, false, undefined, undefined, tier);
    const config = await builder.build();
    return config.outbounds.find(outbound => outbound.type === 'hysteria2');
};

const clashYaml = (up, down) => `proxies:
  - name: HY2
    type: hysteria2
    server: example.net
    port: 8443
    password: pw
    sni: example.net
    up: "${up}"
    down: "${down}"
`;

describe('sing-box hysteria2 bandwidth fields', () => {
    it('parses share-link up/down into integer Mbps', async () => {
        const outbound = await buildHysteria2(
            'hysteria2://pw@example.net:8443?sni=example.net&up=100&down=200&mport=20000-30000&hop-interval=30#Hy2'
        );

        expect(outbound.up_mbps).toBe(100);
        expect(outbound.down_mbps).toBe(200);
        expect(outbound).not.toHaveProperty('up');
        expect(outbound).not.toHaveProperty('down');
        expect(outbound.server_ports).toEqual(['20000:30000']);
        expect(outbound.hop_interval).toBe('30s');
    });

    it('parses the upmbps alias as a number too', async () => {
        const outbound = await buildHysteria2(
            'hysteria2://pw@example.net:8443?sni=example.net&upmbps=50&downmbps=60#Hy2'
        );

        expect(outbound.up_mbps).toBe(50);
        expect(outbound.down_mbps).toBe(60);
    });

    it('normalizes Clash bandwidth strings, including unit scaling', async () => {
        const outbound = await buildHysteria2(clashYaml('200 Mbps', '1 Gbps'));

        expect(outbound.up_mbps).toBe(200);
        expect(outbound.down_mbps).toBe(1000);
        expect(outbound).not.toHaveProperty('up');
        expect(outbound).not.toHaveProperty('down');
    });

    it('drops unparseable bandwidth values instead of emitting a string', async () => {
        const outbound = await buildHysteria2('hysteria2://pw@example.net:8443?sni=example.net&up=unlimited#Hy2');

        expect(outbound).not.toHaveProperty('up_mbps');
        expect(outbound).not.toHaveProperty('up');
    });

    it('applies the same mapping on the 1.15 tier', async () => {
        const outbound = await buildHysteria2(
            'hysteria2://pw@example.net:8443?sni=example.net&up=100&down=200#Hy2',
            '1.15'
        );

        expect(outbound.up_mbps).toBe(100);
        expect(outbound.down_mbps).toBe(200);
    });
});

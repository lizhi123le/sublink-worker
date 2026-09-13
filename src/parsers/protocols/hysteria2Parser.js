import { parseServerInfo, parseUrlParams, createTlsConfig, parseMaybeNumber, parseArray, parseBool } from '../../utils.js';

export function parseHysteria2(url) {
    const { addressPart, params, name } = parseUrlParams(url);
    let host;
    let port;
    let password = null;

    if (addressPart.includes('@')) {
        const [uuid, serverInfo] = addressPart.split('@');
        const parsed = parseServerInfo(serverInfo);
        host = parsed.host;
        port = parsed.port;
        password = decodeURIComponent(uuid);
    } else {
        const parsed = parseServerInfo(addressPart);
        host = parsed.host;
        port = parsed.port;
        password = params.auth;
    }

    // Hysteria2 requires TLS by protocol design
    if (!params.security) params.security = 'tls';
    const tls = createTlsConfig(params);
    const obfs = {};
    if (params['obfs-password']) {
        obfs.type = params.obfs;
        obfs.password = params['obfs-password'];
    }

    const hopInterval = parseMaybeNumber(params['hop-interval'] ?? params['hop_interval']);
    // sing-box types up_mbps/down_mbps as int, so the raw share-link strings
    // ("up=100") must not leak through as strings
    const up = parseMaybeNumber(params.up) ?? parseMaybeNumber(params.upmbps);
    const down = parseMaybeNumber(params.down) ?? parseMaybeNumber(params.downmbps);

    return {
        tag: name,
        type: 'hysteria2',
        server: host,
        server_port: port,
        password: password,
        tls,
        obfs: Object.keys(obfs).length > 0 ? obfs : undefined,
        auth: params.auth,
        recv_window_conn: params.recv_window_conn,
        ...(up !== undefined ? { up } : {}),
        ...(down !== undefined ? { down } : {}),
        ports: params.mport || params.ports,
        hop_interval: hopInterval,
        alpn: parseArray(params.alpn),
        fast_open: parseBool(params['fast-open'])
    };
}

/**
 * Sing-box Configuration
 * Base configuration template for Sing-box client
 */

export const SING_BOX_CONFIG = {
	dns: {
		servers: [
			{
				tag: "local",
				type: "local"
			},
			{
				tag: "hosts",
				type: "hosts",
				predefined: {
					"dns.alidns.com": ["223.5.5.5", "223.6.6.6"],
					"dns.google": ["8.8.8.8", "8.8.4.4"]
				}
			},
			{
				tag: "dns_proxy",
				type: "https",
				server: "dns.google",
				domain_resolver: "hosts",
				detour: "🚀 节点选择"
			},
			{
				tag: "dns_direct",
				type: "https",
				server: "dns.alidns.com",
				domain_resolver: "hosts"
			},
			{
				tag: "fakeip",
				type: "fakeip",
				inet4_range: "198.18.0.0/15",
				inet6_range: "fc00::/18"
			}
		],
		rules: [
			{
				rule_set: "geolocation-!cn",
				query_type: ["A", "AAAA"],
				server: "fakeip"
			},
			{
				rule_set: "geolocation-!cn",
				query_type: "CNAME",
				server: "dns_proxy"
			},
			{
				query_type: ["A", "AAAA", "CNAME"],
				invert: true,
				server: "dns_direct",
				disable_cache: true
			}
		],
		final: "dns_direct",
		strategy: "prefer_ipv4"
	},
	ntp: {
		enabled: true,
		server: 'time.apple.com',
		server_port: 123,
		interval: '30m'
	},
	inbounds: [
		{
			type: 'mixed',
			tag: 'mixed-in',
			listen: '127.0.0.1',
			listen_port: 7890
		},
		{
			type: 'tun',
			tag: 'tun-in',
			address: [
				'172.19.0.0/30',
				'fdfe:dcba:9876::0/126'
			],
			auto_route: true,
			strict_route: true,
			stack: 'system'
		}
	],
	outbounds: [
		{ type: "direct", tag: 'DIRECT' }
	],
	http_clients: [
		{
			tag: "default",
			detour: "🚀 节点选择"
		},
		{
			tag: "direct",
			detour: "DIRECT"
		}
	],
	route: {
		default_domain_resolver: "local",
		auto_detect_interface: true,
		rule_set: [
			{
				tag: "geosite-geolocation-!cn",
				type: "remote",
				format: "binary",
				url: "https://gh-proxy.com/raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/geolocation-!cn.srs"
			}
		],
		rules: []
	},
	experimental: {
		clash_api: {
			external_controller: "0.0.0.0:9090",
			external_ui: "ui",
			secret: "",
			external_ui_download_url: "https://gh-proxy.com/https://github.com/Zephyruso/zashboard/archive/refs/heads/gh-pages.zip",
			external_ui_download_detour: "DIRECT",
			default_mode: "rule"
		},
		cache_file: {
			enabled: true,
			store_fakeip: true,
			store_dns: true
		}
	}
};

export const SING_BOX_CONFIG_V1_11 = {
	dns: {
		servers: [
			{
				tag: "dns_proxy",
				address: "tls://1.1.1.1",
				detour: "🚀 节点选择"
			},
			{
				tag: "dns_direct",
				address: "https://dns.alidns.com/dns-query",
				detour: "DIRECT",
				address_resolver: "dns_resolver"
			},
			{
				tag: "dns_resolver",
				address: "223.5.5.5",
				detour: "DIRECT"
			},
			{
				tag: "dns_fakeip",
				address: "fakeip"
			}
		],
		rules: [
			{
				rule_set: "geolocation-!cn",
				query_type: [
					"A",
					"AAAA"
				],
				server: "dns_fakeip"
			},
			{
				rule_set: "geolocation-!cn",
				query_type: "CNAME",
				server: "dns_proxy"
			},
			{
				query_type: [
					"A",
					"AAAA",
					"CNAME"
				],
				invert: true,
				server: "dns_direct",
				disable_cache: true
			}
		],
		final: "dns_direct",
		strategy: "prefer_ipv4",
		independent_cache: true,
		fakeip: {
			enabled: true,
			inet4_range: "198.18.0.0/15",
			inet6_range: "fc00::/18"
		}
	},
	ntp: {
		enabled: true,
		server: 'time.apple.com',
		server_port: 123,
		interval: '30m'
	},
	inbounds: [
		{ type: 'mixed', tag: 'mixed-in', listen: '0.0.0.0', listen_port: 2080 },
		{ type: 'tun', tag: 'tun-in', address: '172.19.0.1/30', auto_route: true, strict_route: true, stack: 'mixed' }
	],
	outbounds: [
		{ type: "direct", tag: 'DIRECT' }
	],
	route: {
		"rule_set": [],
		rules: []
	},
	experimental: {
		cache_file: {
			enabled: true,
			store_fakeip: true
		}
	}
};

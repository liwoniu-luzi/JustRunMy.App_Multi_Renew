#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
proxy_handler.py -- Parse PROXY_URL (supports single or multi-nodes) and generate sing-box config.json with auto-failover

Supported protocols:
  socks5://[user:pass@]host:port
  http://[user:pass@]host:port
  https://[user:pass@]host:port
  vless://uuid@host:port?security=tls|reality&pbk=xxx&sid=yyy&type=ws&...#name
  vmess://base64EncodedJSON
  hy2://password@host:port?sni=xxx&insecure=1
  hysteria2://password@host:port?sni=xxx
  hysteria://host:port?auth=xxx&upmbps=11&downmbps=55&peer=xxx&insecure=1&alpn=h3
  hy://host:port?auth=xxx...
  trojan://password@host:port?sni=xxx
  tuic://uuid:password@host:port?sni=xxx&alpn=h3&congestion_control=bbr
  anytls://password@host:port?sni=xxx&insecure=1

Output: config.json with Mixed (HTTP/SOCKS) inbound on 127.0.0.1:8080
"""

import os
import sys
import json
import base64
from urllib.parse import urlparse, parse_qs, unquote

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 8080


# ============================================================
#  Protocol Parsers
# ============================================================

def parse_socks5(parsed, tag="proxy"):
    outbound = {
        "type": "socks",
        "tag": tag,
        "server": parsed.hostname,
        "server_port": parsed.port or 1080,
        "version": "5",
    }
    if parsed.username:
        outbound["username"] = unquote(parsed.username)
    if parsed.password:
        outbound["password"] = unquote(parsed.password)
    return outbound


def parse_http(parsed, tag="proxy"):
    outbound = {
        "type": "http",
        "tag": tag,
        "server": parsed.hostname,
        "server_port": parsed.port or 8080,
    }
    if parsed.username:
        outbound["username"] = unquote(parsed.username)
    if parsed.password:
        outbound["password"] = unquote(parsed.password)
    if parsed.scheme == "https":
        outbound["tls"] = {"enabled": True}
    return outbound


def parse_vless(parsed, params, tag="proxy"):
    outbound = {
        "type": "vless",
        "tag": tag,
        "server": parsed.hostname,
        "server_port": parsed.port or 443,
        "uuid": parsed.username,
        "packet_encoding": "xudp",
    }

    # Flow (e.g. xtls-rprx-vision)
    flow = params.get("flow", [""])[0]
    if flow:
        outbound["flow"] = flow

    # TLS / REALITY
    security = params.get("security", [""])[0]
    if security in ("tls", "reality"):
        tls = {"enabled": True}

        sni = params.get("sni", [parsed.hostname])[0]
        if sni:
            tls["server_name"] = sni

        fp = params.get("fp", ["chrome"])[0]
        if fp:
            tls["utls"] = {"enabled": True, "fingerprint": fp}

        alpn = params.get("alpn", [""])[0]
        if alpn:
            tls["alpn"] = alpn.split(",")

        insecure = params.get("insecure", params.get("allowInsecure", ["0"]))[0]
        if insecure in ("1", "true", "True"):
            tls["insecure"] = True

        if security == "reality":
            reality = {"enabled": True}
            pbk = params.get("pbk", [""])[0]
            if pbk:
                reality["public_key"] = pbk
            sid = params.get("sid", [""])[0]
            if sid:
                reality["short_id"] = sid
            tls["reality"] = reality

        outbound["tls"] = tls

    # Transport
    net_type = params.get("type", [""])[0]
    if net_type == "ws":
        transport = {"type": "ws"}
        path = params.get("path", ["/"])[0]
        if path:
            transport["path"] = unquote(path)
        host = params.get("host", [sni if 'sni' in locals() else parsed.hostname])[0]
        if host:
            transport["headers"] = {"Host": [host]}
        outbound["transport"] = transport
    elif net_type == "grpc":
        transport = {"type": "grpc"}
        sn = params.get("serviceName", [""])[0]
        if sn:
            transport["service_name"] = sn
        outbound["transport"] = transport
    elif net_type in ("http", "h2"):
        transport = {"type": "http"}
        path = params.get("path", ["/"])[0]
        if path:
            transport["path"] = unquote(path)
        host = params.get("host", [""])[0]
        if host:
            transport["host"] = [host]
        outbound["transport"] = transport

    return outbound


def parse_vmess(url_str, tag="proxy"):
    encoded = url_str[len("vmess://"):]
    pad = 4 - len(encoded) % 4
    if pad != 4:
        encoded += "=" * pad
    decoded = base64.b64decode(encoded).decode("utf-8")
    cfg = json.loads(decoded)

    outbound = {
        "type": "vmess",
        "tag": tag,
        "server": cfg.get("add", ""),
        "server_port": int(cfg.get("port", 443)),
        "uuid": cfg.get("id", ""),
        "security": cfg.get("scy", "auto"),
        "alter_id": int(cfg.get("aid", 0)),
    }

    # TLS
    if cfg.get("tls") == "tls":
        tls = {"enabled": True}
        sni = cfg.get("sni", "") or cfg.get("host", "") or cfg.get("add", "")
        if sni:
            tls["server_name"] = sni
        alpn = cfg.get("alpn", "")
        if alpn:
            tls["alpn"] = alpn.split(",")
        fp = cfg.get("fp", "chrome")
        tls["utls"] = {"enabled": True, "fingerprint": fp}
        outbound["tls"] = tls

    # Transport
    net = cfg.get("net", "tcp")
    if net == "ws":
        transport = {"type": "ws"}
        if cfg.get("path"):
            transport["path"] = cfg["path"]
        if cfg.get("host"):
            transport["headers"] = {"Host": [cfg["host"]]}
        outbound["transport"] = transport
    elif net == "grpc":
        transport = {"type": "grpc"}
        if cfg.get("path"):
            transport["service_name"] = cfg["path"]
        outbound["transport"] = transport
    elif net in ("h2", "http"):
        transport = {"type": "http"}
        if cfg.get("path"):
            transport["path"] = cfg["path"]
        if cfg.get("host"):
            transport["host"] = [cfg["host"]]
        outbound["transport"] = transport

    return outbound


def parse_hysteria(parsed, params, tag="proxy"):
    auth = params.get("auth", [""])[0] or unquote(parsed.username or "")
    peer = params.get("peer", [""])[0] or params.get("sni", [parsed.hostname])[0]
    insecure = params.get("insecure", ["0"])[0] in ("1", "true", "True")
    up_mbps = int(params.get("upmbps", [10])[0]) if params.get("upmbps") else 10
    down_mbps = int(params.get("downmbps", [50])[0]) if params.get("downmbps") else 50
    alpn = params.get("alpn", ["h3"])

    outbound = {
        "type": "hysteria",
        "tag": tag,
        "server": parsed.hostname,
        "server_port": parsed.port or 443,
        "auth_str": auth,
        "up_mbps": up_mbps,
        "down_mbps": down_mbps,
        "tls": {
            "enabled": True,
            "server_name": peer,
            "insecure": insecure,
            "alpn": alpn if isinstance(alpn, list) else [alpn]
        }
    }
    return outbound


def parse_hysteria2(parsed, params, tag="proxy"):
    outbound = {
        "type": "hysteria2",
        "tag": tag,
        "server": parsed.hostname,
        "server_port": parsed.port or 443,
        "password": unquote(parsed.username or "") or params.get("auth", [""])[0],
    }

    tls = {"enabled": True}
    sni = params.get("sni", [parsed.hostname])[0]
    if sni:
        tls["server_name"] = sni
    insecure = params.get("insecure", params.get("allowInsecure", ["0"]))[0]
    if insecure in ("1", "true", "True"):
        tls["insecure"] = True
    alpn = params.get("alpn", [""])[0]
    if alpn:
        tls["alpn"] = alpn.split(",")
    outbound["tls"] = tls

    obfs = params.get("obfs", [""])[0]
    if obfs:
        obfs_pwd = params.get("obfs-password", [""])[0]
        outbound["obfs"] = {"type": obfs, "password": obfs_pwd}

    return outbound


def parse_trojan(parsed, params, tag="proxy"):
    outbound = {
        "type": "trojan",
        "tag": tag,
        "server": parsed.hostname,
        "server_port": parsed.port or 443,
        "password": unquote(parsed.username or ""),
        "tls": {
            "enabled": True,
            "server_name": params.get("sni", [parsed.hostname])[0]
        }
    }
    return outbound


def parse_anytls(parsed, params, tag="proxy"):
    outbound = {
        "type": "anytls",
        "tag": tag,
        "server": parsed.hostname,
        "server_port": parsed.port or 443,
        "password": unquote(parsed.username or ""),
    }

    tls = {"enabled": True}
    sni = params.get("sni", [parsed.hostname])[0]
    if sni:
        tls["server_name"] = sni
    insecure = params.get("insecure", params.get("allowInsecure", ["0"]))[0]
    if insecure in ("1", "true", "True"):
        tls["insecure"] = True
    alpn = params.get("alpn", [""])[0]
    if alpn:
        tls["alpn"] = alpn.split(",")
    outbound["tls"] = tls

    return outbound


def parse_tuic(parsed, params, tag="proxy"):
    outbound = {
        "type": "tuic",
        "tag": tag,
        "server": parsed.hostname,
        "server_port": parsed.port or 443,
        "uuid": "",
        "password": "",
        "congestion_control": params.get("congestion_control", ["bbr"])[0],
    }

    user_part = unquote(parsed.username or "")
    pass_part = unquote(parsed.password or "")

    if ":" in user_part and not pass_part:
        outbound["uuid"], outbound["password"] = user_part.split(":", 1)
    else:
        outbound["uuid"] = user_part
        outbound["password"] = pass_part

    tls = {"enabled": True}
    sni = params.get("sni", [parsed.hostname])[0]
    if sni:
        tls["server_name"] = sni
    insecure = params.get("insecure", params.get("allowInsecure", ["0"]))[0]
    if insecure in ("1", "true", "True"):
        tls["insecure"] = True
    alpn = params.get("alpn", [""])[0]
    if alpn:
        tls["alpn"] = alpn.split(",")
    outbound["tls"] = tls

    return outbound


def parse_single_uri(uri, tag="proxy"):
    uri = uri.strip()
    if not uri:
        return None
    
    if uri.startswith("ulink://"):
        parsed = urlparse(uri)
        qs = parse_qs(parsed.query)
        b64 = qs.get("content", [""])[0]
        raw = base64.b64decode(b64).decode("utf-8")
        data = json.loads(raw)
        ob = data[0] if isinstance(data, list) else data
        ob["tag"] = tag
        return ob
    
    if uri.startswith("{") or uri.startswith("["):
        data = json.loads(uri)
        ob = data[0] if isinstance(data, list) else data
        ob["tag"] = tag
        return ob

    scheme = uri.split("://")[0].lower()
    if scheme == "vmess":
        return parse_vmess(uri, tag)

    parsed = urlparse(uri)
    params = parse_qs(parsed.query)

    if scheme in ("socks5", "socks"):
        return parse_socks5(parsed, tag)
    elif scheme in ("http", "https"):
        return parse_http(parsed, tag)
    elif scheme == "vless":
        return parse_vless(parsed, params, tag)
    elif scheme in ("hy", "hysteria"):
        return parse_hysteria(parsed, params, tag)
    elif scheme in ("hy2", "hysteria2"):
        return parse_hysteria2(parsed, params, tag)
    elif scheme == "trojan":
        return parse_trojan(parsed, params, tag)
    elif scheme == "tuic":
        return parse_tuic(parsed, params, tag)
    elif scheme == "anytls":
        return parse_anytls(parsed, params, tag)
    else:
        print(f"⚠️ 未知或暂不支持的协议格式: {scheme}", file=sys.stderr)
        return None


# ============================================================
#  Main
# ============================================================

def main():
    proxy_url_env = os.environ.get("PROXY_URL", "").strip()
    if not proxy_url_env:
        print("PROXY_URL is empty, skipping sing-box config generation.")
        sys.exit(0)

    # 支持多行、逗号或竖线分隔多个节点
    raw_links = [l.strip() for l in proxy_url_env.replace(",", "\n").replace("|", "\n").split("\n") if l.strip()]
    
    parsed_outbounds = []
    for idx, link in enumerate(raw_links):
        node_tag = f"node_{idx+1}"
        ob = parse_single_uri(link, node_tag)
        if ob:
            parsed_outbounds.append(ob)

    if not parsed_outbounds:
        print("❌ 无法解析任何有效代理节点！", file=sys.stderr)
        sys.exit(1)

    all_outbounds = []
    tag_list = [ob["tag"] for ob in parsed_outbounds]

    # 多节点自动开启 URL-Test 自动故障转移
    if len(parsed_outbounds) > 1:
        urltest_group = {
            "type": "urltest",
            "tag": "auto_fallback",
            "outbounds": tag_list,
            "url": "https://www.gstatic.com/generate_204",
            "interval": "1m",
            "tolerance": 50
        }
        all_outbounds.append(urltest_group)
        all_outbounds.extend(parsed_outbounds)
        default_outbound_tag = "auto_fallback"
    else:
        all_outbounds.extend(parsed_outbounds)
        default_outbound_tag = tag_list[0]

    all_outbounds.append({"type": "direct", "tag": "direct"})

    config = {
        "log": {"level": "warn", "timestamp": True},
        "dns": {
            "servers": [
                {
                    "tag": "dns-direct",
                    "address": "https://1.1.1.1/dns-query",
                    "detour": "direct"
                }
            ]
        },
        "inbounds": [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": LISTEN_HOST,
                "listen_port": LISTEN_PORT,
            }
        ],
        "outbounds": all_outbounds,
        "route": {
            "final": default_outbound_tag
        }
    }

    with open("config.json", "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)

    print(f"✅ sing-box config.json 生成成功！已挂载 {len(parsed_outbounds)} 个节点并开启自动故障转移（URL-Test）。")
    print(f"  本地监听: mixed://{LISTEN_HOST}:{LISTEN_PORT}")
    print(f"  出站策略: {default_outbound_tag} ({', '.join(tag_list)})")


if __name__ == "__main__":
    main()

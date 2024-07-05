---
icon: material/new-box
---

!!! quote "sing-box 1.9.0 中的更改"

    :material-plus: [client_subnet](#client_subnet)

# DNS

### 结构

```json
{
  "dns": {
    "servers": [],
    "rules": [],
    "final": "",
    "strategy": "",
    "disable_cache": false,
    "disable_expire": false,
    "independent_cache": false,
    "lazy_cache": false,
    "reverse_mapping": false,
    "mapping_override": false,
    "client_subnet": "",
    "fakeip": {},
    "hosts": {
      "www.abc.com": "www.bcd.com",
      "www.def.com": [
        "127.0.0.1",
        "fe80::"
      ]
    }
  }
}

```

### 字段

| 键        | 格式                      |
|----------|-------------------------|
| `server` | 一组 [DNS 服务器](./server/) |
| `rules`  | 一组 [DNS 规则](./rule/)    |

#### final

默认 DNS 服务器的标签。

默认使用第一个服务器。

#### strategy

默认解析域名策略。

可选值: `prefer_ipv4` `prefer_ipv6` `ipv4_only` `ipv6_only`。

如果设置了 `server.strategy`，则不生效。

#### disable_cache

禁用 DNS 缓存。

#### disable_expire

禁用 DNS 缓存过期。

#### independent_cache

使每个 DNS 服务器的缓存独立，以满足特殊目的。如果启用，将轻微降低性能。

#### lazy_cache

当缓存查询命中一个已过期的 DNS 回应缓存时，立即返回一个 TTL 为 0 的 DNS 回应，并同时进行 DNS 查询。

#### reverse_mapping

在响应 DNS 查询后存储 IP 地址的反向映射以为路由目的提供域名。

由于此过程依赖于应用程序在发出请求之前解析域名的行为，因此在 macOS 等 DNS 由系统代理和缓存的环境中可能会出现问题。

#### mapping_override

使用存储的 IP 地址的反向映射的域名覆盖连接目标地址。

依赖 `reverse_mapping` 开启。

#### client_subnet

!!! question "自 sing-box 1.9.0 起"

默认情况下，将带有指定 IP 前缀的 `edns0-subnet` OPT 附加记录附加到每个查询。

如果值是 IP 地址而不是前缀，则会自动附加 `/32` 或 `/128`。

可以被 `servers.[].client_subnet` 或 `rules.[].client_subnet` 覆盖。

#### fakeip

[FakeIP](./fakeip/) 设置。

#### hosts

!!! note ""

    当内容只有一项时，可以忽略 JSON 数组 [] 标签

设置私有 DNS 记录，支持 CNAME/A/AAAA 类型。

CNAME 类型记录仅可被单独使用。

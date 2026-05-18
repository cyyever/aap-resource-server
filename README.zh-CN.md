# Open Agent Auth — AAP fork baseline

本仓库是被裁剪为 **Agent Auth Protocol (AAP)** fork 的上游基线。

- Spec:[`cyyever/authentication_plan`](https://github.com/cyyever/authentication_plan) — 单文件 `agent_auth_protocol.tex`
- 范围:仅认证(authentication-only),单算法 **Ed25519 + SHA-512**(`alg=EdDSA`),两条线协议 — CT(委托)+ DPoP(每请求),JWS compact 序列化,仅 HTTPS。
- 不包含:授权(authorization)、同意 UI、CA / X.509、OAuth 2.0 / OIDC 流程、W3C VC。

README 将在 M1 patches(~250 LoC:`alg` 锁定、DPoP 模块、PIC 级联吊销、CRL 防回滚、JSONL 错误事件、header 白名单)落地后重写。原上游内容已删除,因为它描述的特性(5-layer validator、AOA、MCP adapter、同意页等)已被 AAP trim 删除。

采用 Apache License 2.0 — 见 [LICENSE](LICENSE)。

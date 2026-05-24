# Open Agent Auth — AAP fork baseline

本仓库是被裁剪为 **Agent Auth Protocol (AAP)** fork 的上游基线。

- Spec:[`cyyever/authentication_plan`](https://github.com/cyyever/authentication_plan) — 单文件 `agent_auth_protocol.tex`
- 范围:仅认证(authentication-only),单算法 **Ed25519 + SHA-512**(`alg=EdDSA`),两条线协议 — CT(委托)+ DPoP(每请求),JWS compact 序列化,仅 HTTPS。
- 不包含:授权(authorization)、同意 UI、CA / X.509、OAuth 2.0 / OIDC 流程、W3C VC。

## 模块

单 Maven 模块 `open-agent-auth-core`:协议原语(JWS 签验、密钥管理、
JWKS 提供端、信任根、WIT/WPT — M1 改名为 CT/DPoP)+ server 侧 actor
(`ResourceServer`、`DefaultResourceServer`、请求/结果模型)位于
`com.alibaba.openagentauth.core.server.*` 包。纯 Java,无 Spring。

模块需要 **Java 21 LTS**(或更高版本)。直接依赖只有
[Nimbus JOSE+JWT](https://connect2id.com/products/nimbus-jose-jwt)、
Jackson 和 SLF4J。Spring Boot 已经移除 —— Spring Boot 应用、Quarkus、
Helidon、plain `main` 等消费方自己用 ~20 行装配 `WitValidator` +
`WptValidator` + `DefaultResourceServer` 即可。

## 状态

- Trim 阶段完成(从 `c8f7c95` 到当前 `HEAD` 一系列 commit)
- **M1 retrofit 待办**:~250 LoC patches — 锁定 `alg=EdDSA`、严格
  JOSE header 白名单、DPoP 模块、PIC 级联吊销、CRL 防回滚、JSONL
  错误事件。
- README、包路径(`core.protocol.wimse.*`)、类名(`WIT`、`WPT`)
  会在 M1 改成 spec 用词(`CT`、`DPoP`)。

采用 Apache License 2.0 — 见 [LICENSE](LICENSE)。

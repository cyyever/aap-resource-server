# AAP Resource Server (Java)

[Agent Auth Protocol](https://github.com/cyyever/authentication_plan)
(AAP) **resource-server(RP) 端**的 Java 参考实现。解析并验证两条线协
议(CT 委托、DPoP 每请求),根据配置的信任域 + JWKS 进行校验,以类型化
的 [`TokenValidationResult`](aap-resource-server-core/src/main/java/ai/shao/aap/rs/core/token/common/TokenValidationResult.java)
ADT 返回结果 —— `Success<T>` 或 `Failure<String>`。

spec 以 git submodule 的形式 vendored 于 `spec/`;spec PR 提交到 spec
repo,而不是这里。

## 范围

- 单算法:**Ed25519 + SHA-512**(`alg=EdDSA`)。其他一律以 `MALFORMED`
  拒绝。
- 两条线协议:**CT**(委托,由 `sk_P` 签发)+ **DPoP**(每请求,由
  `sk_S` 签发)。JWS compact 序列化。
- JOSE header 白名单:仅 `{alg, typ}`(DPoP 额外允许 `jwk`)。
- 仅 HTTPS。**不包含**:授权(AuthZ)、同意 UI、CA / X.509、OAuth 2.0
  / OIDC、W3C VC。

## 模块

单 Maven 模块 `aap-resource-server-core`,根包 `ai.shao.aap.rs.core.*`。
纯 Java 21。直接依赖只有 Nimbus JOSE+JWT、Jackson、SLF4J、JSpecify。
无 Spring —— 消费方(Spring Boot 应用、Quarkus、Helidon、plain `main`)
用 ~20 行自己装配 `CtValidator` + `DpopValidator` +
`DefaultResourceServer` 即可。

## 构建 / 质量门禁

```bash
mvn -B test                     # 单元测试(293 / 293)
mvn -P errorprone clean compile # Error Prone + NullAway @ ERROR,0 项
mvn -P spotbugs verify          # SpotBugs + FindSecBugs,0 项
mvn -P format spotless:apply    # google-java-format AOSP,就地改写
mvn -P coverage verify          # JaCoCo 报告位于 target/site/jacoco/
```

CI 在每次 push / PR 上跑这四个 lint/test profile,以及 CodeQL
(`security-extended`)和 dependency-review。最低需要 Java 21 LTS。

## 状态

- **M1 #1–#3 已落**:`alg=EdDSA` 锁定、JOSE header 白名单、CT/DPoP 包
  名 + 类名 rename(`core.protocol.{ct,dpop}`、`CredentialToken`、
  `DpopToken`)。
- **M1 收尾待办**(在 spec v0.9.4/v0.9.5 重新评估后约 ~330–390 LoC):
  DPoP 声明字段(`htm`/`htu`/`iat`/`jti`/`ath`)、registry keyset + 信
  任集 + trial-verify、CRL 拉取 + 防回滚 + 级联、PIC 拉取、运维侧
  `pk_R` 黑名单、JSONL 错误事件、HTTP header 白名单执行器。

采用 Apache License 2.0 — 见 [LICENSE](LICENSE)。

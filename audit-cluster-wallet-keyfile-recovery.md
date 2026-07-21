## Cluster: 钱包/密钥文件/恢复 (Wallet / Keyfile / Recovery)

审计范围:docs/proofs/ 下 12 篇文档。所有代码对照均在当前脏树(src/main.cpp、src/rpc/rpc.cpp、src/node/node.cpp、include/determ/node/node.hpp 已修改)上本轮重新核实。

### Per-document verdicts

**1. S004KeyfileAtRest.md — SOUND-WITH-GAPS**
核心 AEAD/AAD 论证与 fail-closed 逻辑在当前代码中仍然成立(envelope.cpp:141 AAD 前置条件、:165 tag 失败 → nullopt;wallet/main.cpp:3894 AAD=utf8(header_pubkey_hex)、:3896-3900 解密失败与错误口令同一诊断 exit 2)。但 T-3 数值示例自相矛盾:Q 定义为"trial decryption 次数"而指数却含 log2(iter),H_pw=40、Q=2^60 处给出 "≈0.43",与其自身 L-1 "一小时内可暴力破解"的结论冲突(按其公式自洽答案 ≈1)。假设标签 A8 在引言("RNG axioms")与 §4("passphrase entropy")之间一词两义,且 A7/A8 不在 F0 规范假设表(Preliminaries §2.1 仅 A1-A4+A6)内;文中 OpenSSL EVP/CRYPTO_memcmp 实现前提已随 2026-07-03 C99 后端切换过时(envelope.cpp 头注 1c)。全部 wallet/main.cpp 行号引用漂移(引用 2981-3186/3239-3483/4497-4622,实际 cmd_keyfile_decrypt 在 3769-4013)。

**2. S005PassphraseKeyfile.md — SOUND-WITH-GAPS**
创建/轮换/检查的生命周期不变量论证结构完整,T-1/T-2 的种子往返与身份保持逻辑与代码一致。F-1(keyfile-recover 的 --threshold 为可选)已获代码确认:wallet/main.cpp:5250-5257 的前置检查允许缺省,:5290 走空 AAD 解密,usage 文本自己承认欠阈值时静默产出垃圾秘密——该隐患至今未修。L-3 声称 share_index 映射提供 AAD 绑定不成立:索引是明文元数据,无密码学绑定(security-by-obscurity)。全部行号引用漂移(引用 3566-4003 等;实际 keyfile_rotate 4093、keyfile_recover 5001-5360、account_recover 5458-5577)。

**3. EnvelopeKeyfileCrypto.md — SOUND-WITH-GAPS**
KE-1..KE-4 是本簇最细致的原语层分析,KE-2 的 GHASH ε-AXU 完整性论证与 fail-closed nullopt(envelope.cpp:165)一致。但 KE-1 与 S004 T-3 共享 Q 量纲含糊:Q 在"试错解密次数"与"原始 HMAC 运算数"两种读法下界相差约 log2(iter)≈19.2 bit。文内自创 (C1)-(C4) 局部假设标签,与 F0 规范 A 表不对齐;"RAND_bytes salt"/"sodium_memzero" 等后端引用已过时(现为 determ_rng_bytes/determ_secure_zero,envelope.cpp:77-83 及头注 1c)。R58 banner 对其 PBKDF2 时代范围的声明是诚实的。

**4. KeyfileArgon2Migration.md — SOUND**
本簇质量最高的文档。KM-1 的 AEAD 腿字节一致论断经逐行核实:DWE1/DWE2 共用 seal 路径(envelope.cpp:64-75,:74 清零密钥),encrypt_argon2id :87-106 与 encrypt_pbkdf2 :108-124 仅在 KDF 上分叉,默认 = Argon2id(:126-131)。KM-3 的 magic 路由(decrypt :144-152)与 KM-4 的参数守卫(deserialize :251-262,DWE2 params==12 且 t≠0/p≠0/m≥8p,DWE1 iters≠0)与当前代码逐行吻合,所有行号引用精确命中。KM-2 刻意只给定性内存硬度下界、KM-5 明确列出非声明(Argon2id 数据相关 passes 非常数时间),均诚实无过度声称。

**5. AtRestKdfMigrationCoverage.md — SOUND**
作为覆盖图(无新定理,自我定位准确),其生命周期各阶段 KDF 归属声明抽查属实:创建路径默认 Argon2id(envelope.cpp:126-131);daemon 读回确经 envelope::decrypt 自动识别 KDF(src/main.cpp:5555,注释 :5389-5396 确认 DWE2 默认 + DWE1 兼容;文档引用 :5119/:5125 已漂移)。keyfile-info 引用 :5930-6068 与实际 :5945 起基本吻合。残余声明(pre-R58 DWE1 文件在 reencrypt 前保持 PBKDF2;`envelope encrypt --iters` 互操作路径仍为 DWE1)诚实。

**6. WalletRecovery.md (FA12) — SOUND-WITH-GAPS**
T-15(Shamir GF(2^8) 重构)论证完整,与 shamir.cpp 实现一致(:55-60 输入校验、:92-101 边界拒绝、gf_mul :14-25、gf_inv :29-39)。T-16 在前提中列入 A1(Ed25519 EUF-CMA)但证明体从未使用——死前提。T-17 的 Q/KDF_cost 量纲同样含糊,虽正文澄清按"原始 HMAC 运算"计。机制描述已过时:默认 KDF 自 R58 起为 Argon2id 而文档仍以 PBKDF2 为默认。OPAQUE 退出本身诚实,但留下了跨文档引用废墟(见 Composition gaps 第 3 条)。

**7. WalletRecoveryFlows.md — SOUND-WITH-GAPS**
全簇唯一行号引用仍精确的文档(shamir.cpp :55-60/:80/:92-101 全部命中)。但其引用的 FA12 "T-17 OPAQUE substitution invariance、T-18 composite" 在 WalletRecovery.md 删除 OPAQUE 后已不存在——跨文档定理编号断裂。T-2/T-3 的恢复流分析未区分两条恢复路径:DWR1 AAD 绑定路径(recovery.cpp:43-51/:86/:91,含 c_pub 校验 :56-60,恢复时跳过失败槽 :113)与 backup-create 的空 AAD 路径(main.cpp:3293/:5290)完整性姿态不同,文档只覆盖了前者。

**8. MakeContribCommitmentBackwardCompat.md — SOUND-WITH-GAPS**
核心结构经代码核实属实:any_view 短路 + "DTM-F2-v1" 域分隔标签就在 producer.cpp:272-288,T-1(v1 字节一致)与 T-2(重放隔离)对 v1↔F2 二分仍然成立。但函数签名已扩到 9 个参数(新增 proposer_time :253、view_shardtip_root :254),并追加了两条文档写作时不存在的条件尾段:"DTM-TS-v1"(:295-298,S-030-D2)与 "DTM-STV-v1"(:306-309,D3.5d)。L-3 的"104 vs 209 字节"长度论证因此过时——扩展路径现有 209/226/251/268 四种长度;长度不相交结论仍然幸存(v1=104 不等于任何扩展长度,且每条尾段自带分隔符),但新尾段之间/与 F2 后缀的交叉歧义未经分析。TLA 伴侣 FB24 的引用(producer.cpp:219-260)亦已漂移。

**9. WireFormatBackwardCompat.md — SOUND-WITH-GAPS**
T-1(zero-skip 字节一致)与 T-3(组合)结构正确;genesis 哈希混合的 zero-skip 用法(committee_region genesis.cpp:458-461、genesis_message :472-475、governance :481-487、suspension/unstake :491-494、merge thresholds :497-503、CT/profile/shard-regions :512-539、ops-v1 无条件块 :556-568)与文档模式描述一致。但 T-2 证明含事实性错误断言"四个已发布实例均无长度可变面"——signing_bytes 含可变长 tx 列表、genesis 含可变长条件分支;真正需要的性质(序列化单射性/无歧义性)未被证明,双解码歧义问题形式上仍然开放。"四个已发布实例"清单也已过时:block.cpp 现有 partner_subset_hash :406、state_root :422、signature_form :432-433、eligible_count :437、shard_tip_records_root :462 五处,外加 producer.cpp 的两条新条件尾段。

**10. SchemaDiscriminatorsImpl.md — OPEN**
文档自我状态描述内部矛盾:§10 称 "Implementation. Pending.",§2.2 却称 "SHIPPED commit 9093189"——后者为真(block.hpp:240-244 SIG_FORM_* 枚举、:661 signature_form 字段、block.cpp:432-433 零跳过 + :647-650 to_json 均存在);§9.3 标 "Open" 而 §4.5 标 "RESOLVED 2026-07-03"。其技术内容(fail-closed 未知值规则、地址推导不绑定鉴别器的 §4 发现)仍有价值,但开放问题清单与实施状态已不可信,须以代码为准重估。判 OPEN:文档自身不一致,无法判 SOUND。

**11. ReservedDiscriminatorAudit.md — EMPIRICAL-ONLY**
流程审计/决策登记而非密码学证明,KEEP/DROP 结论属治理记录。其可核查声明多数在当前代码中成立:§6.1.1 的 binary_codec 保留字节修复已落地(binary_codec.cpp:373-374 拒绝非零 offset-3;:271-273 tx-frame 保留 u64 零强制;:224/:315 编码侧置零);§6.2(v2_7_f2_active_from_height 未被 from_json 解析——genesis.cpp 全文零命中,字段仅有 genesis.hpp:244 默认值,活读者 node.cpp:209,UINT64_MAX 哨兵经配置文件不可达)与 §6.3(inclusion_model 在 to_json :81 发出、from_json :194 解析,但不在 :556-568 的 ops-v1 哈希混合块内)均经核实为真且至今未修。但序言中"已验证 src/+include/ 零 signature_form 命中"的声明现已为假(block.hpp:661、block.cpp:432-433)——grep 型"已验证"声明随树漂移腐烂的典型例证。

**12. OperatorToolingReadOnly.md — EMPIRICAL-ONLY**
诚实的枚举式调查,论证是穷举而非归约,天然不可"证明"。OT-1 的核心——6 个 mutating 端点集合 {send, stake, unstake, register, submit_tx, submit_equivocation}——与 rpc.cpp:215-299 的 dispatch 逐一核对精确无误。但 "~20-method READ set" 已松动:当前 dispatch 有 29 个方法(23 读 + 6 写),另有带外 dapp_subscribe 连接接管路径(rpc.cpp:189-200,不改链状态但不在 dispatch 枚举内);91 个脚本家族计数本轮未复核。结论方向可信,数值随树漂移。

### Assumption consistency findings

- F0 规范假设表(Preliminaries §2.1)只定义 A1 Ed25519 EUF-CMA、A2 SHA-256 CR、A3 preimage、A4 CSPRNG、A6 HMAC-PRF。S004 的 A7(constant-time 实现)/A8 不在表内,且 A8 在同一文档内一词两义(引言 "RNG axioms" vs §4 "passphrase entropy";F0 的 RNG 假设编号是 A4)。EnvelopeKeyfileCrypto 自创 (C1)-(C4) 局部标签。各文档假设标签未对齐 F0,跨文档引用时需逐条还原语义。
- 三处共享同一 Q 量纲缺陷:S004 T-3、EnvelopeKeyfileCrypto KE-1、WalletRecovery T-17。界 Pr ≤ Q·2^-(H_pw+log2(iter)) 只有在 Q 按"原始 HMAC/KDF 运算数"计时才成立;按"试错解密次数"读则低估攻击者优势约 log2(600000)≈19.2 bit。S004 的数值示例(H_pw=40、Q=2^60 → "≈0.43")内部不自洽(与 L-1 "一小时破解"矛盾;自洽答案 ≈1)。
- A1 死前提:WalletRecovery T-16 列入 A1 但证明体未使用。
- 实现层假设整体迁移:2026-07-03 OpenSSL→in-tree C99 切换(envelope.cpp 头注 1c;src/crypto/keys.cpp:4-16;wallet/main.cpp:49-53 的 ed25519 shim)使所有引用 EVP/CRYPTO_memcmp/RAND_bytes/sodium_memzero 的"常数时间比较/安全擦除"前提改挂到 determ_* C99 原语上;后者主要由测试向量与 CRYPTO-C99-SPEC 12/12 网格经验支撑(簇外的 C99CryptoStackAudit 提供部分缓解:0 Critical/0 High,18 项已修复)。
- Argon2id 非常数时间:KeyfileArgon2Migration KM-5 已诚实声明(数据相关 passes);凡引用 Argon2id 的文档均需附带此非声明。

### Code cross-reference spot checks

本轮在当前脏树上逐项核实的对照(抽查,非穷举):

| 文档声明 | 代码现状 | 结论 |
|---|---|---|
| envelope MAGIC/解密路由/参数守卫(KM-3/KM-4) | envelope.cpp:25-26/:133-167/:230-274 | 精确命中 |
| 新信封默认 Argon2id | envelope.cpp:126-131 | 属实 |
| PBKDF2 iters=600,000;Argon2 t=3/m=65536/p=1;salt=16 | envelope.hpp:56/:64-66/:70(旧文档引 :46,值正确行漂移) | 属实 |
| AAD 前置 + tag 失败 fail-closed | envelope.cpp:141/:165 | 属实 |
| keyfile-decrypt:header 校验、AAD=pubkey_hex、失败统一 exit 2、私种不上 stdout、0600 | wallet/main.cpp:3822-3829/:3894/:3896-3900/:3953-3959/:4000-4011/:3989-3998 | 属实(S004/S005/Envelope 行号引用整体漂移 400-800 行) |
| keyfile-recover --threshold 可选(S005 F-1) | main.cpp:5250-5257;usage 自认欠阈值静默垃圾 | 属实,未修 |
| backup-create 空 AAD + 每 keyholder 口令;keyfile-recover 空 AAD | main.cpp:3293/:5290 | 属实(两恢复路径姿态分歧) |
| DWR1 AAD 绑定 + c_pub 校验 + 失败槽跳过 | recovery.cpp:43-51/:56-60/:86/:91/:113 | 属实 |
| Shamir 校验/随机系数/边界拒绝 | shamir.cpp:55-60/:80/:92-101(:80 现为 determ_rng_bytes,文档写 RAND_bytes) | 结构属实,后端引用漂移 |
| make_contrib_commitment any_view + DTM-F2-v1 | producer.cpp:272-288 | 属实;但已 9 参,新增 TS/STV 尾段 :295-309,长度数字过时 |
| block zero-skip 实例 | block.cpp:406/:422/:432-433(+:647-650)/:437/:462 | "signature_form 零命中"为假;实例 >4,清单过时 |
| genesis 哈希混合模式 | genesis.cpp:453-568 | 属实(行号漂移) |
| §6.2:v2_7_f2_active_from_height 不可由 genesis JSON 设置 | genesis.cpp 零命中;genesis.hpp:244 默认;node.cpp:209 读取 | 属实,未修 |
| §6.3:inclusion_model 不入 genesis 哈希混合 | 发出 :81、解析 :194、混合块 :556-568 无此字段 | 属实,未修 |
| binary_codec 保留字节 fail-closed(W-1 修复 + W-2) | binary_codec.cpp:373-374/:271-273/:224/:315 | 属实 |
| 6 个 mutating RPC 端点 | rpc.cpp:215-299(29 方法:23 读 6 写;带外 dapp_subscribe :189-200) | 集合精确;READ 计数过时 |
| daemon 读回 DWE2 keyfile | src/main.cpp:5555(注释 :5389-5396;文档引 :5119/:5125 漂移) | 属实 |
| save_node_key 形状 | src/crypto/keys.cpp:42-50(pubkey+priv_seed hex JSON) | 属实 |

### Composition gaps

- **MAJOR — 实现前提整体漂移(OpenSSL→C99,2026-07-03)**:S004/S005/EnvelopeKeyfileCrypto/WalletRecovery(Flows) 的实现层前提(EVP、CRYPTO_memcmp、RAND_bytes、sodium_memzero、OpenSSL 常数时间)全部改挂到 in-tree determ_* C99 原语。证明的数学骨架不受影响(黑盒归约层面),但"常数时间 tag 比较""安全擦除"等实现性引理现仅由经验测试与簇外的 C99CryptoStackAudit 支撑,四篇文档均未补注。
- **MAJOR — 两条恢复路径完整性姿态分歧,且无文档分析**:DWR1 路径 AAD 绑定 + 公钥校验(recovery.cpp),backup-create/keyfile-recover 路径空 AAD、account-recover 有 --threshold 硬检查(:5487)但无公钥校验。口令复用 + 备份集掉包下,空 AAD 路径会静默恢复出错误秘密(usage 文本自认)。S005 L-3 "share_index 提供 AAD 绑定"的声称不成立(明文索引,security-by-obscurity)。
- **MAJOR — FA12 定理编号跨文档断裂**:WalletRecoveryFlows 引用 FA12 "T-17(OPAQUE 替换不变性)/T-18(组合)",但 WalletRecovery.md 删除 OPAQUE 后这些编号已不存在;Preliminaries §12 仍称 "OPAQUE adapter",README :35/:199 行仍宣传 OPAQUE 组合。沿 README/flows 追溯的读者会得到幻影定理。
- **MINOR — Q 量纲缺陷跨三文档共享**(S004 T-3 / EnvelopeKeyfileCrypto KE-1 / WalletRecovery T-17):最坏读法下界松约 19.2 bit;S004 数值示例内部矛盾。
- **MINOR — 假设标签体系混乱**:A8 一词两义、A7/A8 不在 F0 表、局部 (C1)-(C4) 标签与 F0 正交。
- **MINOR — 系统性行号漂移**:所有 R58 前文档的 wallet/main.cpp 引用漂移 400-1000 行(实际:decrypt 3769-4013、recover 5001-5360、account-recover 5458-5577、info 5945);producer.cpp 引用(219-260 → 247-311,含 FB24 TLA)、block.cpp zero-skip 引用(329-334 → 406 等)、genesis.cpp 引用均漂移。WalletRecoveryFlows 是唯一幸免者。
- **NOTE — 遗留小问题**:genesis 配置缺口(§6.2/§6.3,已核实仍未修:激活高度不可经 JSON 配置 + inclusion_model 不入链身份);S-039 未绑定 genesis 字段被显式 deferred;main.cpp:3884 仍报 "not a valid DWE1 serialization"(DWE2 已存在);WireFormatBackwardCompat T-2 的序列化单射性未证(双解码歧义形式开放);S004 T-4 的 A_online 未计并行 spawn;FB24 TLA 引用漂移。

### Cluster bottom line

无 CRITICAL。密码学核心——envelope AEAD 构造、Argon2id 迁移(KM 系列)、Shamir 算术、fail-closed 参数校验——经当前代码逐行抽查成立;KeyfileArgon2Migration 达到可作全库范本的严谨度。但证明语料正在对一棵快速变动的树腐烂:后端切换使四篇文档的实现前提过时、跨文档定理编号断裂产生幻影引用、行号系统性漂移。另有两处真实的未分析安全面——空 AAD 恢复路径的静默误恢复(口令复用 + 备份掉包场景),以及 v2_7_f2_active_from_height 不可配置 + inclusion_model 不入 genesis 哈希——属于设计/集成缺口而非证明错误,至今未修。**整簇判 SOUND-WITH-GAPS**:可依赖其数学骨架,不可依赖其实现脚注与交叉引用。

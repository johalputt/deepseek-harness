# Agent Note: 已发布依赖与提交历史的定期安全流水线

Status: implemented

[English](2026-08-25-security-pipeline.md) | 中文

## 问题

仓库的 CI（`ci.yml`）在每个 pull request 上验证行为，但没有任何常设扫描覆盖三类测试抓不到的风险：已合并依赖新公布的漏洞（周一发布的 CVE 永远不会让一个绿色的分支变红）、在有人察觉之前就进入 git 历史的密钥，以及跨文件数据流缺陷（注入、SSRF 形态的数据流、不安全的反序列化）——按包划分的单测在结构上无法端到端看到它们。覆盖率分区、lockfile 钉扎和凭证卫生降低了暴露面，但都检测不了这三类问题。

## 决策

独立的 `.github/workflows/security.yml` 承担持续安全扫描，刻意与 `ci.yml` 分离，使 pull-request 检查面板保持纯行为性（遵循 `.github` 组合规则：非 PR 任务不进 PR 圆圈）：

1. **CodeQL**（`javascript-typescript`）分析安装后的工作区依赖图——先 install 后分析，让类型感知查询能解析 workspace 导入——并把 SARIF 上传到 code scanning。每周定时加 push/PR 触发。
2. **gitleaks** 在每次触发时扫描完整历史；从 HEAD 清除的密钥仍会经由更早的提交泄露。
3. **`pnpm audit --prod --audit-level high`** 直接基于已提交的 lockfile 审计生产依赖图（无需 install），被审计的工件就是实际发布的内容。

该工作流运行在 `ubuntu-latest` 而非本仓库以 Windows 优先的 runner 机群上：这里的每个任务都是平台无关的静态分析，没有待验证的产品行为；`ubuntu-latest` 让流水线在任何缺少部署专属自托管池与 failover 变量的 fork 上都能工作。

阈值理由：审计门槛取 `high`，因为 moderate 级别的生态公告噪音积累太快，撑不起合并门禁；会被人关掉的门禁不是门禁。仅限生产范围让开发期工具的公告留在 PR 评审中可见，而不阻塞发布。

## 备选方案考量

**为什么不把这些任务并进 `ci.yml`？** `.github` 组合规则把 master-only 泳道挡在 `ci.yml` 之外，正是为了让 PR 检查圆圈只显示 PR 应当把关的内容。安全扫描有不同的触发面（每周 cron、全历史）和不同的失败语义（由公告驱动，有时靠一次版本升级而非代码修改来修复）；并进单文件要么让 cron 任务出现在每个 PR 面板里，要么让触发条件在同一文件里变得混乱。

**为什么不只靠 Dependabot alerts？** Dependabot 在清单视图中标记易受攻击的*解析结果*，但不给合并设置门禁、不扫描历史泄露的密钥、也不做数据流分析。本流水线与 Dependabot（已在运行）互补而非替代。

**为什么不取 `--audit-level moderate` 更严格？** 严格审计下 JavaScript 生态会产生足够多 moderate 公告（常见为不可达路径或争议报告），几周内这个任务就会被关闭。high 以上加生产范围，才是本仓库能够永远大声失败的可持续水平。

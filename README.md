# 报警日志网关 · 双采集进程入仓演示

模拟工厂网关把 JSONL 报警日志（设备号 / UTC 时间 / 报警码）写入共享目录，
两个独立采集进程持续把日志入仓到同一个 SQLite 检索库，并通过网页控制网关、
观察采集结果。重点演示**改名轮转、旧文件补写、并发采集、进程中断重启**下
**不漏行、不重复**。

## 一、组件

| 组件 | 文件 | 职责 |
|---|---|---|
| 网页服务 | `app/main.py` | FastAPI：网关控制 + 入仓结果查询 + 单页控制台 |
| 网关模拟器 | `app/gateway.py` | 追加 JSONL、写半行、**仅改名轮转**（不删除/不截断，最多 3 件）、旧文件补写 |
| 采集器 | `app/collector.py` | 扫描共享目录，按文件身份与字节位点精确入仓（每个容器跑一个进程，共两个） |
| 存储层 | `app/db.py` | SQLite（WAL），表结构、事务与并发连接 |
| 配置 | `app/config.py` | 全部参数走环境变量 |

## 二、怎么保证不漏、不重

1. **文件身份与改名无关。** 用 `(st_dev, st_ino)` 生成 `file_id`。网关把
   `alarms.jsonl` 改名为 `alarms.1.jsonl` 并新建同名空文件后，旧 inode 仍按新
   路径被跟踪；之后对旧文件的补写（backfill）照样入仓，新文件是另一个身份。
2. **位点与数据同一事务提交。** 每个文件的已提交字节位点 `read_offset` 与
   新插入的报警行在同一个 `BEGIN IMMEDIATE` 事务里提交。读取或写库失败时事务
   回滚，位点不前进，下一轮从旧位点重读——因此**不会跳过未入仓部分**。
3. **唯一约束兜底防重。** `alarms` 上有
   `UNIQUE(file_id, byte_offset)`，插入用 `INSERT OR IGNORE`；两个采集器竞争时
   同一物理行最多入仓一次。同文不同行（字节偏移不同）各自保留；内容完全相同
   的两条记录也作为不同行保留。
4. **只入完整行。** 只消费到最后一个换行符；末尾没有换行的记录留在磁盘上，等
   补全后再入仓。各文件独立推进，一个文件的半行**不会阻塞**其它文件（含新建
   的活动文件）。
5. **跨块读取。** 单条记录大于 `READ_CHUNK` 时，一次扫描内累积读取直到遇到换行
   或 EOF，避免长行把位点永久卡死；超过 `MAX_LINE_BYTES` 仍无换行则挂起并报错，
   绝不静默截断。
6. **WAL + busy_timeout + 启动重试。** 多进程共库使用 WAL；连接时对
   `journal_mode=WAL`（该 pragma 不受 busy_timeout 保护）做带退避的重试，避免
   两个采集器同时启动时因瞬时写锁直接退出。

## 三、轮转规则

* 只做 `rename`：`alarms.jsonl → alarms.1.jsonl`，世代号顺延（`.1→.2`…），随后
  立刻创建同名空文件；**不删除、不截断任何文件**。
* 目录内最多 `MAX_GENERATIONS=3` 个 `.jsonl`；达到上限再轮转会被拒绝（HTTP 409），
  从源头保证旧文件不丢失。
* 旧文件依旧可以追加（网页下拉选择旧文件名即可补写）。

## 四、运行

```bash
docker compose up --build
# 打开 http://localhost:8000
```

启动三个容器：`web`（FastAPI）、`collector-a`、`collector-b`，共享两个卷：
`shared_data`（JSONL 目录）与 `db_data`（SQLite）。

网页功能：追加完整记录 / 写无换行半行 / 补换行 / 改名轮转；展示采集进程心跳、
目录文件与 inode、每个文件的已提交字节位点、入仓记录（含 file_id、行号、字节
偏移、源路径、采集者）、采集错误。

## 五、HTTP 接口（详见 `/docs`）

网关：`POST /api/gateway/append`、`/fragment`、`/complete`、`/rotate`，
`GET /api/gateway/files`
查询：`GET /api/alarms`、`/api/file-states`、`/api/collectors`、
`/api/errors`、`/api/stats`
运维：`GET /healthz`
（`POST /__test/shutdown` 仅在 `ALLOW_TEST_SHUTDOWN=1` 时可用，生产镜像不开启）

## 六、自测

```bash
# 端到端：真实拉起 1 个 web + 2 个采集器进程
python3 tests/selftest.py
# 故障注入：写库失败不推进、读失败不推进、跨块读取、空行
python3 tests/test_faults.py
```

`selftest.py` 覆盖：基础入仓、改名轮转身份保持、旧文件补写、半行挂起且不阻塞
新文件、3 件上限拒绝且不删不截、4 路并发 + 双采集器无漏无重、采集器中断重启、
坏行只阻塞自身且修复后继续、字节偏移与源文件逐字节对应、同文不同行分别保留。

## 七、已知边界

* 轮转世代号靠文件名约定；若有人在共享目录手工改名，身份仍以 inode 为准，只是
  世代排序可能变化。
* SQLite 适合本演示规模与单机共享卷场景；更高吞吐可平移到 Postgres 等，采集器
  的“位点与数据同事务”模型不变。
* 不处理文件被外部截断（合同约定网关只追加/改名）；若检测到文件变短会记录错误
  并冻结该文件位点，避免静默错位。

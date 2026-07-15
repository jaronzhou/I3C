# Saleae MIPI I3C Analyzer

这是一个用于 Saleae Logic 2 的 High Level Analyzer (HLA) 插件，
用于在 I2C 基础帧之上解析 MIPI I3C 的 SDR 事务并输出更高层可读结果。

## 1. 实现目标

- 识别普通 I3C 私有传输 (Private Transfer)
- 识别 CCC 传输 (通过广播地址 `0x7E`)
- 在结果中展示方向、地址、字节负载和 ACK/NACK 信息

## 2. 项目结构

- `extension.json`: Saleae 扩展清单
- `mipi_i3c_hla.py`: HLA 主体逻辑

## 3. 按流程使用

1. 打开 Logic 2，先添加一个 `I2C` 低层分析器并绑定 SDA/SCL。
2. 将本仓库作为本地扩展目录安装到 Logic 2。
3. 在测量页面中添加本插件 `MIPI I3C Analyzer`，输入源选择刚才的 `I2C` 分析器。
4. 运行采集后，在 Analyzer Results 中查看解析结果。

## 4. 当前解析策略

- 以 `start/address/data/stop` 帧聚合一个传输事务。
- 地址为 `0x7E` 且写方向时，按 CCC 头处理：
	- 第一个数据字节作为 CCC Code
	- 后续数据字节作为 CCC Payload
- 非 `0x7E` 地址按 Private Transfer 展示。

## 5. 结果说明

- Private 示例: `I3C W 0x2A [3B] 12 34 56 ACK:all`
- CCC 示例: `Broadcast CCC 0x07 ENTDAA (Broadcast) [0B] ACK:all`

当 `show_ack` 设为 `hide` 时，不输出 ACK 信息后缀。

## 6. 已知限制

- 当前实现基于 I2C 低层帧输入，适用于 I3C SDR 可观测字节流场景。
- HDR 模式、位级时序细节、完整 DAA/IBI 深度语义暂未实现。
- 若下层分析器输出格式变化，可能需要调整 `mipi_i3c_hla.py` 中的数据字段提取逻辑。

## 7. 后续可扩展方向

- 增加 IBI 识别与事件分类
- 增加 DAA 过程专门状态机
- 对常见 CCC 增加字段级解析和校验提示

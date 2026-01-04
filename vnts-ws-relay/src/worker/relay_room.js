import { NetPacket } from "./core/packet.js";
import { VntContext } from "./core/context.js";
import { PacketHandler } from "./core/handler.js";
import { PROTOCOL, TRANSPORT_PROTOCOL } from "./core/constants.js";
import { parseVNTHeaderFast } from "./utils/fast_parser.js";
import { logger } from "./core/logger.js";

export class RelayRoom {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.connections = new Map();
    this.contexts = new Map();
    this.p2p_connections = new Map();
    this.connection_last_update = new Map();
    this.packetHandler = new PacketHandler(env, this);

    // 心跳管理
    this.heartbeatTimers = new Map();
    this.heartbeatInterval = parseInt(env.HEARTBEAT_INTERVAL || "60") * 1000;

    // 连接信息存储
    this.connectionInfos = new Map();
  }
  // 获取网关IP地址
  getGatewayIp(clientId) {
    const context = this.contexts.get(clientId);
    if (context && context.link_context && context.link_context.network_info) {
      return context.link_context.network_info.gateway;
    }
    return null;
  }
  async handleGatewayPing(clientId, uint8Data) {
    try {
      // logger.info(`开始处理客户端发来的ping包`);

      // 直接修改原始数据包
      const modifiedData = new Uint8Array(uint8Data);

      // 正确解析VNT头部的源和目标地址
      const source =
        (modifiedData[4] << 24) |
        (modifiedData[5] << 16) |
        (modifiedData[6] << 8) |
        modifiedData[7];
      const destination =
        (modifiedData[8] << 24) |
        (modifiedData[9] << 16) |
        (modifiedData[10] << 8) |
        modifiedData[11];

      // logger.debug(`源地址: ${this.packetHandler.formatIp(source)}`);
      // logger.debug(`目标地址: ${this.packetHandler.formatIp(destination)}`);

      // 交换VNT头部的源和目标地址
      modifiedData[4] = (destination >> 24) & 0xff; // 新源地址（原目标）
      modifiedData[5] = (destination >> 16) & 0xff;
      modifiedData[6] = (destination >> 8) & 0xff;
      modifiedData[7] = destination & 0xff;
      modifiedData[8] = (source >> 24) & 0xff; // 新目标地址（原源）
      modifiedData[9] = (source >> 16) & 0xff;
      modifiedData[10] = (source >> 8) & 0xff;
      modifiedData[11] = source & 0xff;

      // logger.debug(`已将ping包的VNT头部地址已交换`);

      // 修改IPv4头部的源和目标地址
      const ipv4HeaderStart = 12;
      modifiedData[ipv4HeaderStart + 12] = (destination >> 24) & 0xff;
      modifiedData[ipv4HeaderStart + 13] = (destination >> 16) & 0xff;
      modifiedData[ipv4HeaderStart + 14] = (destination >> 8) & 0xff;
      modifiedData[ipv4HeaderStart + 15] = destination & 0xff;
      modifiedData[ipv4HeaderStart + 16] = (source >> 24) & 0xff;
      modifiedData[ipv4HeaderStart + 17] = (source >> 16) & 0xff;
      modifiedData[ipv4HeaderStart + 18] = (source >> 8) & 0xff;
      modifiedData[ipv4HeaderStart + 19] = source & 0xff;

      // 修改ICMP类型为Echo Reply (0)
      const icmpStart = ipv4HeaderStart + 20;
      // logger.debug(`原始ICMP类型: ${modifiedData[icmpStart]}`);
      modifiedData[icmpStart] = 0;
      // logger.debug(`修改后ICMP类型: ${modifiedData[icmpStart]}`);

      // 重新计算校验和
      modifiedData[icmpStart + 2] = 0;
      modifiedData[icmpStart + 3] = 0;
      const icmpData = modifiedData.slice(icmpStart);
      const icmpChecksum = this.calculateIcmpChecksum(icmpData);
      modifiedData[icmpStart + 2] = (icmpChecksum >> 8) & 0xff;
      modifiedData[icmpStart + 3] = icmpChecksum & 0xff;
      // logger.debug(`ICMP校验和: 0x${icmpChecksum.toString(16)}`);

      modifiedData[ipv4HeaderStart + 10] = 0;
      modifiedData[ipv4HeaderStart + 11] = 0;
      const ipv4Header = modifiedData.slice(ipv4HeaderStart, icmpStart);
      const ipv4Checksum = this.calculateIpv4Checksum(ipv4Header);
      modifiedData[ipv4HeaderStart + 10] = (ipv4Checksum >> 8) & 0xff;
      modifiedData[ipv4HeaderStart + 11] = ipv4Checksum & 0xff;
      // logger.debug(`IPv4校验和: 0x${ipv4Checksum.toString(16)}`);

      // logger.debug(`响应包长度: ${modifiedData.length}`);
      // logger.debug(`响应包内容: ${Array.from(modifiedData).map((b) => b.toString(16).padStart(2, "0")).join(" ")}`);

      return { buffer: () => modifiedData };
    } catch (error) {
      // logger.error("处理客户端ping网关的包失败:", error);
      return null;
    }
  }

  // 添加原始buffer的校验和计算方法
  calculateIcmpChecksum(data) {
    let sum = 0;
    for (let i = 0; i < data.length - 1; i += 2) {
      sum += (data[i] << 8) | data[i + 1];
    }
    if (data.length % 2 === 1) {
      sum += data[data.length - 1] << 8;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += sum >> 16;
    return ~sum & 0xffff;
  }

  calculateIpv4Checksum(header) {
    let sum = 0;
    for (let i = 0; i < 20; i += 2) {
      sum += (header[i] << 8) | header[i + 1];
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += sum >> 16;
    return ~sum & 0xffff;
  }
  // 更新P2P连接状态
  updateP2PStatus(clientId, p2pTargets) {
    this.p2p_connections.set(clientId, new Set(p2pTargets));
    this.connection_last_update.set(clientId, Date.now());
    // logger.debug(`更新客户端 ${clientId} 的P2P连接状态，目标数量: ${p2pTargets.length}`);
  }

  // 检查是否有P2P连接
  hasP2PConnection(sourceId, targetIp) {
    const sourceP2P = this.p2p_connections.get(sourceId);
    if (!sourceP2P) {
      // logger.debug(`客户端 ${sourceId} 无P2P连接记录`);
      return false;
    }

    // 查找目标客户端ID
    for (const [clientId, context] of this.contexts) {
      if (context.virtual_ip === targetIp) {
        const hasConnection = sourceP2P.has(clientId);
        // logger.debug(`检查P2P连接: ${sourceId} -> ${targetIp} (客户端ID: ${clientId}), 结果: ${hasConnection ? "有连接" : "无连接"}`);
        return hasConnection;
      }
    }
    // logger.debug(`未找到目标IP ${targetIp} 对应的客户端`);
    return false;
  }
  // 处理客户端 P2P 状态报告
  handleP2PStatusReport(clientId, p2pList) {
    // logger.debug(`开始处理客户端 ${clientId} 的P2P状态报告，目标数量: ${p2pList.length}`);
    const p2pTargets = [];
    for (const targetInfo of p2pList) {
      const targetClientId = this.findClientByIp(targetInfo.target_ip);
      if (targetClientId) {
        p2pTargets.push(targetClientId);
        // logger.debug(`找到P2P目标: ${targetInfo.target_ip} -> 客户端ID: ${targetClientId}`);
      } else {
        // logger.debug(`未找到P2P目标 ${targetInfo.target_ip} 对应的客户端`);
      }
    }
    this.updateP2PStatus(clientId, p2pTargets);
    // logger.debug(`客户端 ${clientId} P2P状态处理完成，有效目标数量: ${p2pTargets.length}`);
  }

  async fetch(request) {
    const url = new URL(request.url);
    // logger.debug(`处理请求: ${url.pathname}`);

    const wsPath = "/" + this.env.WS_PATH || "/ws";
if (url.pathname === wsPath) {
      logger.debug(`WebSocket连接请求，开始处理`);
      return this.handleWebSocket(request);
    }
    // logger.debug(`未知路径: ${url.pathname}，返回404`);
    return new Response("Not Found", { status: 404 });
  }

  async handleWebSocket(request) {
    const [client, server] = Object.values(new WebSocketPair());
    server.accept();

    const clientId = this.generateClientId();
    const addr = this.parseClientAddress(request);

    // logger.info(`新的WebSocket连接: ${clientId} 来自 ${JSON.stringify(addr)}`);

    // 创建 VNT 上下文
    const context = new VntContext({
      linkAddress: addr,
      serverCipher: null,
    });

    this.contexts.set(clientId, context);
    this.connections.set(clientId, server);

    // 初始化连接状态
    this.initializeConnection(clientId, server);

    // 设置 WebSocket 消息处理
    server.addEventListener("message", async (event) => {
      await this.handleMessage(clientId, event.data);
    });

    server.addEventListener("close", (event) => {
      logger.info(`WebSocket关闭: ${clientId}`);
      this.handleClose(clientId);
    });

    server.addEventListener("error", (error) => {
      logger.error(`WebSocket错误 ${clientId}:`, error);
      this.handleClose(clientId);
    });

    // ping/pong 事件监听
    server.addEventListener("ping", () => {
      server.pong();
    });

    server.addEventListener("pong", () => {
      this.updateLastActivity(clientId);
    });
    // logger.debug(`WebSocket握手完成，返回101状态码`);

    return new Response(null, {
      status: 101,
      webSocket: client,
    });
  }

  // 初始化连接管理
  initializeConnection(clientId, server) {
    logger.info(`初始化客户端连接: ${clientId}`);
    const connectionInfo = {
      server: server,
      lastActivity: Date.now(),
      clientId: clientId,
      isAlive: true,
    };

    this.connectionInfos.set(clientId, connectionInfo);
    // logger.debug(`客户端 ${clientId} 连接信息已存储`);

    // 启动心跳定时器
    this.startHeartbeat(clientId);

    // 启动定期健康检查
    if (!this.healthCheckInterval) {
      // 从环境变量读取健康检查间隔，默认300秒（5分钟）
      const healthCheckSeconds = parseInt(
        this.env.HEALTH_CHECK_INTERVAL || "300"
      );
      const healthCheckMs = healthCheckSeconds * 1000;
      this.healthCheckInterval = setInterval(() => {
        this.checkConnectionHealth();
      }, healthCheckMs);
      logger.info(
        `健康检查定时器已启动，间隔${healthCheckSeconds}秒，清理已断开连接的客户端`
      );
    }
  }

  // 启动心跳机制
  startHeartbeat(clientId) {
    const server = this.connections.get(clientId);
    if (!server) return;

    // 从环境变量读取心跳检查间隔，默认30秒
    const heartbeatSeconds = parseInt(this.env.HEARTBEAT_INTERVAL || "30");
    const heartbeatMs = heartbeatSeconds * 1000;
    const heartbeatId = setInterval(() => {
      try {
        // 只检查连接状态，不主动发送心跳包
        if (server.readyState !== WebSocket.OPEN) {
          // logger.debug(`连接 ${clientId} 已断开，清理资源`);
          this.handleClose(clientId);
        }
      } catch (error) {
        // logger.error(`心跳检查失败 ${clientId}:`, error);
        this.handleClose(clientId);
      }
    }, heartbeatMs); // 每30秒检查一次连接状态

    this.heartbeatTimers.set(clientId, heartbeatId);
    logger.info(
      `客户端 ${clientId} 心跳定时器已启动，间隔${heartbeatSeconds}秒`
    );
  }

  // 更新最后活动时间
  updateLastActivity(clientId) {
    const connectionInfo = this.getConnectionInfo(clientId);
    if (connectionInfo) {
      connectionInfo.lastActivity = Date.now();
      // logger.debug(`更新客户端 ${clientId} 最后活动时间`);
    } else {
      // logger.debug(`客户端 ${clientId} 连接信息不存在，无法更新活动时间`);
    }
  }

  // 获取连接信息
  getConnectionInfo(clientId) {
    if (!this.connectionInfos) {
      // logger.debug(`连接信息映射未初始化`);
      return null;
    }
    const connectionInfo = this.connectionInfos.get(clientId);
    if (!connectionInfo) {
      // logger.debug(`客户端 ${clientId} 无连接信息记录`);
    }
    return connectionInfo;
  }

  // 轻量级 VNT 头部解析（类似 easytier）
  parseVNTHeader(buffer) {
    if (!buffer || buffer.length < 12) {
      // logger.debug(`VNT头部解析失败：数据包长度不足 (${buffer?.length || 0} < 12)`);
      return null;
    }

    const header = {
      source:
        (buffer[4] << 24) | (buffer[5] << 16) | (buffer[6] << 8) | buffer[7],
      destination:
        (buffer[8] << 24) | (buffer[9] << 16) | (buffer[10] << 8) | buffer[11],
      protocol: buffer[1],
      transportProtocol: buffer[2],
    };

    // logger.debug(`VNT头部解析完成: 源=${this.packetHandler.formatIp(header.source)}, 目标=${this.packetHandler.formatIp(header.destination)}, 协议=${header.protocol}, 传输=${header.transportProtocol}`);
    return header;
  }

  // 快速转发判断
  shouldFastForward(data) {
    if (!data || data.length < 12) {
      // logger.debug(`快速转发判断失败：数据包长度不足`);
      return false;
    }

    const protocol = data[1];
    const transport = data[2];

    const shouldForward =
      // IPTURN 数据包（最常见）
      (protocol === 4 && transport === 4) ||
      // WGIpv4 数据包
      (protocol === 4 && transport === 2) ||
      // Ipv4Broadcast 数据包
      (protocol === 4 && transport === 3) ||
      // 注意：移除 IPTURN IPv4（ICMP ping）包
      false;

    // logger.debug(`是否快速转发判断: 协议=${protocol}, 传输=${transport}, 结果=${shouldForward ? "允许" : "拒绝"}`);
    return shouldForward;
  }

  // 需要完整解析的包
  requiresFullParsing(data) {
    if (!data || data.length < 12) {
      // logger.debug(`完整解析检查：数据包长度不足，需要完整解析`);
      return true;
    }

    const protocol = data[1];
    // SERVICE 协议和部分 CONTROL 协议需要完整解析
    const needsFullParsing = protocol === 1 || (protocol === 3 && data[2] >= 3);

    // logger.debug(`是否完整解析检查: 协议=${protocol}, 传输=${data[2]}, 结果=${needsFullParsing ? "需要" : "不需要"}`);
    return needsFullParsing;
  }

  async relayPacket(sourceClientId, data, header) {
    logger.info(
      `开始转发数据包从 ${sourceClientId} 到 ${this.packetHandler.formatIp(
        header.destination
      )}`
    );

    // 检查是否禁用中继
    if (this.env.DISABLE_RELAY === "1") {
      logger.warn("中继转发已禁用，丢弃数据包");
      return;
    }

    // 获取源客户端的网络信息
    const sourceContext = this.contexts.get(sourceClientId);
    if (!sourceContext || !sourceContext.link_context) {
      logger.error(`源客户端 ${sourceClientId} 上下文不存在`);
      return;
    }

    // 查找同一网络中的所有在线客户端
    const networkInfo = sourceContext.link_context.network_info;
    const targetClient = networkInfo.clients.get(header.destination);

    if (targetClient && targetClient.online) {
      // 通过服务器中继到目标客户端
      for (const [clientId, server] of this.connections) {
        if (clientId === sourceClientId) continue;

        const clientContext = this.contexts.get(clientId);
        if (
          clientContext &&
          clientContext.link_context &&
          clientContext.link_context.virtual_ip === header.destination
        ) {
          try {
            server.send(data);
            // logger.info(`数据包已转发到客户端 ${clientId}`);
            break;
          } catch (error) {
            logger.error(`转发到客户端 ${clientId} 失败:`, error);
          }
        }
      }
    } else {
      logger.warn(
        `目标客户端 ${this.packetHandler.formatIp(
          header.destination
        )} 不在线或不存在`
      );
    }
  }
  // 高性能消息处理
  async handleMessage(clientId, data) {
    try {
      // 确保数据是 Uint8Array
      let uint8Data;
      if (data instanceof ArrayBuffer) {
        uint8Data = new Uint8Array(data);
      } else if (data instanceof Uint8Array) {
        uint8Data = data;
      } else {
        // logger.warn(`不支持的数据类型: ${typeof data}`);
        return;
      }

      // 更新活动时间
      this.updateLastActivity(clientId);
      const protocol = uint8Data[1];
      const transport = uint8Data[2];

      // 检测传输协议4的ping包
      if (protocol === 4 && transport === 4) {
        // logger.debug(`检测到传输协议4包，目标=${this.packetHandler.formatIp((uint8Data[8] << 24) | (uint8Data[9] << 16) | (uint8Data[10] << 8) | uint8Data[11])}`);
        const header = parseVNTHeaderFast(uint8Data);
        if (header && header.destination) {
          const gatewayIp = this.getGatewayIp(clientId);
          if (header.destination === gatewayIp) {
            // logger.debug(`检测到ping网关（传输协议4），直接响应`);
            const response = await this.handleGatewayPing(clientId, uint8Data);

            // 关键修复：发送响应包给客户端
            if (response) {
              const server = this.connections.get(clientId);
              if (server && server.readyState === WebSocket.OPEN) {
                server.send(response.buffer());
                // logger.debug(`ICMP响应已发送给客户端`);
              }
            }
            return;
          }
        }
      }

      // 优先检查快速转发
      if (this.shouldFastForward(uint8Data)) {
        const protocol = uint8Data[1];
        const transport = uint8Data[2];
        // logger.debug(`快速转发: 协议=${protocol}, 传输=${transport}`);

        // 在快速转发中也检查 P2P 连接
        const header = parseVNTHeaderFast(uint8Data);
        if (header && header.destination) {
          if (this.hasP2PConnection(clientId, header.destination)) {
            // logger.debug(`快速路径: ${clientId} 到 ${header.destination} 有P2P连接，跳过转发`);
            return;
          }
        }

        return await this.fastForward(clientId, uint8Data);
      }

      // 完整解析路径
      const header = parseVNTHeaderFast(uint8Data);

      if (!header) {
        return await this.fullParsingPath(clientId, uint8Data);
      }

      // 数据包智能处理 - 参照 vnts 的优先 P2P 逻辑
      if (header.isDataPacket && !(uint8Data[1] === 4 && uint8Data[2] === 1)) {
        const targetIp = header.destination;

        // 优先检查 P2P 连接 - 类似 vnts 的 route_one_p2p 逻辑
        if (this.hasP2PConnection(clientId, targetIp)) {
          // logger.debug(`${clientId} 到 ${targetIp} 有P2P连接，跳过转发`);
          return; // 让客户端直连，不中继
        }

        // 没有 P2P 连接，尝试直接转发
        const targetClient = this.findClientByIp(targetIp);
        if (targetClient && targetClient !== clientId) {
          const server = this.connections.get(targetClient);
          if (server && server.readyState === WebSocket.OPEN) {
            server.send(uint8Data);
            return;
          }
        }

        // 目标不在线或无法直连，才考虑服务器中继
        if (this.env.DISABLE_RELAY !== "1") {
          return await this.relayPacket(clientId, uint8Data, header);
        }
      }

      // 控制包和服务包需要完整解析
      if (header.isControlPacket || header.isServicePacket) {
        return await this.fullParsingPath(clientId, uint8Data);
      }

      // 其他情况默认广播（但也要检查 P2P）
      if (header.destination) {
        if (this.hasP2PConnection(clientId, header.destination)) {
          // logger.debug(`广播路径: ${clientId} 到 ${header.destination} 有P2P连接，跳过转发`);
          return;
        }
      }
      return await this.fastForward(clientId, uint8Data);
    } catch (error) {
      logger.error(`处理 ${clientId} 消息时出错:`, error);
    }
  }

  // 辅助函数：根据 IP 查找客户端
  findClientByIp(targetIp) {
    // logger.debug(`开始查找IP地址 ${targetIp} 对应的客户端`);
    for (const [clientId, context] of this.contexts) {
      if (
        context.link_context &&
        context.link_context.virtual_ip === targetIp
      ) {
        // logger.debug(`找到客户端: ${targetIp} -> ${clientId}`);
        return clientId;
      }
    }
    // logger.debug(`未找到IP地址 ${targetIp} 对应的客户端`);
    return null;
  }

  // 快速转发路径
  async fastForward(clientId, data) {
    // logger.info(`开始快速转发数据包，来源客户端: ${clientId}`);

    let forwardedCount = 0;
    for (const [targetClientId, server] of this.connections) {
      if (targetClientId === clientId) continue;

      try {
        if (server.readyState === WebSocket.OPEN) {
          server.send(data);
          forwardedCount++;
          // logger.debug(`数据包已转发到客户端: ${targetClientId}`);
        } else {
          // logger.debug(`客户端 ${targetClientId} 连接未开启，跳过转发`);
        }
      } catch (error) {
        logger.error(`转发到客户端 ${targetClientId} 失败:`, error);
      }
    }

    // logger.info(`快速转发完成，成功转发到 ${forwardedCount} 个客户端`);
  }

  // 完整解析路径（保持 VNT 兼容性）
  async fullParsingPath(clientId, data) {
    const packet = NetPacket.parse(data);
    const context = this.contexts.get(clientId);
    const addr = this.parseClientAddress({ cf: { colo: "unknown" } });

    // logger.debug(`开始完整VNT解析，客户端: ${clientId}`);
    // logger.debug(`数据包协议: ${packet.protocol}, 传输协议: ${packet.transportProtocol}`);

    // 检查是否是 P2P 状态报告包
    if (
      packet.protocol === PROTOCOL.SERVICE &&
      packet.transportProtocol === TRANSPORT_PROTOCOL.RegistrationRequest
    ) {
      try {
        const payload = packet.get_payload();
        if (payload && payload.p2p_status) {
          // logger.debug(`检测到P2P状态报告包，开始处理`);
          this.handleP2PStatusReport(clientId, payload.p2p_status);
        }
      } catch (e) {
        // 忽略解析错误  logger.debug(`P2P状态报告解析失败，忽略错误`);
      }
    }

    const response = await this.packetHandler.handle(
      context,
      packet,
      addr,
      clientId
    );

    if (response) {
      const server = this.connections.get(clientId);
      if (server && server.readyState === WebSocket.OPEN) {
        server.send(response.buffer());
        // logger.debug(`响应包已发送给客户端: ${clientId}`);
      }
    }

    // VNT 协议的广播逻辑 - 添加 P2P 检查
    if (this.shouldBroadcast(packet)) {
      // 检查广播目标是否有 P2P 连接
      if (
        packet.destination &&
        this.hasP2PConnection(clientId, packet.destination)
      ) {
        // logger.debug(`广播包 ${clientId} 到 ${this.packetHandler.formatIp(packet.destination)} 有P2P连接，跳过服务器广播`);
        return;
      }
      // logger.info(`开始广播数据包，来源客户端: ${clientId}`);
      await this.broadcastPacket(clientId, packet);
    }
  }

  buildHandshakeResponse(clientId) {
    const context = this.contexts.get(clientId);
    // logger.debug(`构建客户端 ${clientId} 的握手响应`);
    const response = {
      // VNT 协议基础字段
      version: "cloudflare", // 协议版本 [1](#26-0)
      secret: false, // 是否启用加密 [2](#26-1)
      public_key: new Uint8Array(0), // 服务器公钥 [3](#26-2)
      key_finger: "", // 密钥指纹 [4](#26-3)

      // P2P 扩展字段
      p2p_targets: Array.from(this.p2p_connections.get(clientId) || []),
      request_p2p_status: true, // 请求客户端报告 P2P 状态
      server_p2p_support: true, // 服务器支持 P2P 智能判断
    };
    // logger.debug(`握手响应构建完成，P2P目标数量: ${p2pTargets.length}`);
    return response;
  }
  // 基于头部的转发
  async headerBasedForward(clientId, data, header) {
    // logger.info(`开始基于头部的转发，来源客户端: ${clientId}`);

    let forwardedCount = 0;
    for (const [targetClientId, server] of this.connections) {
      if (targetClientId === clientId) continue;

      try {
        if (server.readyState === WebSocket.OPEN) {
          server.send(data);
          forwardedCount++;
          // logger.debug(`数据包已转发到客户端: ${targetClientId}`);
        } else {
          // logger.debug(`客户端 ${targetClientId} 连接未开启，跳过转发`);
        }
      } catch (error) {
        logger.error(`头部转发到客户端 ${targetClientId} 失败:`, error);
      }
    }

    // logger.info(`头部转发完成，成功转发到 ${forwardedCount} 个客户端`);
  }

  // VNT 协议广播判断
  shouldBroadcast(packet) {
    // logger.debug(`判断数据包是否需要广播，协议: ${packet.protocol}`);
    // 保持原有的 VNT 广播逻辑
    if (packet.protocol === PROTOCOL.SERVICE) {
      // logger.debug(`SERVICE协议，不广播`);
      return false;
    }

    if (packet.protocol === PROTOCOL.ERROR) {
      // logger.debug(`ERROR协议，不广播`);
      return false;
    }

    // logger.debug(`协议 ${packet.protocol} 允许广播`);
    return true;
  }

  async broadcastPacket(senderId, packet) {
    const senderContext = this.contexts.get(senderId);

    for (const [clientId, server] of this.connections) {
      if (clientId === senderId) continue;

      try {
        if (this.shouldForward(senderContext, packet)) {
          // logger.debug(`广播数据包从 ${senderId} 到 ${clientId}`);

          const packetCopy = this.copyPacket(packet);
          server.send(packetCopy.buffer());
        }
      } catch (error) {
        logger.error(`广播到客户端 ${clientId} 失败:`, error);
      }
    }
  }

  copyPacket(originalPacket) {
    try {
      const buffer = originalPacket.buffer();
      const copiedBuffer = new Uint8Array(buffer.length);
      copiedBuffer.set(buffer);
      return NetPacket.parse(copiedBuffer);
    } catch (error) {
      logger.error(`复制数据包失败:`, error);
      return originalPacket;
    }
  }

  shouldForward(context, packet) {
    const shouldForward = packet.protocol !== PROTOCOL.SERVICE;
    // logger.debug(`转发判断: 协议=${packet.protocol}, 结果=${shouldForward ? "允许转发" : "拒绝转发"}`);
    return shouldForward;
  }

  handleClose(clientId) {  
    logger.info(`开始清理连接: ${clientId}`);  
  
    const context = this.contexts.get(clientId);  
  
    if (context) {  
        try {  
            // 获取网络信息用于通知  
            let networkInfo = null;  
            let disconnectedIp = null;  
              
            if (context.link_context) {  
                networkInfo = context.link_context.network_info;  
                disconnectedIp = context.link_context.virtual_ip;  
            }  
              
            // 清理上下文（仅标记离线，不删除）  
            this.packetHandler.leave(context);  
              
            // 通知其他客户端有设备离线  
            if (networkInfo && disconnectedIp) {  
                const disconnectedClient = networkInfo.clients.get(disconnectedIp);  
                if (disconnectedClient) {  
                    // 创建设备列表更新包（包含离线设备）  
                    const updatePacket = this.packetHandler.createDeviceUpdatePacket(  
                        networkInfo,   
                        disconnectedClient  
                    );  
                      
                    // 通知其他在线客户端  
                    for (const [ip, client] of networkInfo.clients) {  
                        if (ip !== disconnectedIp && client.online) {  
                            try {  
                                // 查找对应的 WebSocket 连接  
                                for (const [cid, ws] of this.connections) {  
                                    const ctx = this.contexts.get(cid);  
                                    if (ctx && ctx.link_context &&   
                                        ctx.link_context.virtual_ip === ip) {  
                                        ws.send(updatePacket.buffer().to_vec());  
                                        break;  
                                    }  
                                }  
                            } catch (error) {  
                                logger.error(  
                                    `[客户端离线通知] 通知客户端 ${this.formatIp(ip)} 失败: ${  
                                        error.message  
                                    }`,  
                                    error  
                                );  
                            }  
                        }  
                    }  
                }  
            }  
        } catch (error) {  
            logger.error(`清理 ${clientId} 上下文时出错:`, error);  
        }  
    }  
  
    // 清理心跳定时器  
    const heartbeatId = this.heartbeatTimers.get(clientId);  
    if (heartbeatId) {  
        logger.debug(`停止 ${clientId} 的心跳定时器`);  
        clearInterval(heartbeatId);  
        this.heartbeatTimers.delete(clientId);  
    }  
  
    // 清理连接和上下文  
    this.contexts.delete(clientId);  
    this.connections.delete(clientId);  
  
    // 清理连接信息  
    if (this.connectionInfos) {  
        this.connectionInfos.delete(clientId);  
    }  
  
    // 如果没有活跃连接了，停止健康检查  
    if (this.connections.size === 0 && this.healthCheckInterval) {  
        clearInterval(this.healthCheckInterval);  
        this.healthCheckInterval = null;  
        logger.info(`所有连接已断开，停止健康检查定时器`);  
    }  
  
    logger.info(`连接 ${clientId} 清理完成`);  
}

  generateClientId() {
    const clientId = Math.random().toString(36).substr(2, 9);
    logger.debug(`生成客户端ID: ${clientId}`);
    return clientId;
  }

  parseClientAddress(request) {
    const cf = request.cf;
    const address = {
      ip: cf?.colo || "unknown",
      port: 0,
    };
    // logger.debug(`解析客户端地址: ${JSON.stringify(address)}`);
    return address;
  }

  checkConnectionHealth() {
    logger.info(`开始健康检查，当前连接数: ${this.connections.size}`);

    let cleanedCount = 0;
    for (const [clientId, server] of this.connections) {
      if (server.readyState !== WebSocket.OPEN) {
        logger.debug(`连接 ${clientId} 已断开，准备清理`);
        this.handleClose(clientId);
        cleanedCount++;
      }
    }

    logger.info(`健康检查完成，清理了 ${cleanedCount} 个断开的连接`);
  }
}

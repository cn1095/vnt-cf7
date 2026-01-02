import { NetPacket } from "./core/packet.js";
import { VntContext } from "./core/context.js";
import { PacketHandler } from "./core/handler.js";
import { PROTOCOL, TRANSPORT_PROTOCOL } from "./core/constants.js";
import { parseVNTHeaderFast } from "./utils/fast_parser.js";

export class RelayRoom {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.connections = new Map();
    this.contexts = new Map();
    this.packetHandler = new PacketHandler(env);

    // 心跳管理
    this.heartbeatTimers = new Map();
    this.heartbeatInterval = parseInt(env.HEARTBEAT_INTERVAL || "60") * 1000;

    // 连接信息存储
    this.connectionInfos = new Map();
  }

  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === "/ws") {
      return this.handleWebSocket(request);
    }

    return new Response("Not Found", { status: 404 });
  }

  async handleWebSocket(request) {
    const [client, server] = Object.values(new WebSocketPair());
    server.accept();

    const clientId = this.generateClientId();
    const addr = this.parseClientAddress(request);

    console.log(
      `[DEBUG] New WebSocket connection: ${clientId} from ${JSON.stringify(
        addr
      )}`
    );

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
      console.log(`[调试] WebSocket关闭: ${clientId}`);
      this.handleClose(clientId);
    });

    server.addEventListener("error", (error) => {
      console.error(`[调试] WebSocket错误 ${clientId}:`, error);
      this.handleClose(clientId);
    });

    // ping/pong 事件监听
    server.addEventListener("ping", () => {
      server.pong();
    });

    server.addEventListener("pong", () => {
      this.updateLastActivity(clientId);
    });

    return new Response(null, {
      status: 101,
      webSocket: client,
    });
  }

  // 初始化连接管理
  initializeConnection(clientId, server) {
    console.log(`[调试] 初始化连接: ${clientId}`);
    const connectionInfo = {
      server: server,
      lastActivity: Date.now(),
      clientId: clientId,
      isAlive: true,
    };

    this.connectionInfos.set(clientId, connectionInfo);

    // 启动心跳定时器
    this.startHeartbeat(clientId);

    // 启动定期健康检查
    if (!this.healthCheckInterval) {
      this.healthCheckInterval = setInterval(() => {
        this.checkConnectionHealth();
      }, 300000); // 5分钟
    }
  }
  createVNTHeartbeat() {
    // 创建包含载荷的CONTROL协议ping包
    const payload = new Uint8Array(4); // 2字节时间 + 2字节纪元
    const view = new DataView(payload.buffer);

    // 设置当前时间（低16位）
    const currentTime = Date.now() & 0xffff;
    view.setUint16(0, currentTime, false); // 大端序

    // 设置纪元（可以从连接信息获取）
    view.setUint16(2, 0, false); // 纪元，暂时设为0

    const packet = NetPacket.new(payload.length);
    packet.set_protocol(PROTOCOL.CONTROL);
    packet.set_transport_protocol(TRANSPORT_PROTOCOL.Ping);
    packet.set_source(0x0a240001); // 网关地址 10.36.0.1
    packet.set_destination(0xffffffff); // 广播地址
    packet.first_set_ttl(5);
    packet.set_gateway_flag(true);
    packet.set_payload(payload); // 设置正确的载荷

    return packet.buffer();
  }
  // 启动心跳机制
  startHeartbeat(clientId) {
    const server = this.connections.get(clientId);
    if (!server) return;

    const heartbeatId = setInterval(() => {
      try {
        // 发送VNT心跳包而不是仅检查状态
        const heartbeatPacket = this.createVNTHeartbeat();
        server.send(heartbeatPacket);
        console.log(`[调试] 发送VNT心跳包到: ${clientId}`);
      } catch (error) {
        console.error(`[调试] 心跳失败 ${clientId}:`, error);
        this.handleClose(clientId);
      }
    }, 3000); // 每3秒发送一次，匹配客户端期望

    this.heartbeatTimers.set(clientId, heartbeatId);
  }

  // 更新最后活动时间
  updateLastActivity(clientId) {
    const connectionInfo = this.getConnectionInfo(clientId);
    if (connectionInfo) {
      connectionInfo.lastActivity = Date.now();
    }
  }

  // 获取连接信息
  getConnectionInfo(clientId) {
    if (!this.connectionInfos) {
      return null;
    }
    return this.connectionInfos.get(clientId);
  }

  // 轻量级 VNT 头部解析（类似 easytier）
  parseVNTHeader(buffer) {
    if (!buffer || buffer.length < 12) return null;

    return {
      source:
        (buffer[4] << 24) | (buffer[5] << 16) | (buffer[6] << 8) | buffer[7],
      destination:
        (buffer[8] << 24) | (buffer[9] << 16) | (buffer[10] << 8) | buffer[11],
      protocol: buffer[1],
      transportProtocol: buffer[2],
    };
  }

  // 快速转发判断
  shouldFastForward(data) {
    if (!data || data.length < 12) return false;

    const protocol = data[1];
    const transport = data[2];

    // 扩大快速路径范围
    return (
      // IPTURN 数据包（最常见）
      (protocol === 4 && transport === 4) ||
      // WGIpv4 数据包
      (protocol === 4 && transport === 2) ||
      // Ipv4Broadcast 数据包
      (protocol === 4 && transport === 3) ||
      // 部分 CONTROL 协议包（ping/pong）
      (protocol === 3 && (transport === 1 || transport === 2))
    );
  }

  // 需要完整解析的包
  requiresFullParsing(data) {
    if (!data || data.length < 12) return true;

    const protocol = data[1];
    // SERVICE 协议和部分 CONTROL 协议需要完整解析
    return protocol === 1 || (protocol === 3 && data[2] >= 3);
  }
  async relayPacket(sourceClientId, data, header) {  
  console.log(`[调试] 中继数据包从 ${sourceClientId} 到 ${header.destination}`);  
    
  // 检查是否禁用中继  
  if (this.env.VNT_DISABLE_RELAY === "1") {  
    console.log("[调试] 中继已禁用，丢弃数据包");  
    return;  
  }  
  
  // 获取源客户端的网络信息  
  const sourceContext = this.contexts.get(sourceClientId);  
  if (!sourceContext || !sourceContext.link_context) {  
    console.log(`[调试] 源客户端 ${sourceClientId} 上下文不存在`);  
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
      if (clientContext &&   
          clientContext.link_context &&  
          clientContext.link_context.virtual_ip === header.destination) {  
        try {  
          server.send(data);  
          console.log(`[调试] 数据包已中继到 ${clientId}`);  
          break;  
        } catch (error) {  
          console.error(`[调试] 中继到 ${clientId} 失败:`, error);  
        }  
      }  
    }  
  } else {  
    console.log(`[调试] 目标客户端 ${header.destination} 不在线或不存在`);  
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
      console.warn(`[调试] 不支持的数据类型: ${typeof data}`);  
      return;  
    }  
  
    console.log(`[调试] 收到来自 ${clientId} 的数据`);  
    console.log(`[调试] 数据长度: ${uint8Data.length}`);  
  
    // 更新活动时间  
    this.updateLastActivity(clientId);  
  
    // 快速路径：解析 VNT 头部  
    const header = parseVNTHeaderFast(uint8Data); // 使用导入的函数  
      
    if (!header) {  
      // 头部解析失败，走完整解析路径  
      console.log(`[调试] 头部解析失败，走完整解析路径`);  
      return await this.fullParsingPath(clientId, uint8Data);  
    }  
  
    // 数据包直接 0 拷贝转发  
    if (header.isDataPacket) {  
      const targetIp = header.destination;  
      const targetClient = this.findClientByIp(targetIp);  
        
      if (targetClient && targetClient !== clientId) {  
        // 0 拷贝：直接发送原始 buffer  
        const server = this.connections.get(targetClient);  
        if (server && server.readyState === WebSocket.OPEN) {  
          server.send(uint8Data);  
          return; // 转发完成，不需要继续处理  
        }  
      }  
        
      // 目标客户端不存在或离线，需要中继  
      if (this.env.VNT_DISABLE_RELAY !== "1") {  
        return await this.relayPacket(clientId, uint8Data, header);  
      }  
    }  
  
    // 控制包和服务包需要完整解析  
    if (header.isControlPacket || header.isServicePacket) {  
      console.log(`[调试] 检测到控制/服务包，走完整解析路径`);  
      return await this.fullParsingPath(clientId, uint8Data);  
    }  
  
    // 其他情况默认广播（保持兼容性）  
    return await this.fastForward(clientId, uint8Data);  
  } catch (error) {  
    console.error(`[调试] 处理 ${clientId} 消息时出错:`, error);  
  }  
}  
  
// 辅助函数：根据 IP 查找客户端  
findClientByIp(targetIp) {  
  for (const [clientId, context] of this.contexts) {  
    if (context.link_context &&   
        context.link_context.virtual_ip === targetIp) {  
      return clientId;  
    }  
  }  
  return null;  
}

  // 快速转发路径
  async fastForward(clientId, data) {
    console.log(`[DEBUG] Fast forwarding from ${clientId}`);

    for (const [targetClientId, server] of this.connections) {
      if (targetClientId === clientId) continue;

      try {
        if (server.readyState === WebSocket.OPEN) {
          server.send(data);
        }
      } catch (error) {
        console.error(`Fast forward to ${targetClientId} failed:`, error);
      }
    }
  }

  // 完整解析路径（保持 VNT 兼容性）
  async fullParsingPath(clientId, data) {
    const packet = NetPacket.parse(data);
    const context = this.contexts.get(clientId);
    const addr = this.parseClientAddress({ cf: { colo: "unknown" } });

    console.log(`[DEBUG] Full VNT parsing for ${clientId}`);
    console.log(
      `[DEBUG] Packet protocol: ${packet.protocol}, transport: ${packet.transportProtocol}`
    );

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
      }
    }

    // VNT 协议的广播逻辑
    if (this.shouldBroadcast(packet)) {
      await this.broadcastPacket(clientId, packet);
    }
  }

  // 基于头部的转发
  async headerBasedForward(clientId, data, header) {
    console.log(`[DEBUG] Header-based forwarding from ${clientId}`);

    // 简单的目标查找和转发
    for (const [targetClientId, server] of this.connections) {
      if (targetClientId === clientId) continue;

      try {
        if (server.readyState === WebSocket.OPEN) {
          server.send(data);
        }
      } catch (error) {
        console.error(
          `Header-based forward to ${targetClientId} failed:`,
          error
        );
      }
    }
  }

  // VNT 协议广播判断
  shouldBroadcast(packet) {
    // 保持原有的 VNT 广播逻辑
    if (packet.protocol === PROTOCOL.SERVICE) {
      return false;
    }

    if (packet.protocol === PROTOCOL.ERROR) {
      return false;
    }

    return true;
  }

  async broadcastPacket(senderId, packet) {
    const senderContext = this.contexts.get(senderId);

    for (const [clientId, server] of this.connections) {
      if (clientId === senderId) continue;

      try {
        if (this.shouldForward(senderContext, packet)) {
          console.log(
            `[DEBUG] Broadcasting packet from ${senderId} to ${clientId}`
          );

          const packetCopy = this.copyPacket(packet);
          server.send(packetCopy.buffer());
        }
      } catch (error) {
        console.error(`[DEBUG] Broadcast error to ${clientId}:`, error);
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
      console.error(`[DEBUG] Failed to copy packet:`, error);
      return originalPacket;
    }
  }

  shouldForward(context, packet) {
    return packet.protocol !== PROTOCOL.SERVICE;
  }

  handleClose(clientId) {
    console.log(`[调试] 开始清理连接: ${clientId}`);

    const context = this.contexts.get(clientId);

    if (context) {
      try {
        console.log(`[调试] 清理 ${clientId} 的上下文`);
        this.packetHandler.leave(context);
      } catch (error) {
        console.error(`[调试] 清理 ${clientId} 上下文时出错:`, error);
      }
    }

    // 清理心跳定时器
    const heartbeatId = this.heartbeatTimers.get(clientId);
    if (heartbeatId) {
      console.log(`[调试] 停止 ${clientId} 的心跳定时器`);
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
      console.log(`[调试] 停止健康检查定时器`);
    }

    console.log(`[调试] 连接 ${clientId} 清理完成`);
  }

  generateClientId() {
    return Math.random().toString(36).substr(2, 9);
  }

  parseClientAddress(request) {
    const cf = request.cf;
    return {
      ip: cf?.colo || "unknown",
      port: 0,
    };
  }

  checkConnectionHealth() {
    console.log(`[调试] 开始健康检查，当前连接数: ${this.connections.size}`);

    for (const [clientId, server] of this.connections) {
      if (server.readyState !== WebSocket.OPEN) {
        console.log(`[调试] 连接 ${clientId} 已断开，准备清理`);
        this.handleClose(clientId);
      }
    }

    console.log(`[调试] 健康检查完成`);
  }
}

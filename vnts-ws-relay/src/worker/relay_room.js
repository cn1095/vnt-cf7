import { NetPacket } from './core/packet.js';  
import { VntContext } from './core/context.js';  
import { PacketHandler } from './core/handler.js';  
import { PROTOCOL, TRANSPORT_PROTOCOL } from './core/constants.js';  
  
export class RelayRoom {  
  constructor(state, env) {  
    this.state = state;  
    this.env = env;  
    this.connections = new Map();  
    this.contexts = new Map();  
    this.packetHandler = new PacketHandler(env);  
      
    // 新增：心跳管理  
    this.heartbeatTimers = new Map();  
    this.connectionTimeouts = new Map();  
    this.heartbeatInterval = parseInt(env.HEARTBEAT_INTERVAL || '60') * 1000; // 转换为毫秒  
    this.connectionTimeout = 120000; // 120秒连接超时  
  }  
  
  async fetch(request) {  
    const url = new URL(request.url);  
      
    if (url.pathname === '/ws') {  
      return this.handleWebSocket(request);  
    }  
      
    return new Response('Not Found', { status: 404 });  
  }  
  
  async handleWebSocket(request) {  
    const [client, server] = Object.values(new WebSocketPair());  
    server.accept();  
      
    const clientId = this.generateClientId();  
    const addr = this.parseClientAddress(request);  
      
    console.log(`[DEBUG] New WebSocket connection: ${clientId} from ${JSON.stringify(addr)}`);  
      
    // 创建 VNT 上下文  
    const context = new VntContext({  
      linkAddress: addr,  
      serverCipher: null  
    });  
      
    this.contexts.set(clientId, context);  
    this.connections.set(clientId, server);  
      
    // 新增：初始化连接状态  
    this.initializeConnection(clientId, server);  
      
    // 设置 WebSocket 消息处理  
    server.addEventListener('message', async (event) => {  
      await this.handleMessage(clientId, event.data);  
    });  
      
    server.addEventListener('close', (event) => {  
  console.log(`[调试] WebSocket关闭: ${clientId}`);  
  console.log(`[调试] 关闭代码: ${event.code}`);  
  console.log(`[调试] 关闭原因: ${event.reason}`);  
  console.log(`[调试] 是否干净关闭: ${event.wasClean}`);  
    
  // 检查连接状态  
  const connectionInfo = this.getConnectionInfo(clientId);  
  if (connectionInfo) {  
    const inactiveTime = Date.now() - connectionInfo.lastActivity;  
    console.log(`[调试] 连接非活跃时间: ${Math.round(inactiveTime/1000)}秒`);  
  }  
    
  this.handleClose(clientId);  
});  
      
    server.addEventListener('error', (error) => {  
  console.error(`[调试] WebSocket错误 ${clientId}:`, error);  
  console.error(`[调试] 错误类型: ${error.type || 'unknown'}`);  
  console.error(`[调试] 错误消息: ${error.message || 'no message'}`);  
    
  // 记录连接状态  
  const connectionInfo = this.getConnectionInfo(clientId);  
  if (connectionInfo) {  
    console.log(`[调试] 错误时连接状态:`, connectionInfo);  
  }  
    
  this.handleClose(clientId);  
});  
      
    // 新增：添加 ping/pong 事件监听  
    server.addEventListener('ping', () => {  
      console.log(`[DEBUG] Received ping from ${clientId}, sending pong`);  
      server.pong();  
    });  
      
    server.addEventListener('pong', () => {  
      console.log(`[DEBUG] Received pong from ${clientId}`);  
      this.updateLastActivity(clientId);  
    });  
      
    return new Response(null, {  
      status: 101,  
      webSocket: client  
    });  
  }  
  
  // 新增：初始化连接管理  
  initializeConnection(clientId, server) { 
  console.log(`[调试] 初始化连接: ${clientId}`); 
    const connectionInfo = {  
      server: server,  
      lastActivity: Date.now(),  
      clientId: clientId,  
      isAlive: true  
    };
    
     // 使用 Map 存储连接信息  
    this.connectionInfos = this.connectionInfos || new Map();  
    this.connectionInfos.set(clientId, connectionInfo);
      
    // 启动心跳定时器  
    console.log(`[调试] 启动心跳机制，间隔: ${this.heartbeatInterval/1000}秒`);
    this.startHeartbeat(clientId);  
    // 新增：启动定期健康检查（每5分钟执行一次）  
  if (!this.healthCheckInterval) {  
    this.healthCheckInterval = setInterval(() => {  
      this.checkConnectionHealth();  
    }, 300000); // 5分钟  
  }
      
    console.log(`[调试] 连接初始化完成: ${clientId}`); 
  }  
  
  // 新增：启动心跳机制  
  startHeartbeat(clientId) {  
    const server = this.connections.get(clientId);  
    if (!server) return;  
      
    const heartbeatId = setInterval(() => {  
        try {  
            console.log(`[调试] 检查连接状态: ${clientId}`);  
              
            // 只检查WebSocket状态，不检查超时  
            if (server.readyState !== WebSocket.OPEN) {  
                console.log(`[调试] 连接已断开，清理: ${clientId}`);  
                this.handleClose(clientId);  
                return;  
            }  
        } catch (error) {  
            console.error(`[调试] 心跳检查失败 ${clientId}:`, error);  
            this.handleClose(clientId);  
        }  
    }, this.heartbeatInterval);  
      
    this.heartbeatTimers.set(clientId, heartbeatId);  
}  
  
  // 新增：更新最后活动时间  
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
  
  async handleMessage(clientId, data) {  
    try {  
      console.log(`[调试] 收到来自 ${clientId} 的数据`);  
    console.log(`[调试] 数据类型: ${typeof data}`);  
    console.log(`[调试] 数据长度: ${data ? data.length || data.byteLength : 'null'}`);  
      
      if (!data) {  
        console.log(`[调试] ${clientId} 未发送数据`);   
        return;  
      }  
        
      // 更新活动时间  
      this.updateLastActivity(clientId);  
      console.log(`[调试] 更新 ${clientId} 活动时间`);
        
      // 转换为 Uint8Array  
      let uint8Data;  
      if (data instanceof ArrayBuffer) {  
        uint8Data = new Uint8Array(data);  
      } else if (data instanceof Uint8Array) {  
        uint8Data = data;  
      } else if (ArrayBuffer.isView(data)) {  
        uint8Data = new Uint8Array(data.buffer);  
      } else {  
        console.log(`[调试] 不支持的数据类型: ${typeof data}`);  
        return;  
      }  
        
      const hexString = Array.from(uint8Data).map(b => b.toString(16).padStart(2, '0')).join('');  
      console.log(`[调试] 数据十六进制: ${hexString}`);  
        
      const context = this.contexts.get(clientId);  
      const server = this.connections.get(clientId);  
        
      if (!context || !server) {  
        console.log(`[DEBUG] No context or server found for ${clientId}`);  
        return;  
      }  
        
      console.log(`[DEBUG] Parsing VNT packet...`);  
      const packet = NetPacket.parse(uint8Data);  
        
      // 检查数据包是否正确解析  
      if (!packet || typeof packet !== 'object') {  
        console.log(`[DEBUG] Invalid packet returned from parse`);  
        return;  
      }  
        
      // 使用属性访问而不是方法调用  
      const protocol = packet.protocol;  
      const transportProtocol = packet.transportProtocol;  
      const source = packet.source;  
      const destination = packet.destination;  
        
      console.log(`[DEBUG] Parsed packet: protocol=${protocol}, transport=${transportProtocol}, source=${source}, dest=${destination}`);  
        
      console.log(`[DEBUG] Handling packet...`);  
      const response = await this.packetHandler.handle(  
        context,  
        packet,  
        context.linkAddress,  
        {  
          send: async (data) => {  
            try {  
              server.send(data);  
            } catch (error) {  
              console.error(`[DEBUG] Failed to send response to ${clientId}:`, error);  
              throw error;  
            }  
          }  
        }  
      );  
        
      // 发送响应 - 修复：避免重复发送  
      if (response) {  
  try {  
    this.packetHandler.validatePacket(response);  
    console.log(`[调试] 发送响应到 ${clientId}，长度: ${response.buffer().length}`);  
    server.send(response.buffer());  
  } catch (error) {  
    console.error(`[调试] 发送响应失败 ${clientId}:`, error);  
    // 检查是否是连接已关闭的错误  
    if (error.message.includes('closed') || error.message.includes('terminated')) {  
      console.log(`[调试] 检测到连接已关闭，清理: ${clientId}`);  
      this.handleClose(clientId);  
    }  
  }  
} else {  
        console.log(`[DEBUG] No response generated for ${clientId}`);  
      }  
        
      // 广播到其他连接（如果需要）- 修复：只在需要时广播  
      if (this.shouldBroadcast(packet)) {  
        await this.broadcastPacket(clientId, packet);  
      }  
        
    } catch (error) {  
  console.error(`[调试] 处理 ${clientId} 消息时出错:`, error);  
  console.error(`[调试] 错误堆栈:`, error.stack);  
    
  // 不要立即关闭连接，记录错误继续  
  console.log(`[调试] 记录错误但保持连接: ${clientId}`);  
    
  // 如果是严重错误，才关闭连接  
  if (error.message.includes('WebSocket') || error.message.includes('connection')) {  
    console.log(`[调试] 检测到连接错误，关闭: ${clientId}`);  
    this.handleClose(clientId);  
  } 
  }
  }  
  
  // 新增：判断是否需要广播  
  shouldForward(context, packet) {  
  // 实现路由逻辑  
  // 检查是否需要转发到其他节点  
  return packet.protocol !== PROTOCOL.SERVICE;  
}  
  
// 新增：在这里添加 shouldBroadcast 方法  
shouldBroadcast(packet) {  
  // SERVICE 协议包不应该广播  
  if (packet.protocol === PROTOCOL.SERVICE) {  
    return false;  
  }  
    
  // CONTROL 协议的握手包也不应该广播  
  if (packet.protocol === PROTOCOL.CONTROL &&   
      packet.transportProtocol === TRANSPORT_PROTOCOL.HandshakeRequest) {  
    return false;  
  }  
    
  // ERROR 协议包不需要广播  
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
        // 根据路由规则决定是否转发  
        if (this.shouldForward(senderContext, packet)) {  
          console.log(`[DEBUG] Broadcasting packet from ${senderId} to ${clientId}`);  
            
          // 修复：创建新的数据包副本避免引用问题  
          const packetCopy = this.copyPacket(packet);  
          server.send(packetCopy.buffer());  
        }  
      } catch (error) {  
        console.error(`[DEBUG] Broadcast error to ${clientId}:`, error);  
        // 如果广播失败，标记连接为不可用  
        this.markConnectionDead(clientId);  
      }  
    }  
  }  
  
  // 新增：复制数据包避免引用问题  
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
  
  // 新增：标记连接为不可用  
  markConnectionDead(clientId) {  
    console.log(`[DEBUG] Marking connection ${clientId} as dead`);  
    // 这里可以添加更多的清理逻辑  
  }  
  
  shouldForward(context, packet) {  
    // 实现路由逻辑  
    // 检查是否需要转发到其他节点  
    return packet.protocol !== PROTOCOL.SERVICE;  
  }  
  
  // 修复：增强的连接关闭处理  
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
    // 从请求中解析客户端地址  
    const cf = request.cf;  
    return {  
      ip: cf?.colo || 'unknown',  
      port: 0  
    };  
  }  
  
  // 新增：定期清理死连接（可选）  
  cleanupDeadConnections() {  
    for (const [clientId, server] of this.connections) {  
        // 只检查WebSocket状态，不检查超时  
        if (server.readyState !== WebSocket.OPEN) {  
            console.log(`[DEBUG] Cleaning up dead connection: ${clientId}`);  
            this.handleClose(clientId);  
        }  
    }  
}  
  // 新增：定期检查连接状态  
checkConnectionHealth() {  
    const now = Date.now();  
    console.log(`[调试] 开始健康检查，当前连接数: ${this.connections.size}`);  
      
    for (const [clientId, server] of this.connections) {  
        // 只检查WebSocket状态，不检查超时  
        if (server.readyState !== WebSocket.OPEN) {  
            console.log(`[调试] 连接 ${clientId} 已断开，准备清理`);  
            this.handleClose(clientId);  
        }  
    }  
      
    console.log(`[调试] 健康检查完成`);  
}
}

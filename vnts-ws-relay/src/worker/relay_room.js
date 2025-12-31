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
        
    // 设置 WebSocket 消息处理    
    server.addEventListener('message', async (event) => {    
      await this.handleMessage(clientId, event.data);    
    });    
        
    server.addEventListener('close', () => {    
      console.log(`[DEBUG] WebSocket closed: ${clientId}`);    
      this.handleClose(clientId);    
    });    
        
    server.addEventListener('error', (error) => {    
      console.error(`[DEBUG] WebSocket error for ${clientId}:`, error);    
      this.handleClose(clientId);    
    });    
        
    return new Response(null, {    
      status: 101,    
      webSocket: client    
    });    
  }    
  
  async handleMessage(clientId, data) {    
    try {    
      console.log(`[DEBUG] Received data from ${clientId}`);    
      console.log(`[DEBUG] Data type: ${typeof data}`);    
      console.log(`[DEBUG] Data length: ${data ? data.length || data.byteLength : 'null'}`);    
        
      if (!data) {    
        console.log(`[DEBUG] No data received from ${clientId}`);    
        return;    
      }    
        
      // 转换为 Uint8Array    
      let uint8Data;    
      if (data instanceof ArrayBuffer) {    
        uint8Data = new Uint8Array(data);    
      } else if (data instanceof Uint8Array) {    
        uint8Data = data;    
      } else if (ArrayBuffer.isView(data)) {    
        uint8Data = new Uint8Array(data.buffer);    
      } else {    
        console.log(`[DEBUG] Unsupported data type: ${typeof data}`);    
        return;    
      }    
        
      const hexString = Array.from(uint8Data).map(b => b.toString(16).padStart(2, '0')).join('');    
      console.log(`[DEBUG] Data hex: ${hexString}`);    
        
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
        context.linkAddress    
      );    
          
      // 发送响应    
      if (response) {    
        console.log(`[DEBUG] Sending response to ${clientId}, length: ${response.buffer().length}`);    
        server.send(response.buffer());    
      } else {    
        console.log(`[DEBUG] No response generated for ${clientId}`);    
      }    
          
      // 广播到其他连接（如果需要）    
      await this.broadcastPacket(clientId, packet);    
          
    } catch (error) {    
      console.error(`[DEBUG] Message handling error for ${clientId}:`, error);    
      console.error(`[DEBUG] Error stack:`, error.stack);    
    }    
  }    
  
  async broadcastPacket(senderId, packet) {    
    const senderContext = this.contexts.get(senderId);    
        
    for (const [clientId, server] of this.connections) {    
      if (clientId === senderId) continue;    
          
      try {    
        // 根据路由规则决定是否转发    
        if (this.shouldForward(senderContext, packet)) {    
          console.log(`[DEBUG] Broadcasting packet from ${senderId} to ${clientId}`);    
          server.send(packet.buffer());    
        }    
      } catch (error) {    
        console.error(`[DEBUG] Broadcast error to ${clientId}:`, error);    
      }    
    }    
  }    
  
  shouldForward(context, packet) {    
    // 实现路由逻辑    
    // 检查是否需要转发到其他节点    
    return packet.protocol !== PROTOCOL.SERVICE;    
  }    
  
  handleClose(clientId) {    
    console.log(`[DEBUG] Cleaning up connection: ${clientId}`);    
    const context = this.contexts.get(clientId);    
        
    if (context) {    
      // 清理连接    
      this.packetHandler.leave(context);    
      this.contexts.delete(clientId);    
      this.connections.delete(clientId);    
    }    
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
}

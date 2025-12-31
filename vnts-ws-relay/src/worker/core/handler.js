import { NetPacket } from './packet.js';    
import { PROTOCOL, TRANSPORT_PROTOCOL, ENCRYPTION_RESERVED } from './constants.js';    
import { VntContext, AppCache, NetworkInfo, ClientInfo, Ipv4Addr } from './context.js';    
import { AesGcmCipher, randomU64String } from './crypto.js';    
  
export class PacketHandler {    
  constructor(env) {    
    this.env = env;    
    this.cache = new AppCache();    
    this.serverPeerId = 10000001; // VNT 服务器节点 ID    
  }    
  
  async handle(context, packet, addr, tcpSender) {  
  try {  
    console.log(`[DEBUG] Packet routing: protocol=${packet.protocol}, transport=${packet.transportProtocol}, is_gateway=${packet.is_gateway()}`);  
      
    // 检查是否为网关包  
    if (packet.is_gateway()) {  
      console.log(`[DEBUG] Routing to handleServerPacket`);  
      return await this.handleServerPacket(context, packet, addr, tcpSender);  
    } else {  
      console.log(`[DEBUG] Routing to handleClientPacket`);  
      return await this.handleClientPacket(context, packet, addr);  
    }  
  } catch (error) {  
    console.error('Packet handling error:', error);  
    return this.createErrorPacket(addr, packet.source, error.message);  
  }  
}  
  
  async handleServerPacket(context, packet, addr, tcpSender) {
  	console.log(`[DEBUG] handleServerPacket: protocol=${packet.protocol}, transport=${packet.transportProtocol}`);  
    const source = packet.source;    
  
    // 处理服务协议 - 握手请求直接处理    
    if (packet.protocol === PROTOCOL.SERVICE) {
    	console.log(`[DEBUG] SERVICE protocol detected, checking transport=${packet.transportProtocol}`); 
      switch (packet.transportProtocol) {    
        case TRANSPORT_PROTOCOL.HandshakeRequest:    
          return await this.handleHandshake(packet, addr);    
            
        case TRANSPORT_PROTOCOL.SecretHandshakeRequest:    
          return await this.handleSecretHandshake(context, packet, addr);    
            
        case TRANSPORT_PROTOCOL.RegistrationRequest:    
          return await this.handleRegistration(context, packet, addr, tcpSender);    
            
        default:    
          break;    
      }    
    }    
  
    // 解密处理    
    const serverSecret = packet.is_encrypt();    
    if (serverSecret) {    
      if (context.server_cipher) {    
        try {    
          context.server_cipher.decrypt_ipv4(packet);    
        } catch (error) {    
          console.error('Decryption failed:', error);    
          return this.createErrorPacket(addr, source, 'Decryption failed');    
        }    
      } else {    
        console.log('No cipher available for encrypted packet');    
        return this.createErrorPacket(addr, source, 'No key');    
      }    
    }    
  
    // 处理解密后的包    
    let response = await this.handleDecryptedPacket(context, packet, addr, tcpSender, serverSecret);    
        
    if (response) {    
      this.setCommonParams(response, source);    
      if (serverSecret && context.server_cipher) {    
        context.server_cipher.encrypt_ipv4(response);    
      }    
    }    
        
    return response;    
  }    
  
  async handleDecryptedPacket(context, packet, addr, tcpSender, serverSecret) {    
    // 如果没有链接上下文，处理基础协议    
    if (!context.link_context) {    
      return await this.handleNotContext(context, packet, addr, tcpSender, serverSecret);    
    }    
  
    // 有链接上下文时的处理    
    if (packet.protocol === PROTOCOL.CONTROL) {    
      switch (packet.transportProtocol) {    
        case TRANSPORT_PROTOCOL.Ping:    
          return this.handlePing(packet, context.link_context);    
            
        default:    
          break;    
      }    
    }    
  
    // 数据包转发处理    
    return await this.handleDataForward(context, packet, addr, tcpSender);    
  }    
  
  async handleNotContext(context, packet, addr, tcpSender, serverSecret) {    
    if (packet.protocol === PROTOCOL.SERVICE) {    
      if (packet.transportProtocol === TRANSPORT_PROTOCOL.RegistrationRequest) {    
        return await this.handleRegistration(context, packet, addr, tcpSender);    
      }    
    } else if (packet.protocol === PROTOCOL.CONTROL) {    
      if (packet.transportProtocol === TRANSPORT_PROTOCOL.AddrRequest) {    
        return this.handleAddrRequest(addr);    
      }    
    }    
        
    // 返回错误，表示需要先建立上下文    
    return this.createErrorPacket(addr, packet.source, 'No context');    
  }    
  
  async handleHandshake(packet, addr) {  
  try {  
    console.log(`[DEBUG] === HANDSHAKE START ===`);  
      
    const payload = packet.payload();  
    console.log(`[DEBUG] Handshake payload length: ${payload.length}`);  
    console.log(`[DEBUG] Handshake payload hex: ${Array.from(payload).map(b => b.toString(16).padStart(2, '0')).join('')}`);  
      
    const handshakeReq = this.parseHandshakeRequest(payload);  
    console.log(`[DEBUG] Parsed handshake request:`, handshakeReq);  
      
    const response = this.createHandshakeResponse(handshakeReq);  
    console.log(`[DEBUG] Created handshake response, length: ${response.buffer().length}`);  
    console.log(`[DEBUG] Response hex: ${Array.from(response.buffer()).map(b => b.toString(16).padStart(2, '0')).join('')}`);  
      
    console.log(`[DEBUG] === HANDSHAKE END ===`);  
    return response;  
  } catch (error) {  
    console.error('[DEBUG] Handshake error:', error);  
    console.error('[DEBUG] Handshake error stack:', error.stack);  
    return this.createErrorPacket(addr, packet.source, 'Handshake failed');  
  }  
}    
  
  async handleSecretHandshake(context, packet, addr) {    
    console.log(`Secret handshake from ${addr}`);    
        
    // 这里应该实现 RSA 解密和 AES 密钥交换    
    // 简化实现，实际需要完整的加密逻辑    
    try {    
      const response = NetPacket.new_encrypt(ENCRYPTION_RESERVED);    
      response.set_protocol(PROTOCOL.SERVICE);    
      response.set_transport_protocol(TRANSPORT_PROTOCOL.SecretHandshakeResponse);    
      this.setCommonParams(response, packet.source);    
          
      // 创建加密会话（简化）    
      const cipher = new AesGcmCipher(this.generateRandomKey());    
      context.server_cipher = cipher;    
      this.cache.cipher_session.set(addr, cipher);    
          
      return response;    
    } catch (error) {    
      console.error('Secret handshake error:', error);    
      return this.createErrorPacket(addr, packet.source, 'Secret handshake failed');    
    }    
  }    
  
  async handleRegistration(context, packet, addr, tcpSender) {    
    try {    
      const payload = packet.payload();    
      const registrationReq = this.parseRegistrationRequest(payload);    
          
      // 验证注册请求    
      this.validateRegistrationRequest(registrationReq);    
          
      // 创建或获取网络信息    
      const networkInfo = this.getOrCreateNetworkInfo(registrationReq.token);    
          
      // 分配虚拟 IP    
      const virtualIp = this.allocateVirtualIp(networkInfo, registrationReq.device_id);    
          
      // 创建客户端信息    
      const clientInfo = new ClientInfo({    
        virtual_ip: virtualIp,    
        device_id: registrationReq.device_id,    
        name: registrationReq.name,    
        version: registrationReq.version,    
        online: true,    
        address: addr,    
        client_secret_hash: registrationReq.client_secret_hash,    
        tcp_sender: tcpSender,    
        timestamp: Date.now()    
      });    
          
      // 添加到网络    
      networkInfo.clients.set(virtualIp, clientInfo);    
      networkInfo.epoch += 1;    
          
      // 创建链接上下文    
      context.link_context = {    
        group: registrationReq.token,    
        virtual_ip: virtualIp,    
        network_info: networkInfo,    
        timestamp: Date.now()    
      };    
          
      // 创建注册响应    
      const response = this.createRegistrationResponse(virtualIp, networkInfo);    
      return response;    
          
    } catch (error) {    
      console.error('Registration error:', error);    
      return this.createErrorPacket(addr, packet.source, 'Registration failed');    
    }    
  }    
  
  handlePing(packet, linkContext) {    
    const responseSize = 12 + 4 + ENCRYPTION_RESERVED;    
    const response = NetPacket.new_encrypt(responseSize);    
        
    response.set_protocol(PROTOCOL.CONTROL);    
    response.set_transport_protocol(TRANSPORT_PROTOCOL.Pong);    
        
    // 复制 ping 负载    
    const payload = packet.payload();    
    response.set_payload(payload.slice(0, 12));    
        
    // 设置 epoch    
    const pongPayload = response.payload_mut();    
    const view = new DataView(pongPayload.buffer, pongPayload.byteOffset);    
    view.setUint16(12, linkContext.network_info.epoch & 0xFFFF, true);    
        
    return response;    
  }    
  
  handleAddrRequest(addr) {    
    const responseSize = 6 + ENCRYPTION_RESERVED;    
    const response = NetPacket.new_encrypt(responseSize);    
        
    response.set_protocol(PROTOCOL.CONTROL);    
    response.set_transport_protocol(TRANSPORT_PROTOCOL.AddrResponse);    
        
    // 设置地址信息    
    const addrPayload = response.payload_mut();    
    const view = new DataView(addrPayload.buffer, addrPayload.byteOffset);    
        
    // 解析 IPv4 地址    
    const ipv4 = this.parseIpv4(addr.ip);    
    view.setUint32(0, ipv4, true);    
    view.setUint16(4, addr.port || 0, true);    
        
    return response;    
  }    
  
  async handleDataForward(context, packet, addr, tcpSender) {    
    // 增加 TTL    
    if (packet.incr_ttl() > 1) {    
      // 检查是否禁用中继    
      if (this.env.VNT_DISABLE_RELAY === '1') {    
        console.log('Relay disabled, dropping packet');    
        return null;    
      }    
          
      const destination = packet.destination;    
          
      if (this.isBroadcast(destination)) {    
        return await this.broadcastPacket(context.link_context, packet);    
      } else {    
        return await this.forwardToDestination(context.link_context, packet, destination);    
      }    
    }    
    return null;    
  }    
  
  async handleClientPacket(context, packet, addr) {  
  if (!context.link_context) {  
    // 处理已知协议  
    if (packet.protocol === PROTOCOL.SERVICE) {  
      switch (packet.transportProtocol) {  
        case TRANSPORT_PROTOCOL.HandshakeRequest:  
          return await this.handleHandshake(packet, addr);  
        case TRANSPORT_PROTOCOL.RegistrationRequest:  
          return await this.handleRegistration(context, packet, addr, null);  
        default:  
          break;  
      }  
    } else if (packet.protocol === PROTOCOL.CONTROL) {  
      if (packet.transportProtocol === TRANSPORT_PROTOCOL.AddrRequest) {  
        return this.handleAddrRequest(addr);  
      }  
    }  
      
    // 对未知包发送握手响应，引导客户端  
    const response = this.createHandshakeResponse({  
      version: "1.0.0",  
      secret: false,  
      key_finger: ""  
    });  
      
    // 设置响应的目标地址  
    response.set_destination(packet.source);  
    response.set_source(this.serverPeerId);  
      
    return response;  
  }  
      
  return await this.forwardPacket(context.link_context, packet);  
}
  
  async forwardPacket(linkContext, packet) {    
    const destination = packet.destination;    
        
    if (this.isBroadcast(destination)) {    
      return await this.broadcastPacket(linkContext, packet);    
    } else {    
      const targetClient = linkContext.network_info.clients.get(destination);    
      if (targetClient && targetClient.online && targetClient.tcp_sender) {    
        // 发送到特定客户端    
        try {    
          await targetClient.tcp_sender.send(packet.buffer().to_vec());    
        } catch (error) {    
          console.error('Forward failed:', error);    
          targetClient.online = false;    
        }    
      }    
    }    
    return null;    
  }    
  
  async broadcastPacket(linkContext, packet) {    
    const networkInfo = linkContext.network_info;    
    const sender = packet.source;    
        
    for (const [virtualIp, client] of networkInfo.clients) {    
      if (client.virtual_ip !== sender && client.online && client.tcp_sender) {    
        try {    
          await client.tcp_sender.send(packet.buffer().to_vec());    
        } catch (error) {    
          console.error(`Broadcast to ${virtualIp} failed:`, error);    
          client.online = false;    
        }    
      }    
    }    
    return null;    
  }    
  
  async forwardToDestination(linkContext, packet, destination) {    
    const targetClient = linkContext.network_info.clients.get(destination);    
    if (targetClient && targetClient.online && targetClient.tcp_sender) {    
      try {    
        await targetClient.tcp_sender.send(packet.buffer().to_vec());    
      } catch (error) {    
        console.error(`Forward to ${destination} failed:`, error);    
        targetClient.online = false;    
      }    
    }    
    return null;    
  }    
  
  async leave(context) {    
    await context.leave(this.cache);    
  }    
  
  // 辅助方法    
  setCommonParams(packet, source) {    
    packet.set_source(this.serverPeerId);    
    packet.set_destination(source);    
  }    
  
  createErrorPacket(addr, destination, message) {  
  try {  
    const errorPacket = NetPacket.new_encrypt(ENCRYPTION_RESERVED);  
      
    // 设置协议字段  
    errorPacket.set_protocol(PROTOCOL.ERROR);  
    errorPacket.set_destination(destination);  
    errorPacket.set_source(this.serverPeerId);  
      
    return errorPacket;  
  } catch (error) {  
    console.error('Failed to create error packet:', error);  
    // 返回一个基本的错误包  
    const fallbackPacket = NetPacket.new_encrypt(ENCRYPTION_RESERVED);  
    return fallbackPacket;  
  }  
}   
  
  createHandshakeResponse(request) {    
    const responseData = {    
      version: "1.0.0",    
      key_finger: new Uint8Array(32),    
      public_key: new Uint8Array(0),    
      secret: false    
    };    
        
    const responseBytes = this.encodeHandshakeResponse(responseData);    
    const response = NetPacket.new_encrypt(responseBytes.length + ENCRYPTION_RESERVED);    
        
    response.set_protocol(PROTOCOL.SERVICE);    
    response.set_transport_protocol(TRANSPORT_PROTOCOL.HandshakeResponse);    
    response.set_payload(responseBytes);    
        
    return response;    
  }    
  
  createRegistrationResponse(virtualIp, networkInfo) {    
    const responseData = {    
      virtual_ip: virtualIp,    
      gateway: networkInfo.gateway,    
      netmask: networkInfo.netmask,    
      epoch: networkInfo.epoch,    
      device_info_list: Array.from(networkInfo.clients.values()).map(client => ({    
        virtual_ip: client.virtual_ip,    
        device_id: client.device_id,    
        name: client.name,    
        online: client.online    
      })),    
      public_ip: networkInfo.public_ip,    
      public_port: networkInfo.public_port    
    };    
        
    const responseBytes = this.encodeRegistrationResponse(responseData);    
    const response = NetPacket.new_encrypt(responseBytes.length + ENCRYPTION_RESERVED);    
        
    response.set_protocol(PROTOCOL.SERVICE);    
    response.set_transport_protocol(TRANSPORT_PROTOCOL.RegistrationResponse);    
    response.set_payload(responseBytes);    
        
    return response;    
  }    
  
  // 协议解析方法    
  parseHandshakeRequest(payload) {    
    const { parseHandshakeRequest } = require('./protos.js');    
    try {    
      return parseHandshakeRequest(payload);    
    } catch (error) {    
      console.error('Failed to parse handshake request:', error);    
      throw new Error('Invalid handshake request format');    
    }    
  }    
  
  parseRegistrationRequest(payload) {    
    const { parseRegistrationRequest } = require('./protos.js');    
    try {    
      return parseRegistrationRequest(payload);    
    } catch (error) {    
      console.error('Failed to parse registration request:', error);    
      throw new Error('Invalid registration request format');    
    }    
  }    
  
  encodeHandshakeResponse(data) {    
    const { createHandshakeResponse } = require('./protos.js');    
    return createHandshakeResponse(data.version, data.secret, data.key_finger);    
  }    
  
  encodeRegistrationResponse(data) {    
    const { createRegistrationResponse } = require('./protos.js');    
    return createRegistrationResponse(    
      data.virtual_ip,    
      data.gateway,    
      data.netmask,    
      data.epoch,    
      data.device_info_list,    
      data.public_ip,    
      data.public_port    
    );    
  }    
  
  validateRegistrationRequest(request) {    
    if (!request.token || request.token.length === 0 || request.token.length > 128) {    
      throw new Error('Invalid token length');    
    }    
    if (!request.device_id || request.device_id.length === 0 || request.device_id.length > 128) {    
      throw new Error('Invalid device_id length');    
    }    
    if (!request.name || request.name.length === 0 || request.name.length > 128) {    
      throw new Error('Invalid name length');    
    }    
  }    
  
  parseIpv4(ipStr) {    
    if (!ipStr || typeof ipStr !== 'string') {    
      return 0;    
    }    
    const parts = ipStr.split('.').map(Number);    
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];    
  }    
  
  isBroadcast(addr) {    
    return addr === 0xFFFFFFFF || addr === 0;    
  }    
  
  generateRandomKey() {    
    const array = new Uint8Array(32);    
    crypto.getRandomValues(array);    
    return array;    
  }    
  
  // 网络管理方法    
  getOrCreateNetworkInfo(token) {    
    if (!this.cache.networks.has(token)) {    
      this.cache.networks.set(token, new NetworkInfo({    
        token: token,    
        gateway: 0x0A000001, // 10.0.0.1    
        netmask: 0xFFFFFF00, // 255.255.255.0    
        epoch: 0,    
        clients: new Map(),    
        public_ip: 0,    
        public_port: 0    
      }));    
    }    
    return this.cache.networks.get(token);    
  }    
  
  allocateVirtualIp(networkInfo, deviceId) {    
    // 简单的 IP 分配策略：从 10.0.0.2 开始分配    
    const baseIp = 0x0A000002; // 10.0.0.2    
    let currentIp = baseIp;    
      
    while (networkInfo.clients.has(currentIp)) {    
      currentIp++;    
      // 防止超出子网范围    
      if ((currentIp & 0xFF) > 254) {    
        throw new Error('No available IP addresses');    
      }    
    }    
      
    return currentIp;    
  }    
}

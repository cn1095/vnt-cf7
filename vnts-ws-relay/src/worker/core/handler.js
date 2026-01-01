import { NetPacket } from './packet.js';    
import { PROTOCOL, TRANSPORT_PROTOCOL, ENCRYPTION_RESERVED } from './constants.js';    
import { VntContext, AppCache, NetworkInfo, ClientInfo, Ipv4Addr } from './context.js';    
import { AesGcmCipher, randomU64String } from './crypto.js';    
  
export class PacketHandler {    
  constructor(env) {    
    this.env = env;    
    this.cache = new AppCache();
    this.cache.networks = new Map();
  }
  calculateGateway(networkInfo) {  
  // 网关是网段的 .1 地址  
  return (networkInfo.network & networkInfo.netmask) | 0x01;  
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
  console.log(`[调试] 处理服务器包: 协议=${packet.protocol}, 传输=${packet.transportProtocol}`);   
  const source = packet.source;  
  
  // 处理服务协议 - 握手请求直接处理      
  if (packet.protocol === PROTOCOL.SERVICE) {  
    console.log(`[调试] 检测到 SERVICE 协议, 传输类型=${packet.transportProtocol}`);   
    switch (packet.transportProtocol) {      
      case TRANSPORT_PROTOCOL.HandshakeRequest:      
        return await this.handleHandshake(packet, addr);      
          
      case TRANSPORT_PROTOCOL.SecretHandshakeRequest:
      	console.log(`[调试] 检测到注册请求, 调用 handleRegistration`);  
        return await this.handleSecretHandshake(context, packet, addr);      
          
      case TRANSPORT_PROTOCOL.RegistrationRequest:      
        return await this.handleRegistration(context, packet, addr, tcpSender);      
          
      default:      
        break;      
    }      
  }  
  
  // 新增：处理 CONTROL 协议的握手请求  
  if (packet.protocol === PROTOCOL.CONTROL) {
  	console.log(`[调试] 检测到 CONTROL 协议, 传输类型=${packet.transportProtocol}`);
    if (packet.transportProtocol === TRANSPORT_PROTOCOL.HandshakeRequest) {  
      console.log(`[DEBUG] CONTROL HandshakeRequest detected, handling...`);  
      return await this.handleHandshake(packet, addr);  
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
    console.log(`[调试] === 握手开始 ===`);  
      
    const payload = packet.payload();  
    const handshakeReq = this.parseHandshakeRequest(payload);  
      
    console.log(`[调试] 客户端握手请求:`, handshakeReq);  
      
    const response = this.createHandshakeResponse(handshakeReq);  
      
    // 确保响应使用 SERVICE 协议  
    response.set_protocol(PROTOCOL.SERVICE);  
    response.set_transport_protocol(TRANSPORT_PROTOCOL.HandshakeResponse);  
      
    // 使用默认网关  
    const defaultGateway = 0x0A240001; // 10.36.0.1  
    this.setCommonParams(response, packet.source, defaultGateway);  
      
    // 关键修复：直接修改最终缓冲区的 TTL  
    const finalBuffer = response.buffer();  
    const view = new DataView(finalBuffer.buffer || finalBuffer);  
    const currentTtl = view.getUint8(3);  
    console.log(`[调试] 发送前 TTL 检查: 0x${currentTtl.toString(16).padStart(2, '0')}`);  
      
    // 强制设置 TTL 为 0xff (原始TTL=15, 当前TTL=15)  
    view.setUint8(3, 0xff);  
    console.log(`[调试] 强制修复 TTL 为: 0xff`);  
      
    console.log(`[调试] 握手响应协议: ${response.protocol}, 传输: ${response.transportProtocol}`);  
    console.log(`[调试] 握手响应网关: ${this.formatIp(defaultGateway)}`);  
    console.log(`[调试] === 握手结束 ===`);  
      
    return response;  
  } catch (error) {  
    console.error('[调试] 握手错误:', error);  
    return this.createErrorPacket(addr, packet.source, '握手失败');  
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
  	console.log(`[DEBUG] Registration request received`);      
    try {      
      const payload = packet.payload();      
      const registrationReq = this.parseRegistrationRequest(payload);      
            
      // 获取客户端请求的IP    
      const requestedIp = registrationReq.virtual_ip || 0;      
            
      // 创建或获取网络信息      
      const networkInfo = this.getOrCreateNetworkInfo(registrationReq.token, requestedIp);     
            
      // 分配虚拟 IP - 如果客户端指定了IP就直接使用，否则分配新的  
      const virtualIp = requestedIp !== 0 ? requestedIp : this.allocateVirtualIp(networkInfo, registrationReq.device_id); 
      console.log(`[DEBUG] Allocated IP: ${this.formatIp(virtualIp)}, 网关: ${this.formatIp(networkInfo.gateway)}`);     
            
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
      console.log(`[DEBUG] Sending registration response: IP=${this.formatIp(virtualIp)}, Gateway=${this.formatIp(networkInfo.gateway)}`);     
      return response;      
            
    } catch (error) {      
      console.error('Registration error:', error);      
      return this.createErrorPacket(addr, packet.source, 'Registration failed');      
    }      
  }
  
  handlePing(packet, linkContext) {  
  console.log(`[DEBUG] Handling ping packet`);  
    
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
    
  console.log(`[DEBUG] Pong response created, epoch: ${linkContext.network_info.epoch}`);  
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
    // 处理服务协议  
    if (packet.protocol === PROTOCOL.SERVICE) {  
      switch (packet.transportProtocol) {  
        case TRANSPORT_PROTOCOL.HandshakeRequest:  
          return await this.handleHandshake(packet, addr);  
        case TRANSPORT_PROTOCOL.RegistrationRequest:  
          return await this.handleRegistration(context, packet, addr, null);  
        default:  
          break;  
      }  
    }  
    // 移除默认握手响应，改为错误响应  
    return this.createErrorPacket(addr, packet.source, 'Invalid packet sequence');  
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
  setCommonParams(packet, source, gateway) {  
  packet.set_default_version();  
  packet.set_destination(source);  
  packet.set_source(gateway);  // 使用动态计算的网关  
  packet.first_set_ttl(15);    // MAX_TTL = 0b1111 = 15  
  packet.set_gateway_flag(true);  
}  
  
// 新增：计算客户端地址的方法  
calculateClientAddress(source) {  
  // 根据原始实现，客户端地址应该基于某种算法计算  
  // 这里暂时使用 source，但可能需要根据实际协议调整  
  return source;  
}    
  
  createErrorPacket(addr, destination, message) {  
  try {  
    console.log(`[DEBUG] Creating error packet: ${message}`);  
      
    const errorPacket = NetPacket.new_encrypt(ENCRYPTION_RESERVED);  
      
    // 设置协议字段  
    errorPacket.set_protocol(PROTOCOL.ERROR);  
    errorPacket.set_destination(destination);  
    errorPacket.set_source(this.serverPeerId);  
      
    // 尝试设置错误消息（如果协议支持）  
    try {  
      const errorPayload = new TextEncoder().encode(message.substring(0, 100)); // 限制长度  
      errorPacket.set_payload(errorPayload);  
    } catch (payloadError) {  
      console.warn(`[DEBUG] Failed to set error payload:`, payloadError);  
    }  
      
    return errorPacket;  
  } catch (error) {  
    console.error('Failed to create error packet:', error);  
    // 返回一个基本的错误包  
    const fallbackPacket = NetPacket.new_encrypt(ENCRYPTION_RESERVED);  
    fallbackPacket.set_protocol(PROTOCOL.ERROR);  
    fallbackPacket.set_source(this.serverPeerId);  
    return fallbackPacket;  
  }  
}  
  
  createHandshakeResponse(request) {  
  const clientVersion = request.version || "1.2.16";  
    
  const responseData = {  
    version: clientVersion,  
    secret: false,  
    public_key: new Uint8Array(0),       
    key_finger: ""  
  };  
    
  const responseBytes = this.encodeHandshakeResponse(responseData);  
    
  // 使用普通数据包而不是加密数据包  
  const response = NetPacket.new(responseBytes.length);  
    
  response.set_protocol(PROTOCOL.SERVICE);  
  response.set_transport_protocol(TRANSPORT_PROTOCOL.HandshakeResponse);  
  response.set_payload(responseBytes);  
    
  return response;  
}
  
  createRegistrationResponse(virtualIp, networkInfo) {      
  const responseData = {      
    virtual_ip: virtualIp,      
    virtual_gateway: networkInfo.gateway,      
    virtual_netmask: networkInfo.netmask,      
    epoch: networkInfo.epoch,      
    device_info_list: Array.from(networkInfo.clients.values()).map(client => ({        
      name: client.name,                        // ✅ 添加 name 字段  
      virtual_ip: client.virtual_ip,        
      device_status: client.online ? 1 : 0,     // ✅ 添加 device_status  
      client_secret: false,                    // ✅ 添加 client_secret  
      client_secret_hash: new Uint8Array(0),   // ✅ 添加 client_secret_hash  
      wireguard: false                         // ✅ 添加 wireguard  
    })),      
    public_ip: networkInfo.public_ip,      
    public_port: networkInfo.public_port,
    public_ipv6: new Uint8Array(0)      
  };      
        
  const responseBytes = this.encodeRegistrationResponse(responseData);      
  const response = NetPacket.new(responseBytes.length);   
  response.set_default_version(); 
        
  response.set_protocol(PROTOCOL.SERVICE);      
  response.set_transport_protocol(TRANSPORT_PROTOCOL.RegistrationResponse);    
    
  // 添加这些关键行：  
  response.set_source(networkInfo.gateway);      // 设置源地址为网关  
  response.set_destination(0xffffffff);          // 设置目标地址为客户端  
  response.set_gateway_flag(true);              // 设置网关标志  
  response.first_set_ttl(15);
    
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
  return createHandshakeResponse(data.version, data.secret, data.public_key, data.key_finger);  
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
  getOrCreateNetworkInfo(token, requestedIp = 0) {  
  if (!this.cache.networks.has(token)) {  
    let gateway = 0x0A240001; // 默认 10.36.0.1  
    let network = 0x0A240000; // 默认 10.36.0.0  
    let netmask = 0xFFFFFF00; // 255.255.255.0  
      
    // 如果第一个客户端指定了IP，根据其更新网段  
    if (requestedIp !== 0) {  
      network = requestedIp & netmask;  
      gateway = network | 0x01; // 网段的 .1 地址  
      console.log(`[DEBUG] Network updated: gateway=${this.formatIp(gateway)}, network=${this.formatIp(network)}`);  
    }  
      
    this.cache.networks.set(token, new NetworkInfo(network, netmask, gateway));  
  }  
  return this.cache.networks.get(token);  
}  
  
// 辅助方法：格式化 IP 地址用于日志  
formatIp(ipUint32) {  
  return `${(ipUint32 >>> 24) & 0xFF}.${(ipUint32 >>> 16) & 0xFF}.${(ipUint32 >>> 8) & 0xFF}.${ipUint32 & 0xFF}`;  
}   
  
  allocateVirtualIp(networkInfo, deviceId) {    
    // 简单的 IP 分配策略：从 10.0.0.2 开始分配    
    const baseIp = 0x0A240002; // 10.0.0.2    
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
  validatePacket(packet) {  
  const buffer = packet.buffer();  
    
  // 修复：确保转换为 ArrayBuffer  
  let arrayBuffer;  
  if (buffer instanceof ArrayBuffer) {  
    arrayBuffer = buffer;  
  } else if (buffer.buffer) {  
    arrayBuffer = buffer.buffer;  
  } else {  
    arrayBuffer = buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);  
  }  
    
  const view = new DataView(arrayBuffer);  
    
  console.log(`[DEBUG] Complete packet hex:`, Array.from(buffer).map(b => b.toString(16).padStart(2, '0')).join(''));  
    
  // 验证地址字段  
  const sourceBytes = [  
    view.getUint8(4), view.getUint8(5),   
    view.getUint8(6), view.getUint8(7)  
  ];  
  const destBytes = [  
    view.getUint8(8), view.getUint8(9),  
    view.getUint8(10), view.getUint8(11)  
  ];  
    
  console.log(`[DEBUG] Packet source: [${sourceBytes.join(', ')}]`);  
  console.log(`[DEBUG] Packet dest: [${destBytes.join(', ')}]`);  
}   
}

import { Ipv4Addr } from './utils.js';  
  
/**  
 * VNT 连接上下文  
 * 对应 Rust 中的 VntContext 结构体  
 */  
export class VntContext {  
  constructor(options = {}) {  
    this.link_context = options.linkContext || null;  
    this.server_cipher = options.serverCipher || null;  
    this.link_address = options.linkAddress || null;  
  }  
  
  /**  
   * 离开连接，清理资源  
   * 对应 Rust 中的 leave 方法  
   */  
  async leave(cache) {  
    // 清理服务端加密会话  
    if (this.server_cipher) {  
      cache.cipher_session.delete(this.link_address);  
    }  
  
    // 清理链接上下文  
    if (this.link_context) {  
      const networkInfo = cache.virtual_network.get(this.link_context.group);  
      if (networkInfo) {  
        const clients = networkInfo.clients;  
          
        // 获取客户端信息  
        const clientInfo = clients.get(this.link_context.virtual_ip);  
        if (clientInfo) {  
          // 验证地址和时间戳匹配  
          if (clientInfo.address !== this.link_address ||  
              clientInfo.timestamp !== this.link_context.timestamp) {  
            return;  
          }  
            
          // 更新客户端状态  
          clientInfo.online = false;  
          clientInfo.tcp_sender = null;  
          networkInfo.epoch += 1;  
        }  
          
        // 插入 IP 会话记录  
        cache.insert_ip_session(  
          [this.link_context.group, this.link_context.virtual_ip],  
          this.link_address  
        );  
      }  
    }  
  }  
}  
  
/**  
 * VNT 链接上下文  
 * 对应 Rust 中的 LinkVntContext 结构体  
 */  
export class LinkVntContext {  
  constructor(options = {}) {  
    this.network_info = options.networkInfo || null;  
    this.group = options.group || '';  
    this.virtual_ip = options.virtualIp || 0;  
    this.broadcast = options.broadcast || new Ipv4Addr([255, 255, 255, 255]);  
    this.timestamp = options.timestamp || Date.now();  
  }  
}  
  
/**  
 * 网络信息结构  
 * 对应 Rust 中的 NetworkInfo  
 */  
export class NetworkInfo {  
  constructor(network, netmask, gateway) {  
    this.network = network;  
    this.netmask = netmask;  
    this.gateway = gateway;  
    this.clients = new Map();  
    this.epoch = 0;  
  }  
  
  static new(network, netmask, gateway) {  
    return new NetworkInfo(network, netmask, gateway);  
  }  
}  
  
/**  
 * 客户端信息结构  
 * 对应 Rust 中的 ClientInfo  
 */  
export class ClientInfo {  
  constructor(options = {}) {  
    this.virtual_ip = options.virtualIp || 0;  
    this.device_id = options.deviceId || '';  
    this.name = options.name || '';  
    this.version = options.version || '';  
    this.wireguard = options.wireguard || null;  
    this.online = options.online || false;  
    this.address = options.address || { ip: '0.0.0.0', port: 0 };  
    this.client_secret = options.clientSecret || false;  
    this.client_secret_hash = options.clientSecretHash || [];  
    this.server_secret = options.serverSecret || false;  
    this.tcp_sender = options.tcpSender || null;  
    this.wg_sender = options.wgSender || null;  
    this.client_status = options.clientStatus || null;  
    this.last_join_time = options.lastJoinTime || new Date();  
    this.timestamp = options.timestamp || Date.now();  
  }  
}  
  
/**  
 * 应用缓存结构  
 * 对应 Rust 中的 AppCache  
 */  
export class AppCache {  
  constructor() {  
    // 虚拟网络映射：group -> NetworkInfo  
    this.virtual_network = new Map();  
      
    // IP 会话映射：(group, ip) -> address  
    this.ip_session = new Map();  
      
    // 加密会话映射：address -> cipher  
    this.cipher_session = new Map();  
      
    // 认证映射：token -> ()  
    this.auth_map = new Map();  
      
    // WireGuard 组映射：public_key -> config  
    this.wg_group_map = new Map();  
  }  
  
  /**  
   * 插入 IP 会话  
   */  
  async insert_ip_session(key, value) {  
    this.ip_session.set(JSON.stringify(key), value);  
  }  
  
  /**  
   * 获取 IP 会话  
   */  
  get_ip_session(key) {  
    return this.ip_session.get(JSON.stringify(key));  
  }  
  
  /**  
   * 删除 IP 会话  
   */  
  delete_ip_session(key) {  
    return this.ip_session.delete(JSON.stringify(key));  
  }  
}  
  
/**  
 * IPv4 地址工具类  
 */  
export class Ipv4Addr {  
  constructor(octets) {  
    this.octets = octets;  
  }  
  
  static from(u32) {  
    return new Ipv4Addr([  
      (u32 >>> 24) & 0xFF,  
      (u32 >>> 16) & 0xFF,  
      (u32 >>> 8) & 0xFF,  
      u32 & 0xFF  
    ]);  
  }  
  
  toString() {  
    return this.octets.join('.');  
  }  
  
  valueOf() {  
    return (this.octets[0] << 24) |   
           (this.octets[1] << 16) |   
           (this.octets[2] << 8) |   
           this.octets[3];  
  }  
}  
  
/**  
 * 客户端状态信息  
 * 对应 Rust 中的 ClientStatusInfo  
 */  
export class ClientStatusInfo {  
  constructor() {  
    this.p2p_list = [];  
    this.up_stream = 0;  
    this.down_stream = 0;  
    this.is_cone = false;  
    this.update_time = new Date();  
  }  
}

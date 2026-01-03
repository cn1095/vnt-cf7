import { NetPacket } from "./packet.js";
import {
  PROTOCOL,
  TRANSPORT_PROTOCOL,
  IP_TURN_TRANSPORT_PROTOCOL,
  ENCRYPTION_RESERVED,
} from "./constants.js";
import {
  VntContext,
  AppCache,
  NetworkInfo,
  ClientInfo,
  Ipv4Addr,
} from "./context.js";
import { AesGcmCipher, randomU64String } from "./crypto.js";
import { logger } from "./logger.js";

export class PacketHandler {
  constructor(env) {
    this.env = env;
    this.cache = new AppCache();
    this.cache.networks = new Map();
    this.cachedEpoch = 0;
    this.lastEpochUpdate = 0;
    this.rsaCipher = null;
    // 如果配置了服务端加密，生成RSA密钥对
    // if (env.SERVER_ENCRYPT === "true") {
    //  this.initializeRsaCipher();
    // }
  }

 // 设置RSA密钥（由RelayRoom调用）  
  setRsaCipher(rsaCipher) {  
    this.rsaCipher = rsaCipher;  
  }

  calculateGateway(networkInfo) {
    // 网关是网段的 .1 地址
    return (networkInfo.network & networkInfo.netmask) | 0x01;
  }

  async handle(context, packet, addr, tcpSender) {
    try {
      logger.debug(
        `数据包路由: 协议=${packet.protocol}, 传输=${
          packet.transportProtocol
        }, 是否网关=${packet.is_gateway()}`
      );

      // 检查是否为网关包
      if (packet.is_gateway()) {
        logger.debug(`路由到服务器包处理函数`);
        return await this.handleServerPacket(context, packet, addr, tcpSender);
      } else {
        logger.debug(`路由到客户端包处理函数`);
        return await this.handleClientPacket(context, packet, addr);
      }
    } catch (error) {
      logger.error(`数据包处理错误:`, error);
      return this.createErrorPacket(addr, packet.source, error.message);
    }
  }

  async handleServerPacket(context, packet, addr, tcpSender) {
    logger.debug(
      `处理服务器包: 协议=${packet.protocol}, 传输=${packet.transportProtocol}`
    );
    const source = packet.source;

    // 处理服务协议 - 握手请求直接处理
    if (packet.protocol === PROTOCOL.SERVICE) {
      logger.debug(`检测到 SERVICE 协议, 传输类型=${packet.transportProtocol}`);
      switch (packet.transportProtocol) {
        case TRANSPORT_PROTOCOL.HandshakeRequest:
          logger.debug(`处理握手请求 (HandshakeRequest)`);
          return await this.handleHandshake(packet, addr);

        case TRANSPORT_PROTOCOL.SecretHandshakeRequest:
          logger.debug(`处理加密握手请求，调用 handleSecretHandshake`);
          return await this.handleSecretHandshake(context, packet, addr);

        case TRANSPORT_PROTOCOL.RegistrationRequest:
          logger.debug(`处理注册请求 (RegistrationRequest)`);
          return await this.handleRegistration(
            context,
            packet,
            addr,
            tcpSender
          );

        default:
          logger.debug(`未知的传输协议类型: ${packet.transportProtocol}`);
          break;
      }
    }

    // 处理 CONTROL 协议的握手请求
    if (packet.protocol === PROTOCOL.CONTROL) {
      logger.debug(`检测到 CONTROL 协议, 传输类型=${packet.transportProtocol}`);
      if (packet.transportProtocol === TRANSPORT_PROTOCOL.HandshakeRequest) {
        logger.debug(`CONTROL 握手请求检测到，开始处理`);
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
          logger.error(`解密失败:`, error);
          return this.createErrorPacket(addr, source, "Decryption failed");
        }
      } else {
        logger.warn(`加密数据包无可用密钥`);
        return this.createErrorPacket(addr, source, "No key");
      }
    }

    // 处理解密后的包
    let response = await this.handleDecryptedPacket(
      context,
      packet,
      addr,
      tcpSender,
      serverSecret
    );

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
      return await this.handleNotContext(
        context,
        packet,
        addr,
        tcpSender,
        serverSecret
      );
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

    // 处理 IpTurn 协议
    if (packet.protocol === PROTOCOL.IPTURN) {
      return await this.handleIpTurn(
        context,
        packet,
        addr,
        tcpSender,
        serverSecret
      );
    }

    // 数据包转发处理
    return await this.handleDataForward(context, packet, addr, tcpSender);
  }

  // IpTurn 协议处理
  async handleIpTurn(context, packet, addr, tcpSender, serverSecret) {
    const destination = packet.destination;
    const source = packet.source;

    logger.debug(
      `处理IP隧道协议，来源: ${this.formatIp(source)}, 目标: ${this.formatIp(
        destination
      )}`
    );

    switch (packet.transportProtocol) {
      case IP_TURN_TRANSPORT_PROTOCOL.Ipv4:
        logger.debug(`[IpTurn-路由] 路由到IPv4处理器`);
        return await this.handleIpv4Packet(
          context,
          packet,
          source,
          destination,
          addr,
          tcpSender,
          serverSecret
        );

      case IP_TURN_TRANSPORT_PROTOCOL.WGIpv4:
        logger.debug(`[IpTurn-路由] 路由到WireGuard IPv4处理器`);
        // WireGuard 数据包转发
        return await this.handleWgIpv4(context, packet, destination);

      case IP_TURN_TRANSPORT_PROTOCOL.Ipv4Broadcast:
        logger.debug(`[IpTurn-路由] 路由到IPv4广播处理器`);
        // 广播包处理
        return await this.handleIpv4Broadcast(context, packet);

      default:
        logger.warn(
          `[IpTurn-警告] 未知的传输协议类型: ${packet.transportProtocol}`
        );
        break;
    }
  }

  // 处理 IPv4 数据包（包括 ICMP ping）
  async handleIpv4Packet(
    context,
    packet,
    source,
    destination,
    addr,
    tcpSender,
    serverSecret
  ) {
    try {
      // 解析 IPv4 包
      logger.debug(
        `开始处理IPv4数据包，来源: ${this.formatIp(
          source
        )}, 目标: ${this.formatIp(destination)}`
      );
      const ipv4Data = packet.payload;
      const ipv4Packet = this.parseIpv4Packet(ipv4Data);

      if (!ipv4Packet) {
        logger.warn(`IPv4包解析失败`);
        return null;
      }
      logger.debug(
        `协议=${ipv4Packet.protocol}, 目标=${this.formatIp(
          destination
        )}, 网关=${this.formatIp(context.link_context.network_info.gateway)}`
      );

      // 检查是否是 ICMP ping 包
      if (
        ipv4Packet.protocol === 1 &&
        destination === context.link_context.network_info.gateway
      ) {
        logger.info(`检测到发往网关的ICMP ping请求`);
        const icmpPacket = this.parseIcmpPacket(ipv4Packet.payload);

        if (icmpPacket && icmpPacket.type === 8) {
          logger.info(`创建ICMP Echo Reply响应`);
          // 创建 ICMP Echo Reply
          return this.createPingResponse(
            packet,
            source,
            destination,
            ipv4Packet,
            icmpPacket
          );
        }
      }

      // 对于其他 IP 包，进行转发
      logger.debug(`转发IPv4数据包到目标: ${this.formatIp(destination)}`);
      return await this.forwardIpPacket(context, packet, destination);
    } catch (error) {
      logger.error(`处理IPv4包时发生异常: ${error.message}`, error);
      return null;
    }
  }

  // 创建 ping 响应
  createPingResponse(
    originalPacket,
    source,
    destination,
    ipv4Packet,
    icmpPacket
  ) {
    // 响应的 ICMP 包
    const responseIcmp = {
      type: 0, // Echo Reply
      code: 0,
      checksum: 0,
      identifier: icmpPacket.identifier,
      sequenceNumber: icmpPacket.sequenceNumber,
      data: icmpPacket.data,
    };

    // 计算校验和
    responseIcmp.checksum = this.calculateIcmpChecksum(responseIcmp);

    // 响应的 IPv4 包
    const responseIpv4 = {
      version: 4,
      headerLength: 5,
      totalLength: 20 + responseIcmp.data.length,
      identification: ipv4Packet.identification,
      flags: 0,
      fragmentOffset: 0,
      ttl: 64, // 标准 TTL 值
      protocol: 1, // ICMP
      headerChecksum: 0,
      sourceIp: this.formatIp(destination), // 字符串格式
      destIp: this.formatIp(source), // 字符串格式
      payload: this.serializeIcmpPacket(responseIcmp),
    };

    // 计算 IPv4 校验和
    responseIpv4.headerChecksum = this.calculateIpv4Checksum(responseIpv4);

    // 创建 VNT 协议包
    const responsePacket = NetPacket.new(20 + responseIcmp.data.length);

    // 设置 VNT 包头
    responsePacket.set_protocol(PROTOCOL.IPTURN);
    responsePacket.set_transport_protocol(IP_TURN_TRANSPORT_PROTOCOL.Ipv4);
    responsePacket.set_source(destination); // 网关地址作为源
    responsePacket.set_destination(source); // 客户端地址作为目标
    responsePacket.set_gateway_flag(true); // 标记为网关包
    responsePacket.first_set_ttl(15); // 设置 VNT TTL

    // 设置 IPv4 包作为载荷
    responsePacket.set_payload(this.serializeIpv4Packet(responseIpv4));

    return responsePacket;
  }

  // 转发 IP 包到目标客户端
  async forwardIpPacket(context, packet, destination) {
    logger.debug(
      `[IP转发-开始] 开始转发IP包到目标: ${this.formatIp(destination)}`
    );
    // 查找目标客户端
    const targetClient = context.link_context.clients.get(
      destination.toString()
    );

    if (!targetClient || !targetClient.online) {
      logger.warn(
        `[IP转发-警告] 目标客户端 ${this.formatIp(destination)} 不在线或不存在`
      );
      return null;
    }

    logger.debug(
      `[IP转发-客户端] 找到目标客户端，连接类型: ${
        targetClient.tcpSender ? "TCP" : "UDP"
      }`
    );
    // 转发到目标客户端
    if (targetClient.tcpSender) {
      logger.debug(`[IP转发-TCP] 通过TCP连接转发数据包`);
      await targetClient.tcpSender.send(packet.buffer);
    } else {
      // UDP 转发
      logger.debug(
        `[IP转发-UDP] 通过UDP转发数据包到: ${JSON.stringify(
          targetClient.address
        )}`
      );
      await this.udp.send(packet.buffer, targetClient.address);
    }
    logger.info(
      `[IP转发-完成] 数据包已成功转发到 ${this.formatIp(destination)}`
    );

    return null;
  }

  // 辅助方法：解析 IPv4 包
  parseIpv4Packet(data) {
    if (data.length < 20) return null;

    const version = (data[0] >> 4) & 0x0f;
    if (version !== 4) return null;

    const headerLength = (data[0] & 0x0f) * 4;
    const totalLength = (data[2] << 8) | data[3];
    const protocol = data[9];
    const sourceIp = `${data[12]}.${data[13]}.${data[14]}.${data[15]}`;
    const destIp = `${data[16]}.${data[17]}.${data[18]}.${data[19]}`;

    return {
      version,
      headerLength,
      totalLength,
      protocol,
      sourceIp,
      destIp,
      payload: data.slice(headerLength),
    };
  }

  // 辅助方法：解析 ICMP 包
  parseIcmpPacket(data) {
    if (data.length < 8) return null;

    return {
      type: data[0],
      code: data[1],
      checksum: (data[2] << 8) | data[3],
      identifier: (data[4] << 8) | data[5],
      sequenceNumber: (data[6] << 8) | data[7],
      data: data.slice(8),
    };
  }

  // 辅助方法：计算 ICMP 校验和
  calculateIcmpChecksum(icmpPacket) {
    const data = this.serializeIcmpPacket(icmpPacket);
    let sum = 0;

    for (let i = 0; i < data.length; i += 2) {
      if (i + 1 < data.length) {
        sum += (data[i] << 8) | data[i + 1];
      } else {
        sum += data[i] << 8;
      }
    }

    while (sum >> 16) {
      sum = (sum & 0xffff) + (sum >> 16);
    }

    return ~sum & 0xffff;
  }

  // 辅助方法：计算 IPv4 校验和
  calculateIpv4Checksum(ipv4Packet) {
    const buffer = this.serializeIpv4Packet(ipv4Packet);
    let sum = 0;

    // IPv4头部校验和（前20字节）
    for (let i = 0; i < 20; i += 2) {
      if (i + 1 < 20) {
        sum += (buffer[i] << 8) | buffer[i + 1];
      } else {
        sum += buffer[i] << 8;
      }
    }

    while (sum >> 16) {
      sum = (sum & 0xffff) + (sum >> 16);
    }

    return ~sum & 0xffff;
  }

  // 辅助方法：序列化 ICMP 包
  serializeIcmpPacket(icmpPacket) {
    const buffer = new Uint8Array(8 + icmpPacket.data.length);
    buffer[0] = icmpPacket.type;
    buffer[1] = icmpPacket.code;
    buffer[2] = (icmpPacket.checksum >> 8) & 0xff;
    buffer[3] = icmpPacket.checksum & 0xff;
    buffer[4] = (icmpPacket.identifier >> 8) & 0xff;
    buffer[5] = icmpPacket.identifier & 0xff;
    buffer[6] = (icmpPacket.sequenceNumber >> 8) & 0xff;
    buffer[7] = icmpPacket.sequenceNumber & 0xff;
    buffer.set(icmpPacket.data, 8);
    return buffer;
  }

  // 辅助方法：序列化 IPv4 包
  serializeIpv4Packet(ipv4Packet) {
    const buffer = new Uint8Array(ipv4Packet.totalLength);
    buffer[0] = (ipv4Packet.version << 4) | (ipv4Packet.headerLength / 4);
    buffer[1] = 0; // DSCP/ECN
    buffer[2] = (ipv4Packet.totalLength >> 8) & 0xff;
    buffer[3] = ipv4Packet.totalLength & 0xff;
    buffer[4] = (ipv4Packet.identification >> 8) & 0xff;
    buffer[5] = ipv4Packet.identification & 0xff;
    buffer[6] = (ipv4Packet.flags >> 13) & 0xff;
    buffer[7] = ipv4Packet.flags & 0xff;
    buffer[8] = ipv4Packet.ttl;
    buffer[9] = ipv4Packet.protocol;
    buffer[10] = (ipv4Packet.headerChecksum >> 8) & 0xff;
    buffer[11] = ipv4Packet.headerChecksum & 0xff;

    // IP 地址
    const sourceBytes = ipv4Packet.sourceIp.split(".").map(Number);
    const destBytes = ipv4Packet.destIp.split(".").map(Number);
    buffer.set(sourceBytes, 12);
    buffer.set(destBytes, 16);

    // 载荷
    buffer.set(ipv4Packet.payload, ipv4Packet.headerLength);

    return buffer;
  }

  // 辅助方法：创建 VNT 协议包
  createVntPacket(protocol, transportProtocol, source, destination, payload) {
    const headerSize = 12;
    const buffer = new Uint8Array(headerSize + payload.length);

    // VNT 头部
    const view = new DataView(buffer.buffer);
    view.setUint8(0, 2); // Version
    view.setUint8(1, protocol);
    view.setUint8(2, transportProtocol);
    view.setUint8(3, 0x60); // TTL (6)

    // 源和目标 IP
    const sourceBytes = source.split(".").map(Number);
    const destBytes = destination.split(".").map(Number);
    buffer.set(sourceBytes, 4);
    buffer.set(destBytes, 8);

    // 载荷
    buffer.set(payload, headerSize);

    return {
      protocol,
      transportProtocol,
      source,
      destination,
      buffer,
    };
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
    logger.warn(`无效的协议组合，需要先建立上下文`);
    return this.createErrorPacket(addr, packet.source, "No context");
  }

  async handleHandshake(packet, addr) {
    try {
      logger.info(`[握手-开始] 开始处理客户端握手请求`);

      const payload = packet.payload();
      const handshakeReq = this.parseHandshakeRequest(payload);

      logger.debug(
        `[握手-请求] 客户端握手请求参数: ${JSON.stringify(handshakeReq)}`
      );
      
      // 先创建基础响应数据  
    const responseData = {  
      version: handshakeReq.version || "Unknown",  
      secret: false,  
      public_key: new Uint8Array(0),  
      key_finger: "",  
    };  
  
    // 如果有RSA加密器，设置加密相关信息  
    if (this.rsaCipher) {  
      logger.debug(`[握手-加密] 启用服务端加密模式`);  
      responseData.secret = true;  
      responseData.public_key = this.rsaCipher.publicKey();  
      responseData.key_finger = await this.rsaCipher.finger();  
    } else {  
      logger.debug(`[握手-加密] 未启用服务端加密`);  
    }

      const response = this.createHandshakeResponse(responseData);

      // 确保响应使用 SERVICE 协议
      response.set_protocol(PROTOCOL.SERVICE);
      response.set_transport_protocol(TRANSPORT_PROTOCOL.HandshakeResponse);
      logger.debug(
        `[握手-协议] 设置响应协议: SERVICE, 传输: HandshakeResponse`
      );

      // 使用默认网关
      const defaultGateway = 0x0a240001; // 10.36.0.1
      this.setCommonParams(response, packet.source, defaultGateway);
      logger.debug(
        `[握手-网关] 设置默认网关: ${this.formatIp(defaultGateway)}`
      );

      // 修改最终缓冲区的 TTL
      const finalBuffer = response.buffer();
      const view = new DataView(finalBuffer.buffer || finalBuffer);
      const currentTtl = view.getUint8(3);
      logger.debug(
        `[握手-TTL] 发送前TTL检查: 0x${currentTtl
          .toString(16)
          .padStart(2, "0")}`
      );

      // 强制设置 TTL 为 0xff (原始TTL=15, 当前TTL=15)
      view.setUint8(3, 0xff);
      logger.debug(`[握手-TTL] 强制修复TTL为: 0xff`);

      logger.info(
        `[握手-完成] 握手响应构建完成，协议: ${response.protocol}, 传输: ${
          response.transportProtocol
        }，网关: ${this.formatIp(defaultGateway)}`
      );

      return response;
    } catch (error) {
      logger.error(`[握手-错误] 握手处理失败: ${error.message}`, error);
      return this.createErrorPacket(addr, packet.source, "握手失败");
    }
  }

  async handleSecretHandshake(context, packet, addr) {
    logger.info(
      `[加密握手-开始] 处理来自 ${JSON.stringify(addr)} 的加密握手请求`
    );

    try {
      // 检查是否有RSA加密器
      if (!this.rsaCipher) {
        logger.error(`[加密握手-错误] 服务端未配置RSA加密器`);
        return this.createErrorPacket(
          addr,
          packet.source,
          "No RSA cipher configured"
        );
      }

      logger.debug(`[加密握手-解密] 开始RSA解密握手请求`);

      // RSA解密握手请求
      const secretBody = await this.rsaCipher.decrypt(packet);
      logger.debug(`[加密握手-解析] 解析SecretHandshakeRequest`);

      const handshakeReq = this.parseSecretHandshakeRequest(secretBody.data());

      if (!handshakeReq || !handshakeReq.token || !handshakeReq.key) {
        logger.error(`[加密握手-错误] 握手请求参数无效`);
        return this.createErrorPacket(
          addr,
          packet.source,
          "Invalid handshake request"
        );
      }

      logger.debug(
        `[加密握手-验证] Token长度: ${handshakeReq.token.length}, Key长度: ${handshakeReq.key.length}`
      );

      // 创建AES-GCM加密器
      logger.debug(`[加密握手-AES] 创建AES-256-GCM加密器`);
      const finger = new Finger(handshakeReq.token);
      const cipher = new AesGcmCipher(handshakeReq.key, finger);

      // 设置加密会话
      context.server_cipher = cipher;
      this.cache.cipher_session.set(addr, cipher);
      logger.info(
        `[加密握手-会话] 已为客户端 ${JSON.stringify(addr)} 建立加密会话`
      );

      // 创建响应包
      logger.debug(`[加密握手-响应] 创建SecretHandshakeResponse`);
      const response = NetPacket.new_encrypt(ENCRYPTION_RESERVED);
      response.set_protocol(PROTOCOL.SERVICE);
      response.set_transport_protocol(
        TRANSPORT_PROTOCOL.SecretHandshakeResponse
      );
      this.setCommonParams(response, packet.source);

      // 加密响应包
      logger.debug(`[加密握手-加密] 加密响应包`);
      cipher.encrypt_ipv4(response);

      logger.info(`[加密握手-完成] 加密握手处理完成`);
      return response;
    } catch (error) {
      logger.error(
        `[加密握手-失败] 处理加密握手时发生异常: ${error.message}`,
        error
      );
      return this.createErrorPacket(
        addr,
        packet.source,
        "Secret handshake failed"
      );
    }
  }
  createDeviceUpdatePacket(networkInfo) {
    logger.debug(
      `[客户端更新-开始] 创建客户端列表更新，当前客户端数量: ${networkInfo.clients.size}`
    );
    const deviceInfoList = Array.from(networkInfo.clients.values())
      .filter((client) => client.virtual_ip !== 0)
      .map((client) => ({
        name: client.name,
        virtual_ip: client.virtual_ip,
        device_status: client.online ? 0 : 1,
        client_secret: false,
        client_secret_hash: new Uint8Array(0),
        wireguard: false,
      }));

    const responseData = {
      device_info_list: deviceInfoList,
      epoch: networkInfo.epoch,
      update_type: "device_list_update",
    };
    logger.debug(`[客户端更新-数据] 构建响应数据，epoch: ${networkInfo.epoch}`);

    const responseBytes = this.encodeRegistrationResponse(responseData);
    const response = NetPacket.new(responseBytes.length);

    response.set_protocol(PROTOCOL.SERVICE);
    response.set_transport_protocol(TRANSPORT_PROTOCOL.DeviceListUpdate);
    response.set_payload(responseBytes);
    logger.debug(
      `[客户端更新-完成] 设备列表更新包创建完成，包大小: ${responseBytes.length}字节`
    );

    return response;
  }
  async notifyClientsUpdate(networkInfo, newClientIp) {
    const updatePacket = this.createDeviceUpdatePacket(networkInfo);

    // 向所有已连接的客户端发送更新
    for (const [ip, client] of networkInfo.clients) {
      if (ip !== newClientIp && client.tcp_sender) {
        try {
          await client.tcp_sender.send(updatePacket.buffer().to_vec());
        } catch (error) {
          logger.error(
            `[客户端列表更新] 通知客户端 ${this.formatIp(ip)} 失败: ${
              error.message
            }`,
            error
          );
        }
      }
    }
  }

  async handleRegistration(context, packet, addr, tcpSender) {
    logger.info(
      `[注册-开始] 处理客户端注册请求，来源: ${JSON.stringify(addr)}`
    );
    try {
      const payload = packet.payload();
      const registrationReq = this.parseRegistrationRequest(payload);
      logger.debug(
        `[注册-请求] 解析注册请求，设备ID: ${registrationReq.device_id}, 名称: ${registrationReq.name}`
      );

      // 获取客户端请求的IP
      const requestedIp = registrationReq.virtual_ip || 0;
      logger.debug(
        `[注册-IP] 客户端请求IP: ${
          requestedIp !== 0 ? this.formatIp(requestedIp) : "自动分配"
        }`
      );
      const deviceId = registrationReq.device_id;
      const allowIpChange = registrationReq.allow_ip_change || false;
      // 创建或获取网络信息
      logger.debug(
        `[注册-网络] 创建或获取网络信息，Token: ${registrationReq.token}`
      );
      const networkInfo = this.getOrCreateNetworkInfo(
        registrationReq.token,
        requestedIp
      );

      // 更新网段信息（如果是第一个客户端且指定了IP）
      this.updateNetworkSegment(networkInfo, requestedIp, networkInfo.netmask);

      let virtualIp = requestedIp;

      // 检查IP冲突
      if (requestedIp !== 0) {
        const conflictCheck = this.checkIpConflict(
          networkInfo,
          requestedIp,
          deviceId,
          allowIpChange
        );

        if (!conflictCheck.canUse) {
          virtualIp = 0; // 需要重新分配
        }
      }

      // 分配虚拟IP
      if (virtualIp === 0) {
        virtualIp = this.allocateVirtualIp(
          networkInfo,
          deviceId,
          allowIpChange
        );
      }

      // 创建客户端信息
      logger.debug(`[注册-客户端] 创建客户端信息对象`);
      const clientInfo = new ClientInfo({
        virtualIp: virtualIp,
        device_id: registrationReq.device_id,
        name: registrationReq.name,
        version: registrationReq.version,
        online: true,
        address: addr,
        client_secret_hash: registrationReq.client_secret_hash,
        tcp_sender: tcpSender,
        timestamp: Date.now(),
      });

      // 添加到网络
      logger.debug(
        `[注册-网络] 添加客户端到网络，当前网络版本: ${networkInfo.epoch}`
      );
      networkInfo.epoch += 1;
      networkInfo.clients.set(virtualIp, clientInfo);
      // 保存网络信息引用
      this.currentNetworkInfo = networkInfo;

      // 创建链接上下文
      logger.debug(`[注册-上下文] 创建链接上下文`);
      context.link_context = {
        group: registrationReq.token,
        virtual_ip: virtualIp,
        network_info: networkInfo,
        timestamp: Date.now(),
      };

      // 创建注册响应
      const response = this.createRegistrationResponse(virtualIp, networkInfo);
      // 通知其他客户端有新设备加入
      logger.debug(`[注册-通知] 通知其他客户端新设备加入`);
      await this.notifyClientsUpdate(networkInfo, virtualIp);
      logger.info(
        `[注册-完成] 注册成功，IP: ${this.formatIp(
          virtualIp
        )}, 网关: ${this.formatIp(networkInfo.gateway)}`
      );
      return response;
    } catch (error) {
      logger.error(`[注册-错误] 注册处理失败: ${error.message}`, error);
      return this.createErrorPacket(addr, packet.source, "Registration failed");
    }
  }

  getCachedEpoch() {
    if (!this.cachedEpoch || Date.now() - this.lastEpochUpdate > 5000) {
      this.cachedEpoch = this.getCurrentEpoch();
      this.lastEpochUpdate = Date.now();
    }
    return this.cachedEpoch;
  }
  async handlePing(packet, linkContext) {
    // 直接读取时间戳，避免额外计算
    const payload = packet.payload();
    const clientTime = (payload[0] << 8) | payload[1];

    // 保持linkContext参数，但立即返回
    return this.createPongPacket(packet, clientTime, linkContext);
  }

  createPongPacket(pingPacket, clientTime, linkContext) {
    const packet = NetPacket.new(4);
    packet.set_protocol(PROTOCOL.CONTROL);
    packet.set_transport_protocol(TRANSPORT_PROTOCOL.Pong);
    packet.set_source(pingPacket.destination);
    packet.set_destination(pingPacket.source);

    // 直接操作字节数组，避免DataView开销
    const payload = new Uint8Array(4);
    payload[0] = (clientTime >> 8) & 0xff;
    payload[1] = clientTime & 0xff;
    payload[2] = (this.getCachedEpoch() >> 8) & 0xff;
    payload[3] = this.getCachedEpoch() & 0xff;

    packet.set_payload(payload);
    return packet;
  }

  // 获取当前epoch
  getCurrentEpoch() {
    // 始终使用网络信息中的epoch，如果没有则返回0
    if (this.currentNetworkInfo) {
      return this.currentNetworkInfo.epoch || 0;
    }
    return 0; // 修复：返回固定值而不是时间戳
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
    logger.debug(
      `[数据转发-开始] 开始处理数据转发，来源: ${JSON.stringify(addr)}`
    );
    // 增加 TTL
    if (packet.incr_ttl() > 1) {
      logger.debug(`[数据转发-TTL] TTL递增，新值: ${newTtl}`);
      // 检查是否禁用中继
      if (this.env.DISABLE_RELAY === "1") {
        logger.warn(`[数据转发-禁用] 中继转发功能已禁用，丢弃数据包`);
        return null;
      }

      const destination = packet.destination;
      logger.debug(`[数据转发-路由] 目标地址: ${this.formatIp(destination)}`);

      if (this.isBroadcast(destination)) {
        logger.debug(`[数据转发-广播] 检测到广播包，开始广播转发`);
        return await this.broadcastPacket(context.link_context, packet);
      } else {
        logger.debug(`[数据转发-单播] 检测到单播包，转发到指定目标`);
        return await this.forwardToDestination(
          context.link_context,
          packet,
          destination
        );
      }
    }
    return null;
  }

  async handleClientPacket(context, packet, addr) {
    if (!context.link_context) {
      // 处理服务协议
      if (packet.protocol === PROTOCOL.SERVICE) {
        logger.debug(`[客户端包-SERVICE] 检测到SERVICE协议`);
        switch (packet.transportProtocol) {
          case TRANSPORT_PROTOCOL.HandshakeRequest:
            logger.info(`[客户端包-握手] 处理握手请求`);
            return await this.handleHandshake(packet, addr);
          case TRANSPORT_PROTOCOL.RegistrationRequest:
            logger.info(`[客户端包-注册] 处理注册请求`);
            return await this.handleRegistration(context, packet, addr, null);
          default:
            logger.debug(
              `[客户端包-SERVICE] 跳过未知的传输协议: ${packet.transportProtocol}`
            );
            break;
        }
      }
      // 移除默认握手响应，改为错误响应
      logger.warn(`[客户端包-错误] 无效的数据包序列，需要先建立上下文`);
      return this.createErrorPacket(
        addr,
        packet.source,
        "Invalid packet sequence"
      );
    }

    return await this.forwardPacket(context.link_context, packet);
  }

  async forwardPacket(linkContext, packet) {
    const destination = packet.destination;
    logger.debug(
      `[数据包转发-开始] 开始转发数据包，目标: ${this.formatIp(destination)}`
    );

    if (this.isBroadcast(destination)) {
      logger.debug(`[数据包转发-广播] 检测到广播包，执行广播转发`);
      return await this.broadcastPacket(linkContext, packet);
    } else {
      logger.debug(`[数据包转发-单播] 检测到单播包，查找目标客户端`);
      const targetClient = linkContext.network_info.clients.get(destination);
      if (targetClient && targetClient.online && targetClient.tcp_sender) {
        // 发送到特定客户端
        logger.debug(`[数据包转发-发送] 找到目标客户端，开始发送数据包`);
        try {
          await targetClient.tcp_sender.send(packet.buffer().to_vec());
          logger.debug(
            `[数据包转发-成功] 数据包已成功发送到 ${this.formatIp(destination)}`
          );
        } catch (error) {
          logger.error(
            `[数据包转发-失败] 发送到 ${this.formatIp(destination)} 失败: ${
              error.message
            }`,
            error
          );
          targetClient.online = false;
        }
      }
    }
    logger.debug(`[数据包转发-完成] 数据包转发处理完成`);
    return null;
  }

  async broadcastPacket(linkContext, packet) {
    const networkInfo = linkContext.network_info;
    const sender = packet.source;
    // logger.info(`[广播包-开始] 开始广播数据包，发送者: ${this.formatIp(sender)}`);

    for (const [virtualIp, client] of networkInfo.clients) {
      if (client.virtual_ip !== sender && client.online && client.tcp_sender) {
        try {
          logger.debug(
            `[广播包-发送] 向客户端 ${this.formatIp(virtualIp)} 发送广播包`
          );
          await client.tcp_sender.send(packet.buffer().to_vec());
        } catch (error) {
          logger.error(
            `[广播包-失败] 广播到 ${this.formatIp(virtualIp)} 失败: ${
              error.message
            }`,
            error
          );
          client.online = false;
        }
      }
    }
    return null;
  }

  async forwardToDestination(linkContext, packet, destination) {
    logger.debug(
      `[目标转发-开始] 开始转发到指定目标: ${this.formatIp(destination)}`
    );
    const targetClient = linkContext.network_info.clients.get(destination);
    if (targetClient && targetClient.online && targetClient.tcp_sender) {
      try {
        await targetClient.tcp_sender.send(packet.buffer().to_vec());
      } catch (error) {
        logger.error(
          `[目标转发-失败] 转发到 ${this.formatIp(destination)} 失败: ${
            error.message
          }`,
          error
        );
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
    logger.debug(`[参数设置-开始] 设置数据包公共参数`);
    packet.set_default_version();
    packet.set_destination(source);
    packet.set_source(0x0a240001);
    packet.first_set_ttl(15); // MAX_TTL = 0b1111 = 15
    packet.set_gateway_flag(true);
  }

  // 计算客户端地址的方法
  calculateClientAddress(source) {
    logger.debug(
      `[地址计算-开始] 计算客户端地址，源地址: ${JSON.stringify(source)}`
    );

    // 在WebSocket环境中，地址已经是从request.cf解析的
    // 如果需要更复杂的地址处理，可以在这里添加
    let clientAddress = source;

    // 处理特殊情况（如果有的话）
    if (!source || !source.ip) {
      logger.warn(`[地址计算-警告] 无效的源地址，使用默认值`);
      clientAddress = { ip: "unknown", port: 0 };
    }

    logger.debug(`[地址计算-完成] 计算结果: ${JSON.stringify(clientAddress)}`);
    return clientAddress;
  }

  createErrorPacket(addr, destination, message) {
    try {
      logger.debug(`[错误包-创建] 开始创建错误包: ${message}`);

      const errorPacket = NetPacket.new_encrypt(ENCRYPTION_RESERVED);

      // 设置协议字段
      errorPacket.set_protocol(PROTOCOL.ERROR);
      errorPacket.set_destination(destination);
      errorPacket.set_source(this.serverPeerId);

      // 尝试设置错误消息（如果协议支持）
      try {
        const errorPayload = new TextEncoder().encode(
          message.substring(0, 100)
        ); // 限制长度
        errorPacket.set_payload(errorPayload);
      } catch (payloadError) {
        logger.warn(`[错误包-警告] 设置错误载荷失败: ${payloadError.message}`);
      }

      return errorPacket;
    } catch (error) {
      logger.error(`[错误包-失败] 创建错误包失败: ${error.message}`, error);
      // 返回一个基本的错误包
      const fallbackPacket = NetPacket.new_encrypt(ENCRYPTION_RESERVED);
      fallbackPacket.set_protocol(PROTOCOL.ERROR);
      fallbackPacket.set_source(this.serverPeerId);
      return fallbackPacket;
    }
  }

  createHandshakeResponse(responseData) {
    logger.debug(`[握手响应-开始] 开始创建握手响应`);
    const clientVersion = responseData.version || "Unknown";
    logger.info(`[握手响应-版本] 客户端版本: ${clientVersion}`);

    const responseBytes = this.encodeHandshakeResponse(responseData);

    // 使用普通数据包而不是加密数据包
    const response = NetPacket.new(responseBytes.length);

    response.set_protocol(PROTOCOL.SERVICE);
    response.set_transport_protocol(TRANSPORT_PROTOCOL.HandshakeResponse);
    response.set_payload(responseBytes); // 这里应该正确工作
    logger.debug(
      `[握手响应-完成] 握手响应包创建完成，大小: ${responseBytes.length}字节`
    );

    return response;
  }

  createRegistrationResponse(virtualIp, networkInfo) {
    logger.info(
      `[注册响应-开始] 创建注册响应包，客户端IP: ${this.formatIp(virtualIp)}`
    );
    logger.debug(
      `[注册响应-网络] 当前网络客户端数量: ${networkInfo.clients.size}`
    );

    // 明确添加网关信息
    const gatewayInfo = {
      name: "服务器",
      virtual_ip: networkInfo.gateway,
      device_status: 0, // 网关始终在线
      client_secret: false,
      client_secret_hash: new Uint8Array(0),
      wireguard: false,
    };
    logger.debug(
      `[注册响应-网关] 网关信息创建完成，IP: ${this.formatIp(
        networkInfo.gateway
      )}`
    );

    // 客户端信息列表（排除本机）
    const clientInfoList = Array.from(networkInfo.clients.values())
      .filter(
        (client) => client.virtual_ip !== 0 && client.virtual_ip !== virtualIp
      )
      .map((client) => ({
        name: client.name,
        virtual_ip: client.virtual_ip,
        device_status: client.online ? 0 : 1,
        client_secret: false,
        client_secret_hash: new Uint8Array(0),
        wireguard: false,
      }));
    logger.debug(
      `[注册响应-客户端] 过滤后客户端数量: ${clientInfoList.length}`
    );

    // 将网关信息放在第一位
    const deviceInfoList = [gatewayInfo, ...clientInfoList];

    const responseData = {
      virtual_ip: virtualIp,
      virtual_gateway: networkInfo.gateway,
      virtual_netmask: networkInfo.netmask,
      epoch: networkInfo.epoch,
      device_info_list: deviceInfoList,
      public_ip: networkInfo.public_ip,
      public_port: networkInfo.public_port,
      public_ipv6: new Uint8Array(0),
    };
    logger.debug(
      `[注册响应-数据] 响应数据构建完成，epoch: ${networkInfo.epoch}`
    );

    const responseBytes = this.encodeRegistrationResponse(responseData);
    const response = NetPacket.new(responseBytes.length);
    response.set_default_version();

    response.set_protocol(PROTOCOL.SERVICE);
    response.set_transport_protocol(TRANSPORT_PROTOCOL.RegistrationResponse);

    response.set_source(networkInfo.gateway); // 设置源地址为网关
    response.set_destination(0xffffffff); // 设置目标地址为客户端
    response.set_gateway_flag(true); // 设置网关标志
    response.first_set_ttl(15);

    response.set_payload(responseBytes);
    logger.info(
      `[注册响应-完成] 注册响应包创建完成，大小: ${responseBytes.length}字节`
    );

    return response;
  }

  // 协议解析方法
  parseHandshakeRequest(payload) {
    logger.debug(
      `[协议解析-握手] 开始解析握手请求，载荷长度: ${payload.length}`
    );
    const { parseHandshakeRequest } = require("./protos.js");
    try {
      const result = parseHandshakeRequest(payload);
      logger.debug(`[协议解析-握手] 握手请求解析成功`);
      return result;
    } catch (error) {
      logger.error(`[协议解析-握手] 握手请求解析失败: ${error.message}`, error);
      throw new Error("Invalid handshake request format");
    }
  }

  parseRegistrationRequest(payload) {
    logger.info(
      `[协议解析-注册] 开始解析注册请求，载荷长度: ${payload.length}`
    );
    const { parseRegistrationRequest } = require("./protos.js");
    try {
      const result = parseRegistrationRequest(payload);
      logger.debug(`[协议解析-注册] 注册请求解析成功`);
      return result;
    } catch (error) {
      logger.error(`[协议解析-注册] 注册请求解析失败: ${error.message}`, error);
      throw new Error("Invalid registration request format");
    }
  }

  encodeHandshakeResponse(data) {
    logger.debug(`[协议编码-握手] 开始编码握手响应`);
    const { createHandshakeResponse } = require("./protos.js");
    const result = createHandshakeResponse(
      data.version,
      data.secret,
      data.public_key,
      data.key_finger
    );
    logger.debug(
      `[协议编码-握手] 握手响应编码完成，大小: ${result.length}字节`
    );
    return result;
  }

  encodeRegistrationResponse(data) {
    logger.debug(`[协议编码-注册] 开始编码注册响应`);
    const { createRegistrationResponse } = require("./protos.js");
    const result = createRegistrationResponse(
      data.virtual_ip,
      data.virtual_gateway,
      data.virtual_netmask,
      data.epoch,
      data.device_info_list,
      data.public_ip,
      data.public_port
    );
    logger.debug(
      `[协议编码-注册] 注册响应编码完成，大小: ${result.length}字节`
    );
    return result;
  }

  validateRegistrationRequest(request) {
    logger.debug(`[请求验证-注册] 开始验证注册请求参数`);
    if (
      !request.token ||
      request.token.length === 0 ||
      request.token.length > 128
    ) {
      logger.error(
        `[请求验证-注册] Token长度无效: ${request.token?.length || 0}`
      );
      throw new Error("Invalid token length");
    }
    if (
      !request.device_id ||
      request.device_id.length === 0 ||
      request.device_id.length > 128
    ) {
      logger.error(
        `[请求验证-注册] 设备ID长度无效: ${request.device_id?.length || 0}`
      );
      throw new Error("Invalid device_id length");
    }
    if (
      !request.name ||
      request.name.length === 0 ||
      request.name.length > 128
    ) {
      logger.error(
        `[请求验证-注册] 设备名称长度无效: ${request.name?.length || 0}`
      );
      throw new Error("Invalid name length");
    }
    logger.debug(`[请求验证-注册] 注册请求验证通过`);
  }

  parseIpv4(ipStr) {
    if (!ipStr || typeof ipStr !== "string") {
      logger.debug(`[地址解析-IPv4] 无效的IP字符串: ${ipStr}`);
      return 0;
    }
    const parts = ipStr.split(".").map(Number);
    const result =
      (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
    logger.debug(`[地址解析-IPv4] IP地址转换: ${ipStr} -> ${result}`);
    return result;
  }

  isBroadcast(addr) {
    return addr === 0xffffffff || addr === 0;
  }

  generateRandomKey() {
    logger.debug(`[密钥生成-随机] 开始生成32字节随机密钥`);
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    logger.debug(`[密钥生成-随机] 随机密钥生成完成`);
    return array;
  }

  // 网络管理方法
  getOrCreateNetworkInfo(token, requestedIp = 0) {
    logger.debug(
      `[网络信息-查询] 查询或创建网络信息，Token: ${token}, 请求IP: ${
        requestedIp !== 0 ? this.formatIp(requestedIp) : "自动分配"
      }`
    );

    let networkInfo;

    if (!this.cache.networks.has(token)) {
      logger.info(`[网络信息-创建] Token不存在，创建新网络`);
      let gateway = 0x0a240001; // 默认 10.36.0.1
      let network = 0x0a240001; // 默认 10.36.0.0
      let netmask = 0xffffff00; // 255.255.255.0

      // 如果第一个客户端指定了IP，根据其更新网段
      if (requestedIp !== 0) {
        network = requestedIp & netmask;
        logger.info(
          `[网络信息-网段] 客户端指定了IP，更新网段 - 网关: ${this.formatIp(
            gateway
          )}, 网络: ${this.formatIp(network)}`
        );
      }

      networkInfo = new NetworkInfo(network, netmask, gateway);
      this.cache.networks.set(token, networkInfo);
      logger.debug(`[网络信息-存储] 网络信息已缓存，Token: ${token}`);
    } else {
      networkInfo = this.cache.networks.get(token);
    }

    logger.debug(
      `[网络信息-完成] 返回网络信息 - 网关: ${this.formatIp(
        networkInfo.gateway
      )}, 掩码: ${this.formatIp(networkInfo.netmask)}`
    );
    return networkInfo;
  }

  // 辅助方法：格式化 IP 地址用于日志
  formatIp(ipUint32) {
    return `${(ipUint32 >>> 24) & 0xff}.${(ipUint32 >>> 16) & 0xff}.${
      (ipUint32 >>> 8) & 0xff
    }.${ipUint32 & 0xff}`;
  }

  allocateVirtualIp(networkInfo, deviceId, allowIpChange = false) {
    logger.debug(`[IP分配-开始] 开始分配虚拟IP，设备ID: ${deviceId}`);

    const gateway = networkInfo.gateway;
    const netmask = networkInfo.netmask;
    const network = networkInfo.network;

    // 使用组网实际的网段计算IP分配范围
    const ipRangeStart = network + 1;
    const ipRangeEnd = network | ~netmask;

    logger.debug(
      `[IP分配-范围] IP分配范围: ${this.formatIp(
        ipRangeStart
      )} - ${this.formatIp(ipRangeEnd)}`
    );

    let virtualIp = 0;
    let insert = true;

    // 1. 检查设备ID重用 - 查找上一次使用的IP
    logger.debug(`[IP分配-重用] 检查设备ID重用: ${deviceId}`);
    for (const [ip, client] of networkInfo.clients) {
      if (client.device_id === deviceId) {
        virtualIp = ip;
        insert = false;
        logger.info(
          `[IP分配-重用] 找到设备之前使用的IP: ${this.formatIp(virtualIp)}`
        );
        break;
      }
    }

    // 2. 如果没有重用IP，分配新的IP
    if (virtualIp === 0) {
      logger.debug(`[IP分配-新分配] 设备ID首次连接，分配新IP`);

      // 从小到大找一个未使用的IP
      for (let ip = ipRangeStart; ip <= ipRangeEnd; ip++) {
        // 跳过网关地址
        if (ip === gateway) {
          logger.debug(`[IP分配-跳过] 跳过网关地址: ${this.formatIp(ip)}`);
          continue;
        }

        // 跳过任何网段的.1地址
        const hostPart = ip & !netmask;
        if (hostPart === 1) {
          logger.debug(`[IP分配-跳过] 跳过网段.1地址: ${this.formatIp(ip)}`);
          continue;
        }

        // 检查IP是否已被占用
        if (!networkInfo.clients.has(ip)) {
          virtualIp = ip;
          logger.info(`[IP分配-成功] 分配新IP: ${this.formatIp(virtualIp)}`);
          break;
        }
      }
    }

    // 3. 检查是否找到可用IP
    if (virtualIp === 0) {
      logger.error(`[IP分配-失败] 地址池已用尽，无法分配IP`);
      throw new Error("No available IP addresses");
    }

    logger.debug(`[IP分配-完成] IP分配完成: ${this.formatIp(virtualIp)}`);
    return virtualIp;
  }

  /**
   * 更新网络信息 - 支持第一个客户端更新网段
   */
  updateNetworkSegment(networkInfo, requestedIp, netmask) {
    if (networkInfo.clients.size === 0 && requestedIp !== 0) {
      const actualNetwork = requestedIp & netmask;
      const oldNetwork = networkInfo.network;

      if (actualNetwork !== oldNetwork) {
        networkInfo.network = actualNetwork;
        logger.info(
          `[网段-更新] 网段已更新: ${this.formatIp(
            oldNetwork
          )} -> ${this.formatIp(actualNetwork)}`
        );
      }
    }
  }

  /**
   * 检查IP冲突并处理
   */
  checkIpConflict(networkInfo, virtualIp, deviceId, allowIpChange) {
    if (virtualIp === 0) return { canUse: true, needReallocate: false };

    // 检查是否为网关地址
    if (virtualIp === networkInfo.gateway) {
      logger.warn(
        `[IP冲突-网关] 请求的IP为网关地址: ${this.formatIp(virtualIp)}`
      );
      throw new Error("Cannot use gateway address");
    }

    // 检查IP是否已被占用
    const existingClient = networkInfo.clients.get(virtualIp);
    if (existingClient) {
      if (existingClient.device_id !== deviceId) {
        // IP被其他设备占用
        if (!allowIpChange) {
          logger.warn(
            `[IP冲突-占用] IP已被其他设备占用: ${this.formatIp(virtualIp)} by ${
              existingClient.device_id
            }`
          );
          throw new Error("IP already exists");
        } else {
          logger.info(
            `[IP冲突-重新分配] IP被占用，允许重新分配: ${this.formatIp(
              virtualIp
            )}`
          );
          return { canUse: false, needReallocate: true };
        }
      } else {
        // 同一设备重用IP
        logger.debug(
          `[IP冲突-重用] 同一设备重用IP: ${this.formatIp(virtualIp)}`
        );
        return { canUse: true, needReallocate: false };
      }
    }

    return { canUse: true, needReallocate: false };
  }
  validatePacket(packet) {
    logger.debug(`[数据包验证-开始] 开始验证VNT数据包`);
    const buffer = packet.buffer();

    // 修复：确保转换为 ArrayBuffer
    let arrayBuffer;
    if (buffer instanceof ArrayBuffer) {
      arrayBuffer = buffer;
      logger.debug(`[数据包验证-缓冲区] 缓冲区已是ArrayBuffer类型`);
    } else if (buffer.buffer) {
      arrayBuffer = buffer.buffer;
      logger.debug(`[数据包验证-缓冲区] 从Uint8Array获取ArrayBuffer`);
    } else {
      arrayBuffer = buffer.buffer.slice(
        buffer.byteOffset,
        buffer.byteOffset + buffer.byteLength
      );
      logger.debug(`[数据包验证-缓冲区] 切片创建ArrayBuffer`);
    }

    const view = new DataView(arrayBuffer);

    logger.debug(
      `[数据包验证-十六进制] 完整数据包: ${Array.from(buffer)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("")}`
    );

    // 验证地址字段
    const sourceBytes = [
      view.getUint8(4),
      view.getUint8(5),
      view.getUint8(6),
      view.getUint8(7),
    ];
    const destBytes = [
      view.getUint8(8),
      view.getUint8(9),
      view.getUint8(10),
      view.getUint8(11),
    ];

    logger.debug(
      `[数据包验证-源地址] 源地址: [${sourceBytes.join(
        ", "
      )}] -> ${this.formatIp(sourceIp)}`
    );
    logger.debug(
      `[数据包验证-目标地址] 目标地址: [${destBytes.join(
        ", "
      )}] -> ${this.formatIp(destIp)}`
    );

    logger.debug(`[数据包验证-完成] 数据包验证完成`);
  }
}

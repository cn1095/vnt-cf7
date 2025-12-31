import { PACKET_HEADER_SIZE, ENCRYPTION_RESERVED } from './constants.js';  
  
export class NetPacket {  
  constructor(data) {  
    this.data = data;  
    this.offset = 0;  
  }  
  
  static parse(buffer) {  
    // 安全检查：确保输入有效  
    if (!buffer) {  
      throw new Error('Buffer is null or undefined');  
    }  
      
    if (!(buffer instanceof Uint8Array) && !(buffer instanceof ArrayBuffer)) {  
      throw new Error('Invalid buffer type: expected Uint8Array or ArrayBuffer');  
    }  
      
    // 获取缓冲区长度  
    const length = buffer instanceof Uint8Array ? buffer.length : buffer.byteLength;  
      
    if (length < 13) { // PACKET_HEADER_SIZE  
      throw new Error(`Packet too short: ${length} bytes, minimum 13 bytes required`);  
    }  
        
    try {  
      const packet = new NetPacket(buffer);  
      packet.parseHeader();  
      return packet;  
    } catch (error) {  
      throw new Error(`Failed to parse VNT packet: ${error.message}`);  
    }  
  }  
  
  parseHeader() {  
    // 安全检查：确保数据存在且类型正确  
    if (!this.data) {  
      throw new Error('Packet data is null or undefined');  
    }  
      
    // 确保有有效的 ArrayBuffer  
    let buffer;  
    if (this.data.buffer) {  
      buffer = this.data.buffer;  
    } else if (this.data instanceof Uint8Array) {  
      // 创建新的 ArrayBuffer 并复制数据  
      buffer = new ArrayBuffer(this.data.length);  
      new Uint8Array(buffer).set(this.data);  
    } else if (this.data instanceof ArrayBuffer) {  
      buffer = this.data;  
    } else {  
      throw new Error('Invalid data type for packet parsing: expected Uint8Array or ArrayBuffer');  
    }  
      
    // 安全检查：确保缓冲区足够大以包含协议头  
    if (buffer.byteLength < 13) {  
      throw new Error('Packet too short: minimum 13 bytes required for VNT header');  
    }  
      
    const view = new DataView(buffer);  
      
    try {  
      // 读取 VNT 协议头部 - 使用小端序  
      this.protocol = view.getUint8(0);  
      this.transportProtocol = view.getUint8(1);  
      this.flags = view.getUint16(2, true); // little endian  
      this.ttl = view.getUint8(4);  
      this.source = view.getUint32(5, true);  
      this.destination = view.getUint32(9, true);  
        
      this.offset = 13; // PACKET_HEADER_SIZE  
        
    } catch (error) {  
      throw new Error(`Failed to parse VNT packet header: ${error.message}`);  
    }  
  }  
  
  protocol() {  
    return this.protocol;  
  }  
  
  transport_protocol() {  
    return this.transportProtocol;  
  }  
  
  source() {  
    return this.source;  
  }  
  
  destination() {  
    return this.destination;  
  }  
  
  payload() {  
    return this.data.slice(this.offset);  
  }  
  
  is_encrypt() {  
    return (this.flags & 0x01) !== 0;  
  }  
  
  is_gateway() {  
    return (this.flags & 0x02) !== 0;  
  }  
  
  incr_ttl() {  
    // 安全检查：确保数据存在  
    if (!this.data) {  
      throw new Error('Cannot increment TTL: packet data is null');  
    }  
      
    // 确保 TTL 值有效  
    if (typeof this.ttl !== 'number' || this.ttl < 0) {  
      throw new Error('Invalid TTL value');  
    }  
      
    // 增加 TTL  
    this.ttl++;  
      
    // 确保有有效的 ArrayBuffer  
    let buffer;  
    if (this.data.buffer) {  
      buffer = this.data.buffer;  
    } else if (this.data instanceof Uint8Array) {  
      buffer = new ArrayBuffer(this.data.length);  
      new Uint8Array(buffer).set(this.data);  
    } else if (this.data instanceof ArrayBuffer) {  
      buffer = this.data;  
    } else {  
      throw new Error('Invalid data type for packet modification');  
    }  
      
    // 安全检查：确保缓冲区足够大  
    if (buffer.byteLength < 5) {  
      throw new Error('Packet too short to modify TTL');  
    }  
      
    try {  
      const view = new DataView(buffer);  
      view.setUint8(4, this.ttl);  
      return this.ttl;  
    } catch (error) {  
      throw new Error(`Failed to increment TTL: ${error.message}`);  
    }  
  }  
  
  buffer() {  
    return this.data;  
  }  
  
  static new_encrypt(size) {  
    const totalSize = PACKET_HEADER_SIZE + size + ENCRYPTION_RESERVED;  
    const buffer = new Uint8Array(totalSize);  
    return new NetPacket(buffer);  
  }  
  
  // 安全获取 ArrayBuffer 的辅助方法  
  _getArrayBuffer() {  
    if (!this.data) {  
      throw new Error('Packet data is null');  
    }  
      
    if (this.data.buffer) {  
      return this.data.buffer;  
    } else if (this.data instanceof Uint8Array) {  
      const buffer = new ArrayBuffer(this.data.length);  
      new Uint8Array(buffer).set(this.data);  
      return buffer;  
    } else if (this.data instanceof ArrayBuffer) {  
      return this.data;  
    } else {  
      throw new Error('Invalid data type');  
    }  
  }  
  
  // 验证数据包完整性  
  validate() {  
    if (!this.data) {  
      throw new Error('Packet data is null');  
    }  
      
    if (typeof this.protocol !== 'number') {  
      throw new Error('Invalid protocol field');  
    }  
      
    if (typeof this.transportProtocol !== 'number') {  
      throw new Error('Invalid transport protocol field');  
    }  
      
    if (typeof this.source !== 'number' || this.source < 0) {  
      throw new Error('Invalid source address');  
    }  
      
    if (typeof this.destination !== 'number' || this.destination < 0) {  
      throw new Error('Invalid destination address');  
    }  
      
    return true;  
  }  
}

set_protocol(protocol) {  
  const buffer = this._getArrayBuffer();  
  const view = new DataView(buffer);  
  view.setUint8(1, protocol);  
  this.protocol = protocol;  
}  
  
set_transport_protocol(transportProtocol) {  
  const buffer = this._getArrayBuffer();  
  const view = new DataView(buffer);  
  view.setUint8(2, transportProtocol);  
  this.transportProtocol = transportProtocol;  
}  
  
set_source(source) {  
  const buffer = this._getArrayBuffer();  
  const view = new DataView(buffer);  
  view.setUint32(5, source, true); // little endian  
  this.source = source;  
}  
  
set_destination(destination) {  
  const buffer = this._getArrayBuffer();  
  const view = new DataView(buffer);  
  view.setUint32(9, destination, true); // little endian  
  this.destination = destination;  
}  
  
set_payload(payload) {  
  const dataStart = 13; // PACKET_HEADER_SIZE  
  if (this.data.length < dataStart + payload.length) {  
    throw new Error('Insufficient space for payload');  
  }  
    
  // 复制 payload 数据  
  const dataArray = this.data instanceof Uint8Array ? this.data : new Uint8Array(this.data);  
  dataArray.set(payload, dataStart);  
  this.data = dataArray;  
}  
  
set_gateway_flag(isGateway) {  
  const buffer = this._getArrayBuffer();  
  const view = new DataView(buffer);  
  const currentFlags = view.getUint16(2, true);  
    
  if (isGateway) {  
    view.setUint16(2, currentFlags | 0x40, true); // 设置网关标志  
  } else {  
    view.setUint16(2, currentFlags & ~0x40, true); // 清除网关标志  
  }  
  this.flags = view.getUint16(2, true);  
}

// 添加到 NetPacket 类末尾  
set_protocol(protocol) {  
  const buffer = this._getArrayBuffer();  
  const view = new DataView(buffer);  
  view.setUint8(1, protocol);  
  this.protocol = protocol;  
}  
  
set_transport_protocol(transportProtocol) {  
  const buffer = this._getArrayBuffer();  
  const view = new DataView(buffer);  
  view.setUint8(2, transportProtocol);  
  this.transportProtocol = transportProtocol;  
}  
  
set_source(source) {  
  const buffer = this._getArrayBuffer();  
  const view = new DataView(buffer);  
  view.setUint32(5, source, true); // little endian  
  this.source = source;  
}  
  
set_destination(destination) {  
  const buffer = this._getArrayBuffer();  
  const view = new DataView(buffer);  
  view.setUint32(9, destination, true); // little endian  
  this.destination = destination;  
}  
  
set_payload(payload) {  
  const dataStart = 13; // PACKET_HEADER_SIZE  
  if (this.data.length < dataStart + payload.length) {  
    throw new Error('Insufficient space for payload');  
  }  
    
  // 复制 payload 数据  
  const dataArray = this.data instanceof Uint8Array ? this.data : new Uint8Array(this.data);  
  dataArray.set(payload, dataStart);  
  this.data = dataArray;  
}

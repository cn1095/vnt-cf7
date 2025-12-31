// VNT 协议常量定义  
export const PROTOCOL = {  
  SERVICE: 0,  
  CONTROL: 1,  
  DATA: 2,  
};  
  
export const TRANSPORT_PROTOCOL = {  
  // Service 协议  
  HandshakeRequest: 5,  
  HandshakeResponse: 6,  
  SecretHandshakeRequest: 7,  
  SecretHandshakeResponse: 8,  
  RegistrationRequest: 1,  
  RegistrationResponse: 2,  
    
  // Control 协议  
  Ping: 0,  
  Pong: 1,  
  AddrRequest: 2,  
  AddrResponse: 3,  
};  
  
export const PACKET_HEADER_SIZE = 12;  
export const ENCRYPTION_RESERVED = 16;  
export const MAGIC = 0x76774e54; // "vwtN" - VNT magic number

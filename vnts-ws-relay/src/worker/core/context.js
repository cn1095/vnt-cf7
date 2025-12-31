export class VntContext {  
  constructor(options = {}) {  
    this.linkAddress = options.linkAddress || null;  
    this.serverCipher = options.serverCipher || null;  
    this.linkContext = options.linkContext || null;  
    this.networkInfo = options.networkInfo || null;  
  }  
  
  async leave(cache) {  
    // 清理连接资源  
    if (this.linkContext) {  
      // 从网络信息中移除客户端  
      const networkInfo = this.networkInfo;  
      if (networkInfo) {  
        const clients = networkInfo.clients;  
        // 移除当前连接的客户端信息  
        // 具体实现取决于网络信息结构  
      }  
    }  
  }  
}  
  
export class LinkVntContext {  
  constructor(options = {}) {  
    this.group = options.group || null;  
    this.networkInfo = options.networkInfo || {  
      clients: new Map(),  
      epoch: Date.now()  
    };  
  }  
}

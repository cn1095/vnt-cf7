// Cloudflare Worker entry for VNT WebSocket relay backed by Durable Object
// Module syntax is required for Durable Objects.
import { RelayRoom } from "./worker/relay_room";
import { generateRsaKeyPair, RsaCipher } from "./worker/core/crypto.js";  
import { logger } from "./worker/core/logger.js";

// 全局RSA密钥对  
let globalRsaCipher = null;  
let rsaInitPromise = null;  
  
// 初始化全局RSA密钥  
async function initializeGlobalRsaCipher() {  
  if (globalRsaCipher) return globalRsaCipher;  
    
  if (!rsaInitPromise) {  
    rsaInitPromise = (async () => {  
      try {  
        logger.info(`[全局RSA-开始] 生成服务端RSA密钥对`);  
        const keyPair = await generateRsaKeyPair();  
        globalRsaCipher = new RsaCipher(keyPair.privateKey, keyPair.publicKey);  
        await globalRsaCipher.finger(); // 等待指纹计算完成  
        logger.info(`[全局RSA-完成] RSA密钥对初始化完成`);  
        return globalRsaCipher;  
      } catch (error) {  
        logger.error(`[全局RSA-失败] RSA密钥对生成失败: ${error.message}`);  
        throw error;  
      }  
    })();  
  }  
    
  return rsaInitPromise;  
}

export { RelayRoom };

export default {
  async fetch(request, env, ctx) {
    // 自动设置全局环境变量，让logger能够读取
    if (typeof globalThis !== "undefined") {
      globalThis.env = env;
    }
    
    // 确保RSA密钥已初始化  
    ctx.waitUntil(initializeGlobalRsaCipher());
    
    const url = new URL(request.url);
    const { pathname, searchParams } = url;

    if (pathname === "/healthz") {
      return new Response("ok", { status: 200 });
    }

    const wsPath = "/" + env.WS_PATH || "/ws";
    if (pathname === wsPath || pathname === wsPath + "/") {
      if (request.headers.get("Upgrade") !== "websocket") {
        return new Response("Expected WebSocket upgrade", { status: 400 });
      }

      const roomId = searchParams.get("room") || "default";
      const roomStub = env.RELAY_ROOM.get(env.RELAY_ROOM.idFromName(roomId));
      return roomStub.fetch(request);
    }

    return new Response("Not found", { status: 404 });
  },
};

// 导出获取全局RSA密钥的函数  
export function getGlobalRsaCipher() {  
  return globalRsaCipher;  
}

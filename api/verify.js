const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');

// ==========================================
// 1. 初始化云端数据库连接
// 注意：这里的密钥必须使用 Service Role Key（最高权限），因为它在后端运行，绝对安全。
// ==========================================
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_KEY; 
const supabase = createClient(supabaseUrl, supabaseKey);

// ==========================================
// 2. 解密算法配置 (必须与 NFC 写入时的加密算法完全一致)
// ==========================================
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY; // 必须是 32 位字符串 (AES-256)
const ALGORITHM = 'aes-256-cbc';

/**
 * 解密函数：将 URL 里的 token 还原成真实的 UID
 * 假设前端传来的 token 格式为：IV(16字节的Hex) + 密文(Hex)
 */
function decryptToken(token) {
    try {
        // 拆分 IV (前32个字符，即16字节Hex) 和 密文
        const iv = Buffer.from(token.slice(0, 32), 'hex');
        const encryptedText = Buffer.from(token.slice(32), 'hex');
        
        const decipher = crypto.createDecipheriv(ALGORITHM, Buffer.from(ENCRYPTION_KEY), iv);
        let decrypted = decipher.update(encryptedText);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        
        return decrypted.toString(); // 返回真实的 UID (例如: "46:48:23:58:01:01:ae:e0")
    } catch (error) {
        console.error("解密失败:", error.message);
        return null;
    }
}

// ==========================================
// 3. 核心 API 接口逻辑 (支持 Token 解密 与 UID 明文 双轨制)
// ==========================================
module.exports = async function handler(req, res) {
    // 允许跨域请求 (CORS) - 保证前端 PWA 能够正常调用
    res.setHeader('Access-Control-Allow-Credentials', true);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    // 🌟 修复点：在这里一次性提取 token 和 uid，绝不重复声明
    const { token, uid } = req.query;
    let realUid = null;

    // --- Step 1: 识别并处理参数 (双轨制) ---
    if (token) {
        // 路线 A：如果是 token 进来，走加密解密流程 (例如扫二维码)
        realUid = decryptToken(token);
        if (!realUid) {
            await logVerification('Unknown', 'Fail', '解密失败：非法伪造的NFC标签');
            return res.status(403).json({ valid: false, message: '非法标签，请谨防假冒！' });
        }
    } else if (uid) {
        // 路线 B：如果是 uid 进来，直接使用明文 (例如安卓 NFC 贴贴)
        realUid = uid; 
    } else {
        // 路线 C：什么都没传，直接拦截
        return res.status(400).json({ valid: false, message: '缺少验证参数' });
    }

    try {
        // --- Step 2: 去数据库查询该 UID 是否存在且合法 ---
        const { data: product, error } = await supabase
            .from('product_whitelist')
            .select('*') // 使用 * 确保返回所有字段
            .eq('uid', realUid)
            .single();

        if (error || !product) {
            // UID 不在白名单中
            await logVerification(realUid, 'Fail', '数据库未找到匹配的UID');
            return res.status(404).json({ valid: false, message: '未找到产品信息，疑似伪造！' });
        }

        if (product.is_active === false) {
             // 标签已被注销（防二次灌装）
             await logVerification(realUid, 'Warning', '已注销或挂失的标签');
             return res.status(403).json({ valid: false, message: '该产品已被注销或存在异常，请勿购买！' });
        }

        // --- Step 3: 一切正常，记录成功查验日志 ---
        await logVerification(realUid, 'Success', '查验通过');
        
        // --- Step 4: 返回完整正品信息 ---
        return res.status(200).json({
            valid: true,
            message: '验证通过，确认为正品',
            product: {
                name: product.product_name,        
                batch: product.batch_number,       
                date: product.production_date,     
                factory: product.factory,          
                workshop: product.workshop,        
                line: product.production_line,     
                isOpened: product.is_opened,       
                alcohol: product.alcohol_content,   
                inspectResult: product.inspection_result, 
                inspectId: product.inspection_id    
            }
        });

    } catch (err) {
        console.error("数据库操作异常:", err);
        return res.status(500).json({ valid: false, message: '系统繁忙，请稍后再试' });
    }
};

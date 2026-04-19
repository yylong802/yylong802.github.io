const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');

// 1. 初始化云端数据库连接
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_KEY; 
const supabase = createClient(supabaseUrl, supabaseKey);

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY; 
const ALGORITHM = 'aes-256-cbc';

// ==========================================
// 辅助函数 1：解密 Token
// ==========================================
function decryptToken(token) {
    try {
        const iv = Buffer.from(token.slice(0, 32), 'hex');
        const encryptedText = Buffer.from(token.slice(32), 'hex');
        const decipher = crypto.createDecipheriv(ALGORITHM, Buffer.from(ENCRYPTION_KEY), iv);
        let decrypted = decipher.update(encryptedText);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return decrypted.toString(); 
    } catch (error) {
        console.error("解密失败:", error.message);
        return null;
    }
}

// ==========================================
// 辅助函数 2：写入查验日志 (提前声明，防止找不到)
// ==========================================
async function logVerification(uid, status, reason) {
    try {
        await supabase.from('check_logs').insert([
            { 
                target_uid: uid, 
                check_type: 'NFC', 
                result: status,
                notes: reason 
            }
        ]);
    } catch (logError) {
        console.error("日志写入失败:", logError.message);
    }
}

// ==========================================
// 核心 API 接口逻辑 (支持双轨制)
// ==========================================
module.exports = async function handler(req, res) {
    // 允许跨域请求 (CORS)
    res.setHeader('Access-Control-Allow-Credentials', true);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    const { token, uid } = req.query;
    let realUid = null;

    // --- Step 1: 识别并处理参数 ---
    if (token) {
        realUid = decryptToken(token);
        if (!realUid) {
            await logVerification('Unknown', 'Fail', '解密失败：非法伪造的NFC标签');
            return res.status(403).json({ valid: false, message: '非法标签，请谨防假冒！' });
        }
    } else if (uid) {
        realUid = uid; 
    } else {
        return res.status(400).json({ valid: false, message: '缺少验证参数' });
    }

    try {
        // --- Step 2: 去数据库查询该 UID 是否存在且合法 ---
        const { data: product, error } = await supabase
            .from('product_whitelist')
            .select('*') 
            .eq('uid', realUid)
            .single();

        if (error || !product) {
            await logVerification(realUid, 'Fail', '数据库未找到匹配的UID');
            return res.status(404).json({ valid: false, message: '未找到产品信息，疑似伪造！' });
        }

        if (product.is_active === false) {
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

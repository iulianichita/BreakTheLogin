import db from '../database.js';

function getClientIp(req) {
    const forwarded = req.headers['x-forwarded-for'];

    if (typeof forwarded === 'string' && forwarded.trim() !== '') {
        return forwarded.split(',')[0].trim();
    }

    const ip = req.ip ?? null;
    
    // converteste ::1 la 127.0.0.1
    if (ip === '::1') return '127.0.0.1';
    
    // converteste ::ffff:192.168.1.1 la 192.168.1.1
    if (ip?.startsWith('::ffff:')) return ip.substring(7);
    
    return ip;
}

export function logAudit({ req, userId = null, action, resource = null, resourceId = null }) {
    if (!action) {
        return;
    }

    const resourceIdValue = resourceId === null || resourceId === undefined
        ? null
        : String(resourceId);

    // db.run(
    //     `
    //         INSERT INTO audit_logs (user_id, action, resource, resource_id, ip_address)
    //         VALUES (?, ?, ?, ?, ?)
    //     `,
    //     [userId, action, resource, resourceIdValue, getClientIp(req)],
    //     (err) => {
    //         if (err) {
    //             console.error('Audit log insert failed:', err.message);
    //         }
    //     }
    // );
}
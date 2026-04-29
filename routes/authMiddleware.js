export const authMiddleware = (req, res, next) => {
    if (!req.session?.userId) {
        return res.status(401).json({ error: 'Login required' });
    }
    req.user = { id: req.session.userId, manager: req.session.manager };
    next();
};
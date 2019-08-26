const httpSig = require('http-sig');

/**
 * @param { { secret: string } } options 中间件配置
 *  {
 *      secret 签名密钥
 *  }
 */
module.exports = options => {
    return async (ctx, next) => {
        const url = ctx.url;
        const method = ctx.method;
        const pathInfo = url.substr(0, url.indexOf('?'));
        const params = method === 'GET' ? ctx.query : ctx.request.body;
        const secret = options.secret || '';
        const clientSig = ctx.get('x-sig') || '';
        const sig = httpSig.generate(method, pathInfo, params, secret);
        if (clientSig !== sig) {
            ctx.throw(400, 'Invalid signature, please check your http header x-sig parameter');
        }

        await next();
    };
};

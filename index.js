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
        const pos = url.indexOf('?');
        const pathInfo = pos === -1 ? url : url.substr(0, url.indexOf('?'));

        let params;
        if (ctx.get('content-type') === 'application/json') {
            params = ctx.request.rawBody;
        } else if (method === 'GET') {
            params = ctx.query;
        } else {
            params = ctx.request.body;
        }

        const secret = options.secret || '';
        const clientSig = ctx.get('x-sig') || '';
        const sig = httpSig.generate(method, pathInfo, params, secret);
        if (clientSig !== sig) {
            ctx.throw(400, 'Invalid signature, please check your http header x-sig parameter');
        }

        await next();
    };
};

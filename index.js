const http = require('http');
const VERSION = process.env.APP_VERSION || 'v1';
const ENV = process.env.APP_ENV || 'unknown';
http
    .createServer((_, res) => {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(`hello from ${ENV} — ${VERSION}\n`);
    })
    .listen(process.env.PORT || 8080);
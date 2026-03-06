const http = require('http');

const options = { hostname: 'localhost', port: 3000, path: '/favicon.ico', method: 'GET', timeout: 5000 };

const req = http.request(options, res => {
  console.log('STATUS', res.statusCode);
  console.log('HEADERS', JSON.stringify(res.headers));
  let bytes = 0;
  res.on('data', chunk => bytes += chunk.length);
  res.on('end', () => console.log('SIZE', bytes));
});

req.on('error', e => { console.error('ERR', e && (e.stack || e.message) ); process.exit(1); });
req.on('timeout', () => { console.error('ERR timeout'); req.destroy(); process.exit(1); });
req.end();

import http from 'node:http'

const alerts = []
const server = http.createServer(async (req, res) => {
  if (req.method === 'GET' && req.url === '/alerts') {
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify({ alerts }))
    return
  }
  if (req.method === 'POST' && req.url === '/alerts') {
    const chunks = []
    for await (const chunk of req) chunks.push(chunk)
    const body = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')
    alerts.push({ ...body, receivedAt: new Date().toISOString() })
    res.writeHead(202, { 'content-type': 'application/json' })
    res.end(JSON.stringify({ accepted: true }))
    return
  }
  res.writeHead(404)
  res.end('not found')
})

server.listen(Number(process.env.PORT ?? 9099), '0.0.0.0')

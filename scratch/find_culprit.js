const http = require('http');

async function main() {
  const targets = await new Promise((resolve, reject) => {
    http.get('http://127.0.0.1:9222/json', (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve(JSON.parse(data)));
    }).on('error', reject);
  });

  const page = targets.find(t => t.type === 'page' && t.url.includes('8501'));
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  let id = 1;
  const pending = new Map();

  ws.onopen = async () => {
    function send(method, params = {}) {
      return new Promise((resolve) => {
        const msgId = id++;
        pending.set(msgId, resolve);
        ws.send(JSON.stringify({ id: msgId, method, params }));
      });
    }

    ws.onmessage = (event) => {
      const msg = JSON.parse(event.data);
      if (msg.id && pending.has(msg.id)) {
        pending.get(msg.id)(msg.result);
        pending.delete(msg.id);
      }
    };

    await send('Emulation.setDeviceMetricsOverride', {
      width: 1440,
      height: 900,
      deviceScaleFactor: 1,
      mobile: false
    });

    await new Promise(r => setTimeout(r, 1000));

    // Click Chapter 4 Decide
    await send('Runtime.evaluate', {
      expression: `document.querySelectorAll('.narrative-spine button')[3].click()`
    });

    await new Promise(r => setTimeout(r, 500));

    const checkPoints = await send('Runtime.evaluate', {
      expression: `(() => {
        const points = [
          { x: 500, y: 200 },
          { x: 500, y: 300 },
          { x: 500, y: 350 },
          { x: 500, y: 400 },
          { x: 500, y: 450 },
          { x: 500, y: 500 },
          { x: 500, y: 600 }
        ];

        return points.map(pt => {
          const el = document.elementFromPoint(pt.x, pt.y);
          if (!el) return { ...pt, el: null };
          const s = window.getComputedStyle(el);
          return {
            ...pt,
            tag: el.tagName,
            className: el.className,
            id: el.id,
            zIndex: s.zIndex,
            opacity: s.opacity,
            bg: s.backgroundColor,
            bgImage: s.backgroundImage?.slice(0, 50),
            color: s.color,
            position: s.position,
            text: el.innerText ? el.innerText.slice(0, 50) : ''
          };
        });
      })()`,
      returnByValue: true
    });

    console.log('Element from points:');
    console.log(JSON.stringify(checkPoints.result.value, null, 2));

    ws.close();
    process.exit(0);
  };
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});

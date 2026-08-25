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
  if (!page) {
    console.error('Page not found in targets:', targets);
    process.exit(1);
  }

  // Node 18+ has built-in WebSocket!
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

    // Wait a moment for page to stabilize
    await new Promise(r => setTimeout(r, 2000));

    // Evaluate layout
    const evalRes = await send('Runtime.evaluate', {
      expression: `(() => {
        const getInfo = (sel) => {
          const el = document.querySelector(sel);
          if (!el) return null;
          const r = el.getBoundingClientRect();
          const s = window.getComputedStyle(el);
          return {
            rect: { top: r.top, left: r.left, width: r.width, height: r.height, bottom: r.bottom },
            style: {
              display: s.display,
              visibility: s.visibility,
              opacity: s.opacity,
              position: s.position,
              transform: s.transform,
              overflow: s.overflow,
              color: s.color,
              background: s.backgroundColor
            },
            text: el.innerText ? el.innerText.slice(0, 100) : ''
          };
        };

        return {
          windowScrollY: window.scrollY,
          appShell: getInfo('.app-shell'),
          sidebar: getInfo('.sidebar'),
          mainContent: getInfo('.main-content'),
          scenarioControl: getInfo('.scenario-control-bar'),
          spine: getInfo('.narrative-spine'),
          narrativeChapter: getInfo('.narrative-chapter'),
          chapterInner: getInfo('.chapter-inner'),
          chapterContext: getInfo('.chapter-context'),
          chapterBody: getInfo('.chapter-body'),
          heroAttempt: getInfo('.hero-attempt-wrapper'),
          heroCard: getInfo('.hero-attempt-card'),
          adaptiveBanner: getInfo('.adaptive-followup-banner'),
          ambientBg: getInfo('.ambient-background')
        };
      })()`,
      returnByValue: true
    });

    console.log(JSON.stringify(evalRes.result.value, null, 2));

    // Capture screenshot
    const shot = await send('Page.captureScreenshot', { format: 'png' });
    const fs = require('fs');
    fs.writeFileSync('scratch/cdp_screenshot.png', Buffer.from(shot.data, 'base64'));
    console.log('Saved scratch/cdp_screenshot.png');

    ws.close();
    process.exit(0);
  };
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});

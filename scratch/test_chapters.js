const http = require('http');
const fs = require('fs');

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

    // Set viewport
    await send('Emulation.setDeviceMetricsOverride', {
      width: 1440,
      height: 900,
      deviceScaleFactor: 1,
      mobile: false
    });

    await new Promise(r => setTimeout(r, 1500));

    async function shoot(name) {
      const shot = await send('Page.captureScreenshot', { format: 'png' });
      fs.writeFileSync(`scratch/${name}.png`, Buffer.from(shot.data, 'base64'));
      console.log(`Saved scratch/${name}.png`);
    }

    async function evalScript(code) {
      const res = await send('Runtime.evaluate', { expression: code, returnByValue: true });
      return res.result ? res.result.value : null;
    }

    await shoot('ch_initial');

    const spineButtons = await evalScript(`(() => {
      const btns = Array.from(document.querySelectorAll('.narrative-spine button'));
      return btns.map(b => b.innerText.split('\\n')[1]);
    })()`);
    console.log('Spine buttons found:', spineButtons);

    for (let i = 0; i < 7; i++) {
      const clicked = await evalScript(`(() => {
        const btns = document.querySelectorAll('.narrative-spine button');
        if (btns[${i}]) {
          btns[${i}].click();
          return btns[${i}].innerText.split('\\n')[1];
        }
        return null;
      })()`);
      console.log('Clicked:', clicked);
      await new Promise(r => setTimeout(r, 600));

      const info = await evalScript(`(() => {
        const chapter = document.querySelector('.narrative-chapter');
        if (!chapter) return { error: 'No .narrative-chapter found' };
        const r = chapter.getBoundingClientRect();
        return {
          top: r.top,
          left: r.left,
          width: r.width,
          height: r.height,
          title: chapter.querySelector('h3')?.innerText,
          textLen: chapter.innerText?.length
        };
      })()`);
      console.log(`Chapter ${i + 1} info:`, info);
      await shoot(`ch_${i + 1}_${clicked}`);
    }

    ws.close();
    process.exit(0);
  };
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});

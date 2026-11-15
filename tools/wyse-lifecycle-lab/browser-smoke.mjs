// Public-synthetic-only Chrome/Chromium UI qualification using the real
// server and its real WebCrypto Ed25519 witness/rotation code.
import puppeteer from 'puppeteer-core';
const port = 18085;
const chrome = process.env.CHROME_BIN;
const token = process.env.WYSE_SYNTHETIC_LAB_TOKEN;
if (!chrome || !token) throw Error('Chrome binary and ephemeral token required');
const browser = await puppeteer.launch({
 executablePath: chrome, headless: true,
 args: ['--no-sandbox','--disable-dev-shm-usage','--disable-gpu']
});
try {
 const page = await browser.newPage();
 await page.goto('http://127.0.0.1:' + port + '/', {waitUntil:'networkidle0'});
 await page.locator('#token').fill(token);
 await page.locator('#refresh').click();
 await page.waitForFunction(() => document.getElementById('result').textContent.includes('refreshed'));
 await page.locator('#device').fill('synthetic-browser-01');
 await page.locator('#enroll').click();
 await page.waitForFunction(() => document.getElementById('result').textContent.includes('Simulated enrollment accepted'), {timeout:30000});
 const states=['commission','qualify','drain','resume','quarantine','repair','commission','qualify','drain','retire'];
 const expected=['COMMISSIONED','READY','DRAINED','READY','QUARANTINED','ENROLLED','COMMISSIONED','READY','DRAINED','RETIRED'];
 await page.locator('#rotate').click();
 await page.waitForFunction(() => document.getElementById('result').textContent.includes('Synthetic key rotated'), {timeout:30000});
 for (let i=0;i<states.length;i++) {
  await page.select('#action',states[i]);
  await page.locator('#apply').click();
  await page.waitForFunction((state) => document.getElementById('result').textContent.includes('→ '+state), {timeout:30000}, expected[i]);
 }
 const receipt=await page.$eval('#events', (el) => el.textContent);
 const events=JSON.parse(receipt).events;
 if (events.length < 12) throw Error('missing enrollment/rotation/lifecycle receipts');
 if (!events.some(e=>e.action==='ROTATE_KEY')) throw Error('missing rotation audit');
 if (!events.some(e=>e.action==='RETIRE')) throw Error('missing retirement audit');
 const inventory=JSON.parse(await page.$eval('#nodes', (el)=>el.textContent)).nodes;
 if (inventory.length!==1||inventory[0].state!=='RETIRED'||inventory[0].hardware_verified!==false) throw Error('incorrect human UI inventory');
 console.log('HUMAN_BROWSER_CHROMIUM_ED25519_ENROLL=PASS');
 console.log('HUMAN_BROWSER_ROTATE_WITH_OLD_NEW_KEY=PASS');
 console.log('HUMAN_BROWSER_ALL_LIFECYCLE_ACTIONS=PASS');
 console.log('HUMAN_BROWSER_AUDIT_AND_RETIREMENT=PASS');
 console.log('PHYSICAL_HARDWARE_VERIFICATION=FALSE');
} finally {
 await browser.close();
}

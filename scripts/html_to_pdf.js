const puppeteer = require('puppeteer');
const path = require('path');

(async () => {
  const browser = await puppeteer.launch({ headless: true });
  const page = await browser.newPage();

  const htmlPath = path.resolve(__dirname, '../docs/technical_docs.html');
  await page.goto(`file://${htmlPath}`, { waitUntil: 'networkidle0', timeout: 30000 });

  // Wait for fonts to load
  await page.evaluateHandle('document.fonts.ready');

  const outPath = path.resolve(__dirname, '../GRC_Toolkit_Technical_Documentation.pdf');
  await page.pdf({
    path: outPath,
    format: 'Letter',
    margin: { top: '0.6in', right: '0.65in', bottom: '0.6in', left: '0.65in' },
    printBackground: true,
    displayHeaderFooter: true,
    headerTemplate: '<div></div>',
    footerTemplate: `
      <div style="width:100%;text-align:center;font-size:9px;color:#94a3b8;font-family:Calibri,Arial,sans-serif;padding-top:4px;">
        Page <span class="pageNumber"></span> of <span class="totalPages"></span>
      </div>`,
  });

  console.log(`PDF written: ${outPath}`);
  await browser.close();
})();

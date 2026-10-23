import path from 'node:path';

import PDFDocument from 'pdfkit';

import { RISK_LABEL } from './risk.ts';
import type { DomainReport } from './score.ts';

const RED = '#D4041C';
const INK = '#0B0B0D';
const MUTED = '#6B6B75';
const LINE = '#E7E7EA';
const STATUS: Record<string, [string, string]> = {
  pass: ['#15803D', 'Pass'],
  warn: ['#B45309', 'Needs attention'],
  fail: ['#C81E1E', 'Fail'],
  missing: ['#C81E1E', 'Missing'],
  unknown: ['#6B6B75', 'Unavailable'],
};
const RISK: Record<string, string> = { low: '#15803D', medium: '#B45309', high: '#C81E1E' };

/** A branded PDF of a domain report: summary, ratings, every check and the to-do list. */
export function reportPdf(r: DomainReport): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ size: 'A4', margin: 48, info: { Title: `Domain security report: ${r.domain}`, Author: 'Axis Intelligence' } });
    const chunks: Buffer[] = [];
    doc.on('data', (c: Buffer) => chunks.push(c));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);
    const W = doc.page.width - 96;

    // header band
    doc.rect(0, 0, doc.page.width, 92).fill(INK);
    doc.rect(0, 92, doc.page.width, 4).fill(RED);
    try {
      doc.image(path.join(process.cwd(), 'public', 'axis-mark.png'), 48, 28, { height: 36 });
    } catch {
      // logo is optional
    }
    doc.fillColor('#FFFFFF').font('Helvetica-Bold').fontSize(18).text('Axis', 150, 34, { continued: true }).fillColor(RED).text(' Intelligence');
    doc.fillColor('#BBBBC2').font('Helvetica').fontSize(9).text('Email and domain security report', 150, 58);

    // summary
    let y = 120;
    doc.fillColor(MUTED).font('Helvetica').fontSize(9).text('DOMAIN', 48, y);
    doc.fillColor(INK).font('Helvetica-Bold').fontSize(20).text(r.domain, 48, y + 12, { width: W - 140 });
    doc.fillColor(MUTED).font('Helvetica').fontSize(9).text(`Checked ${new Date(r.checkedAt).toUTCString()}`, 48, y + 38);
    doc.roundedRect(48 + W - 120, y, 120, 64, 10).fill(INK);
    doc.fillColor('#FFFFFF').font('Helvetica-Bold').fontSize(30).text(String(r.score), 48 + W - 120, y + 8, { width: 80, align: 'center' });
    doc.fontSize(9).font('Helvetica').text('out of 100', 48 + W - 120, y + 44, { width: 80, align: 'center' });
    doc.font('Helvetica-Bold').fontSize(26).fillColor(RED).text(r.grade, 48 + W - 44, y + 16, { width: 36, align: 'center' });
    y += 76;
    doc.fillColor(RISK[r.risk]).font('Helvetica-Bold').fontSize(11).text(`${RISK_LABEL[r.risk].toUpperCase()} RISK`, 48, y);
    doc.fillColor(INK).font('Helvetica').fontSize(10.5).text(r.summary, 48, y + 16, { width: W });
    y = doc.y + 18;

    // ratings
    const colW = (W - 24) / 3;
    r.categories.forEach((c, i) => {
      const x = 48 + i * (colW + 12);
      doc.roundedRect(x, y, colW, 92, 10).lineWidth(1).strokeColor(LINE).stroke();
      doc.fillColor(INK).font('Helvetica-Bold').fontSize(11).text(c.title, x + 12, y + 12);
      doc.fillColor(INK).fontSize(22).text(`${c.rating}`, x + 12, y + 30, { continued: true }).fillColor(MUTED).fontSize(11).text(' / 5');
      doc.fillColor(RISK[c.risk]).font('Helvetica-Bold').fontSize(9).text(`${RISK_LABEL[c.risk].toUpperCase()} RISK`, x + 12, y + 62);
      doc.fillColor(MUTED).font('Helvetica').fontSize(8).text(c.checks.map((id) => r.checks[id].title).join(' · '), x + 12, y + 76, { width: colW - 24 });
    });
    y += 108;

    const ensure = (h: number) => {
      if (y + h > doc.page.height - 60) {
        doc.addPage();
        y = 48;
      }
    };

    // common records
    ensure(70);
    doc.fillColor(INK).font('Helvetica-Bold').fontSize(13).text('Common records', 48, y);
    y += 20;
    const common: [string, string][] = [
      ['DNS provider', `${r.common.dnsProvider}${r.common.ns.length ? ` (${r.common.ns.join(', ')})` : ''}`],
      ['Email provider', `${r.common.emailProvider}${r.common.mx.length ? ` (${r.common.mx.join(', ')})` : ''}`],
      ['Website', r.common.website ? `Yes (${r.common.a.join(', ')})` : 'No address record'],
    ];
    for (const [k, v] of common) {
      doc.fillColor(MUTED).font('Helvetica').fontSize(9.5).text(k, 48, y, { width: 110 });
      doc.fillColor(INK).text(v, 160, y, { width: W - 112 });
      y = doc.y + 6;
    }
    y += 8;

    // checks
    for (const id of ['dmarc', 'spf', 'dkim', 'mtasts', 'tlsrpt', 'bimi', 'mx']) {
      const c = r.checks[id];
      if (!c) continue;
      ensure(90);
      doc.moveTo(48, y).lineTo(48 + W, y).lineWidth(1).strokeColor(LINE).stroke();
      y += 10;
      const [col, label] = STATUS[c.status];
      doc.fillColor(INK).font('Helvetica-Bold').fontSize(12).text(c.title, 48, y);
      doc.fillColor(col).fontSize(9).text(label.toUpperCase(), 48, y + 2, { width: W, align: 'right' });
      y += 18;
      doc.fillColor(INK).font('Helvetica').fontSize(10).text(c.summary, 48, y, { width: W });
      y = doc.y + 4;
      if (c.record) {
        doc.fillColor(MUTED).font('Courier').fontSize(8).text(c.record.slice(0, 600), 56, y, { width: W - 16 });
        y = doc.y + 4;
      }
      for (const f of c.findings.slice(0, 6)) {
        ensure(20);
        const mark = f.level === 'ok' ? '✓' : f.level === 'bad' ? '✕' : f.level === 'warn' ? '!' : '•';
        doc.fillColor(f.level === 'ok' ? '#15803D' : f.level === 'bad' ? '#C81E1E' : f.level === 'warn' ? '#B45309' : MUTED).font('Helvetica-Bold').fontSize(9).text(mark === '✓' ? '+' : mark === '✕' ? 'x' : mark, 56, y, { width: 10 });
        doc.fillColor(INK).font('Helvetica').fontSize(9).text(f.text, 70, y, { width: W - 22 });
        y = doc.y + 3;
      }
      y += 8;
    }

    if (r.recommendations.length) {
      ensure(80);
      doc.fillColor(INK).font('Helvetica-Bold').fontSize(13).text('What to fix first', 48, y);
      y += 20;
      r.recommendations.forEach((rec, i) => {
        ensure(24);
        doc.fillColor(RED).font('Helvetica-Bold').fontSize(10).text(`${i + 1}.`, 48, y, { width: 16 });
        doc.fillColor(INK).font('Helvetica').fontSize(10).text(rec, 66, y, { width: W - 18 });
        y = doc.y + 6;
      });
    }

    doc.fillColor(MUTED).font('Helvetica').fontSize(8).text('Axis Intelligence by Axis Solutions · Mobility. Agility. Security.', 48, doc.page.height - 40, { width: W, align: 'center' });
    doc.end();
  });
}

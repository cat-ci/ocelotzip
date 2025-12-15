import sharp from 'sharp';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';

const allowedFormats = ['png', 'jpeg', 'jpg', 'webp', 'avif', 'tiff', 'gif', 'bmp'];

async function process(inputPath, params, tempDir) {
  let img = sharp(inputPath);
  const meta = await img.metadata();

  // Determine resize options
  let resizeOpts = {};
  if (params.s) {
    // Scale percent
    const scale = Math.max(1, Math.min(1000, parseInt(params.s, 10)));
    resizeOpts.width = Math.round(meta.width * scale / 100);
    resizeOpts.height = Math.round(meta.height * scale / 100);
  } else {
    if (params.w) resizeOpts.width = Math.max(1, parseInt(params.w, 10));
    if (params.h) resizeOpts.height = Math.max(1, parseInt(params.h, 10));
    if (resizeOpts.width && resizeOpts.height) {
      resizeOpts.fit = 'fill';
    }
  }
  if (resizeOpts.width || resizeOpts.height) {
    img = img.resize(resizeOpts);
  }

  // Format
  let format = null;
  if (params.f && allowedFormats.includes(params.f.toLowerCase())) {
    format = params.f.toLowerCase();
    if (format === 'jpg') format = 'jpeg';
  } else {
    // Use original extension if not set
    format = meta.format;
    if (format === 'jpg') format = 'jpeg';
    if (!allowedFormats.includes(format)) format = 'png';
  }

  // Quality
  let quality = 80;
  if (params.q) {
    quality = Math.max(1, Math.min(100, parseInt(params.q, 10)));
  }

  let outputOptions = {};
  if (format === 'jpeg') {
    outputOptions.quality = quality;
    outputOptions.progressive = true;
  } else if (format === 'webp') {
    outputOptions.quality = quality;
  } else if (format === 'avif') {
    outputOptions.quality = quality;
  } else if (format === 'tiff') {
    outputOptions.quality = quality;
  } else if (format === 'gif') {
    // GIF doesn't support quality parameter
  } else if (format === 'png') {
    // PNG is lossless - use compression level instead
    outputOptions.compressionLevel = Math.max(0, Math.min(9, Math.floor(quality / 11)));
  } else if (format === 'bmp') {
    // BMP doesn't support quality parameter
  }

  img = img.toFormat(format, outputOptions);

  // Output file path
  const hash = crypto
    .createHash('md5')
    .update(inputPath + JSON.stringify(params))
    .digest('hex');
  const outFile = path.join(tempDir, `${hash}.${format}`);

  await img.toFile(outFile);

  return outFile;
}

export { process };

import ffmpeg from 'fluent-ffmpeg';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';

// Map requested format → { ext, codec, defaultQuality, defaultBitrate(kbps), ffFormat }
const formatMap = {
  mp3:  { ext: 'mp3',  codec: 'libmp3lame', defaultQuality: null, defaultBitrate: 192, ffFormat: 'mp3'  },
  ogg:  { ext: 'ogg',  codec: 'libvorbis',  defaultQuality: 4,    defaultBitrate: null, ffFormat: 'ogg'  },
  opus: { ext: 'opus', codec: 'libopus', defaultQuality: null, defaultBitrate: 128, ffFormat: 'ogg' },
  wav:  { ext: 'wav',  codec: 'pcm_s16le',  defaultQuality: null, defaultBitrate: null, ffFormat: 'wav'  },
  flac: { ext: 'flac', codec: 'flac',       defaultQuality: null, defaultBitrate: null, ffFormat: 'flac' },
  m4a:  { ext: 'm4a',  codec: 'aac',        defaultQuality: null, defaultBitrate: 192, ffFormat: 'mp4'  },
  aac:  { ext: 'aac',  codec: 'aac',        defaultQuality: null, defaultBitrate: 192, ffFormat: 'adts' },
};

/**
 * Clamp n between min and max.
 */
function clamp(n, min, max) {
  return n < min ? min : n > max ? max : n;
}

/**
 * Map qualityPercent (0–100) to bitrate (kbps).
 */
function qualityToBitrate(qPercent, defaultBitrate) {
  if (!defaultBitrate) return null;
  const pct = clamp(parseInt(qPercent, 10) || 0, 0, 100) / 100;
  return Math.round(defaultBitrate * pct);
}

/**
 * Map qualityPercent (0–100) to Vorbis audioQuality (0–10).
 */
function qualityToVorbis(qPercent, defaultQ) {
  const pct = clamp(parseInt(qPercent, 10) || 0, 0, 100) / 100;
  return clamp(pct * 10, 0, 10);
}

/**
 * Process an audio file: transcode format & adjust quality.
 *
 * @param {string} inputPath
 * @param {{f?:string, q?:number}} params
 * @param {string} tempDir
 * @returns {Promise<string>} outPath
 */
function process(inputPath, params, tempDir) {
  return new Promise((resolve, reject) => {
    // Validate input
    if (!fs.existsSync(inputPath)) {
      return reject(new Error('Input file does not exist'));
    }
    const stat = fs.statSync(inputPath);
    if (!stat.isFile() || stat.size === 0) {
      return reject(new Error('Input file is empty or invalid'));
    }

    // Determine desired format
    const origExt = path.extname(inputPath).slice(1).toLowerCase();
    const reqFmt = (params.f || origExt).toLowerCase();
    const fmt = formatMap[reqFmt] || formatMap[origExt] || formatMap.mp3;
    const { ext: outExt, codec, defaultQuality, defaultBitrate, ffFormat } = fmt;

    // Prepare output path
    fs.mkdirSync(tempDir, { recursive: true });
    const hash = crypto
      .createHash('md5')
      .update(inputPath + JSON.stringify(params))
      .digest('hex');
    const outPath = path.join(tempDir, `${hash}.${outExt}`);

    // Collect FFmpeg stderr
    const ffmpegLogs = [];

    // Build ffmpeg command
    let cmd = ffmpeg(inputPath)
      .noVideo()
      .audioCodec(codec)
      .format(ffFormat)
      .outputOptions('-y') // overwrite
      .on('start', cmdLine => {
        console.log(`[audio] ffmpeg start: ${cmdLine}`);
      })
      .on('stderr', line => {
        ffmpegLogs.push(line);
      })
      .on('error', err => {
        const fullErr = [`ffmpeg error: ${err.message}`, ...ffmpegLogs].join('\n');
        console.error('[audio] ' + fullErr);
        reject(new Error(fullErr));
      })
      .on('end', () => {
        console.log(`[audio] ffmpeg finished, output: ${outPath}`);
        resolve(outPath);
      });

    // Apply quality settings
    if (outExt === 'ogg') {
      // Vorbis: use VBR quality scale 0–10
      const qv = params.q != null
        ? qualityToVorbis(params.q, defaultQuality)
        : defaultQuality;
      cmd = cmd.audioQuality(qv);
    } else if (defaultBitrate) {
      // CBR codecs: use bitrate based on quality %
      const br = params.q != null
        ? qualityToBitrate(params.q, defaultBitrate)
        : defaultBitrate;
      cmd = cmd.audioBitrate(br ? `${br}k` : undefined);
    }

    // AAC/M4A requires experimental flag
    if (outExt === 'aac' || outExt === 'm4a') {
      cmd = cmd.outputOptions('-strict', '-2');
    }

    // Run ffmpeg
    cmd.output(outPath).run();
  });
}

export { process };

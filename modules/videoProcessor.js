import ffmpeg from 'fluent-ffmpeg';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';

/**
 * Map container format to video codec and codec-specific options
 */
const formatMap = {
  mp4: { codec: 'libx264', ext: 'mp4' },
  mov: { codec: 'libx264', ext: 'mov' },
  webm: { codec: 'libvpx', ext: 'webm', opts: ['-b:v', '1M'] },
  ogg: { codec: 'libtheora', ext: 'ogv' },
  ogv: { codec: 'libtheora', ext: 'ogv' },
  av1: { codec: 'libaom-av1', ext: 'mkv' },
  hevc: { codec: 'libx265', ext: 'mp4' },
};

/**
 * Probe video metadata (width, height) using ffprobe.
 *
 * @param {string} inputPath
 * @returns {Promise<{width: number, height: number}>}
 */
function probeVideo(inputPath) {
  return new Promise((resolve, reject) => {
    ffmpeg.ffprobe(inputPath, (err, metadata) => {
      if (err) return reject(err);
      const stream = metadata.streams.find(s => s.width && s.height);
      if (!stream) return reject(new Error('No video stream found'));
      resolve({ width: stream.width, height: stream.height });
    });
  });
}

/**
 * Process a video file with given parameters.
 *
 * @param {string} inputPath - Path to the original video.
 * @param {object} params - { f, w, h, s, q }
 * @param {string} tempDir - Directory to save processed file.
 * @returns {Promise<string>} - Path to processed file.
 */
function process(inputPath, params, tempDir) {
  return new Promise(async (resolve, reject) => {
    // Read original extension & metadata
    const origExt = path.extname(inputPath).toLowerCase().replace('.', '');
    const fmtKey = (params.f || origExt).toLowerCase();
    const fmt = formatMap[fmtKey] || formatMap['mp4'];
    const codec = fmt.codec;
    const outExt = fmt.ext;

    // Quality → CRF for x264/x265/aom
    let crf = 23;
    if (params.q) {
      const q = Math.max(1, Math.min(100, parseInt(params.q, 10)));
      // Map quality 1–100 to CRF 51–0
      crf = Math.round((100 - q) * 51 / 100);
    }

    // Determine resize string
    let sizeStr = null;
    if (params.s) {
      // scale percent
      const scale = Math.max(1, Math.min(1000, parseInt(params.s, 10)));
      // we'll compute exact dimensions by probing input
      try {
        const probe = await probeVideo(inputPath);
        const w = Math.round(probe.width * scale / 100);
        const h = Math.round(probe.height * scale / 100);
        sizeStr = `${w}x${h}`;
      } catch (e) {
        return reject(e);
      }
    } else if (params.w || params.h) {
      const w = params.w ? Math.max(1, parseInt(params.w, 10)) : '?';
      const h = params.h ? Math.max(1, parseInt(params.h, 10)) : '?';
      sizeStr = `${w}x${h}`;
    }

    // Generate unique output filename
    const hash = crypto
      .createHash('md5')
      .update(inputPath + JSON.stringify(params))
      .digest('hex');
    const outPath = path.join(tempDir, `${hash}.${outExt}`);

    // Ensure temp directory exists
    fs.mkdirSync(tempDir, { recursive: true });

    // Collect FFmpeg stderr for logging
    const ffmpegLogs = [];

    // Build ffmpeg command
    let cmd = ffmpeg(inputPath)
      .videoCodec(codec)
      .outputOptions(['-crf', crf.toString()])
      .on('start', cmdLine => {
        console.log(`[video] ffmpeg start: ${cmdLine}`);
      })
      .on('stderr', line => {
        ffmpegLogs.push(line);
      })
      .on('error', (err) => {
        const fullErr = [`ffmpeg error: ${err.message}`, ...ffmpegLogs].join('\n');
        console.error('[video] ' + fullErr);
        reject(new Error(fullErr));
      })
      .on('end', () => {
        console.log(`[video] ffmpeg finished, output: ${outPath}`);
        resolve(outPath);
      });

    if (fmt.opts) {
      cmd = cmd.outputOptions(fmt.opts);
    }
    if (sizeStr) {
      cmd = cmd.size(sizeStr);
    }
    cmd = cmd.format(outExt).output(outPath).run();
  });
}

export { process };

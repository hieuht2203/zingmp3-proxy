import express from "express";
import * as zing from "zingmp3-api-full";
import { Readable } from "stream";
import crypto from "crypto";

const app = express();
const PORT = 5005;

// Helper: normalize different shapes of lyricDetail from ZingMp3
function parseLyricDetail(lyricDetail) {
  if (!lyricDetail || !lyricDetail.data) return { type: 'none' };
  const d = lyricDetail.data;

  // If structured sentences (word-level timing)
  if (Array.isArray(d.sentences) && d.sentences.length > 0) {
    return { type: 'sentences', sentences: d.sentences, metadata: d.metadata };
  }

  // Some responses include a plain lyric string under different keys
  if (typeof d.lyric === 'string' && d.lyric.trim()) {
    return { type: 'text', text: d.lyric };
  }

  if (typeof d.lyrics === 'string' && d.lyrics.trim()) {
    return { type: 'text', text: d.lyrics };
  }

  // Some providers put the raw lyric under 'content' or 'raw'
  if (typeof d.content === 'string' && d.content.trim()) {
    return { type: 'text', text: d.content };
  }

  if (typeof d.raw === 'string' && d.raw.trim()) {
    return { type: 'text', text: d.raw };
  }

  // If there's an object with lines
  if (Array.isArray(d.lines) && d.lines.length > 0) {
    return { type: 'text', text: d.lines.map(l => (typeof l === 'string' ? l : l.text)).join('\n') };
  }

  // Zing sometimes returns a .lrc file URL in data.file
  if (typeof d.file === 'string' && d.file.trim()) {
    return { type: 'file', url: d.file };
  }

  // Nothing recognized
  return { type: 'none' };
}

// ESP32 Authentication
const SECRET_KEY = "your-esp32-secret-key-2024";

// Middleware để xác thực ESP32
function authenticateESP32(req, res, next) {
  const macAddress = req.headers['x-mac-address'];
  const chipId = req.headers['x-chip-id'];
  const timestamp = req.headers['x-timestamp'];
  const dynamicKey = req.headers['x-dynamic-key'];

  // Kiểm tra header có đầy đủ không
  if (!macAddress || !chipId || !timestamp || !dynamicKey) {
    console.log("❌ Missing authentication headers:", {
      macAddress: !!macAddress,
      chipId: !!chipId, 
      timestamp: !!timestamp,
      dynamicKey: !!dynamicKey
    });
    return res.status(401).json({ error: "ESP32动态密钥验证失败" });
  }

  console.log(`🔐 ESP32 Auth attempt - MAC: ${macAddress}, ChipID: ${chipId}`);

  // Kiểm tra timestamp (cho phép sai lệch 30 phút để tránh lỗi đồng bộ thời gian)
  const now = Math.floor(Date.now() / 1000);
  const reqTime = parseInt(timestamp);
  const timeDiff = Math.abs(now - reqTime);
  
  console.log(`🕐 Timestamp check - Server: ${now}, ESP32: ${reqTime}, Diff: ${timeDiff}s`);
  
  // Kiểm tra nếu ESP32 timestamp quá nhỏ (chưa đồng bộ NTP)
  if (reqTime < 1000000000) { // Timestamp nhỏ hơn năm 2001 = chưa đồng bộ
    console.log(`⚠️ ESP32 timestamp seems not synced with NTP (${reqTime}), skipping timestamp check`);
    // Bỏ qua kiểm tra timestamp và chỉ xác thực bằng MAC/ChipID
  } else {
    // Nới lỏng thời gian cho phép lên 30 phút (1800 giây)
    if (timeDiff > 1800) {
      console.log(`❌ Timestamp expired - Diff: ${timeDiff}s > 1800s`);
      return res.status(401).json({ error: "ESP32动态密钥验证失败" });
    }
  }

  // Tạo lại dynamic key để xác thực
  const data = `${macAddress}:${chipId}:${timestamp}:${SECRET_KEY}`;
  const hash = crypto.createHash('sha256').update(data).digest('hex');
  const expectedKey = hash.substring(0, 32).toUpperCase();

  console.log(`🔑 Key verification - Expected: ${expectedKey}, Received: ${dynamicKey}`);

  // Nếu ESP32 chưa đồng bộ thời gian, thử tạo key với timestamp = 0
  if (dynamicKey !== expectedKey && reqTime < 1000000000) {
    console.log(`🔄 ESP32 timestamp not synced, trying with fallback method...`);
    
    // Thử với một số timestamp phổ biến khi ESP32 chưa đồng bộ
    const fallbackTimestamps = [0, 1, reqTime];
    let authSuccess = false;
    
    for (const fallbackTime of fallbackTimestamps) {
      const fallbackData = `${macAddress}:${chipId}:${fallbackTime}:${SECRET_KEY}`;
      const fallbackHash = crypto.createHash('sha256').update(fallbackData).digest('hex');
      const fallbackKey = fallbackHash.substring(0, 32).toUpperCase();
      
      console.log(`🔄 Trying fallback timestamp ${fallbackTime}: ${fallbackKey}`);
      
      if (dynamicKey === fallbackKey) {
        console.log(`✅ Authentication successful with fallback timestamp: ${fallbackTime}`);
        authSuccess = true;
        break;
      }
    }
    
    if (!authSuccess) {
      console.log("❌ All authentication attempts failed - Auth data:", data);
      return res.status(401).json({ error: "ESP32动态密钥验证失败" });
    }
  } else if (dynamicKey !== expectedKey) {
    console.log("❌ Invalid dynamic key - Auth data:", data);
    return res.status(401).json({ error: "ESP32动态密钥验证失败" });
  }

  console.log(`✅ ESP32 authenticated: ${macAddress}`);
  next();
}

// API để lấy thông tin bài hát (cho ESP32)
app.get("/stream_pcm", authenticateESP32, async (req, res) => {
  const song = req.query.song || "";
  const artist = req.query.artist || "";

  try {
    console.log(`🎵 ESP32 yêu cầu: ${song} - ${artist}`);

    // 🔍 Tìm bài hát
    const search = await zing.ZingMp3.search(`${song} ${artist}`);
    const result = search.data.songs?.[0];

    if (!result) {
      return res.status(404).json({ error: "Không tìm thấy bài hát" });
    }

    console.log(`🎶 Tìm thấy: ${result.title} - ${result.artistsNames} (${result.encodeId})`);

    // 🔗 Lấy link nhạc
    const detail = await zing.ZingMp3.getSong(result.encodeId);
    const url128 = detail.data["128"];

    if (!url128) {
      return res.status(404).json({ error: "Không lấy được link nhạc 128kbps" });
    }

    // 🎼 Lấy link lời bài hát (nếu có). Trả về endpoint .lrc để ESP32 dễ parse
    let lyricUrl = "";
    try {
      const lyricDetail = await zing.ZingMp3.getLyric(result.encodeId);
      const parsed = parseLyricDetail(lyricDetail);
      console.log('ℹ️ lyricDetail shape:', parsed.type);
      if (parsed.type !== 'none') {
        // Trỏ tới endpoint trả về file LRC plain-text (endpoint will handle different shapes)
        lyricUrl = `/lyric.lrc?id=${result.encodeId}`;
      } else {
        try {
          console.log('⚠️ No parsed lyrics for', result.encodeId, '- raw lyricDetail:', JSON.stringify(lyricDetail).slice(0, 20000));
        } catch (e) {
          console.log('⚠️ No parsed lyrics and failed to stringify lyricDetail for', result.encodeId);
        }
      }
    } catch (lyricErr) {
      console.log("⚠️ Không lấy được lời bài hát:", lyricErr.message);
    }

    // � Trả về JSON với thông tin bài hát (theo format ESP32 mong đợi)
    const response = {
      artist: result.artistsNames || artist,
      title: result.title || song,
      audio_url: `/audio?url=${encodeURIComponent(url128)}`,
      lyric_url: lyricUrl,
      duration: result.duration || 0,
      encodeId: result.encodeId
    };

    console.log(`✅ Trả về thông tin bài hát cho ESP32`);
    res.json(response);

  } catch (err) {
    console.error("🔥 Lỗi:", err);
    res.status(500).json({ error: "Lỗi server: " + err.message });
  }
});

// API debug không cần xác thực (chỉ dùng để test)
app.get("/stream_pcm_debug", async (req, res) => {
  const song = req.query.song || "";
  const artist = req.query.artist || "";

  console.log(`🐛 DEBUG: ${song} - ${artist} (không xác thực)`);

  try {
    // 🔍 Tìm bài hát
    const search = await zing.ZingMp3.search(`${song} ${artist}`);
    const result = search.data.songs?.[0];

    if (!result) {
      return res.status(404).json({ error: "Không tìm thấy bài hát" });
    }

    // 🔗 Lấy link nhạc
    const detail = await zing.ZingMp3.getSong(result.encodeId);
    const url128 = detail.data["128"];

    if (!url128) {
      return res.status(404).json({ error: "Không lấy được link nhạc 128kbps" });
    }

    // 📋 Trả về JSON với thông tin bài hát
    // Nếu có lời, trả về endpoint .lrc giống /stream_pcm để test dễ dàng
    let debugLyricUrl = "";
    try {
      const lyricDetail = await zing.ZingMp3.getLyric(result.encodeId);
      const parsed = parseLyricDetail(lyricDetail);
      console.log('🐛 DEBUG lyricDetail shape:', parsed.type);
      if (parsed.type !== 'none') {
        debugLyricUrl = `/lyric.lrc?id=${result.encodeId}`;
      } else {
        try {
          console.log('⚠️ DEBUG no parsed lyrics for', result.encodeId, '- raw lyricDetail:', JSON.stringify(lyricDetail).slice(0,20000));
        } catch (e) {
          console.log('⚠️ DEBUG no parsed lyrics and failed to stringify lyricDetail for', result.encodeId);
        }
      }
    } catch (e) {
      // ignore
    }

    const response = {
      artist: result.artistsNames || artist,
      title: result.title || song,
      audio_url: `/audio?url=${encodeURIComponent(url128)}`,
      lyric_url: debugLyricUrl,
      duration: result.duration || 0,
      encodeId: result.encodeId
    };

    console.log(`✅ DEBUG: Trả về thông tin bài hát`);
    res.json(response);

  } catch (err) {
    console.error("🔥 DEBUG Lỗi:", err);
    res.status(500).json({ error: "Lỗi server: " + err.message });
  }
});

// API để stream audio (được gọi từ ESP32 thông qua audio_url)
app.get("/audio", async (req, res) => {
  const audioUrl = req.query.url;
  if (!audioUrl) return res.status(400).send("❌ Thiếu URL audio");

  try {
    console.log("🔊 Stream audio từ:", audioUrl);
    // Hỗ trợ forward header Range từ ESP32 (nếu có) để yêu cầu partial content
    const upstreamHeaders = {};
    if (req.headers.range) {
      upstreamHeaders['range'] = req.headers.range;
      console.log('➡️ Forwarding Range header to upstream:', req.headers.range);
    }

    const response = await fetch(decodeURIComponent(audioUrl), { headers: upstreamHeaders });

    if (!response.ok) throw new Error("Không thể tải nhạc");

    // Forward một số header quan trọng từ upstream về client để tránh client nhúng (ESP32)
    const headersToForward = {};
    const ct = response.headers.get('content-type');
    const cl = response.headers.get('content-length');
    const cr = response.headers.get('content-range');
    const ar = response.headers.get('accept-ranges');
    const te = response.headers.get('transfer-encoding');

    if (ct) headersToForward['Content-Type'] = ct;
    else headersToForward['Content-Type'] = 'application/octet-stream';

    if (cl) headersToForward['Content-Length'] = cl;
    if (cr) headersToForward['Content-Range'] = cr;
    if (ar) headersToForward['Accept-Ranges'] = ar;
    if (te) headersToForward['Transfer-Encoding'] = te;

    // Đảm bảo tránh một số proxy/edge re-encoding; đóng connection sau khi stream
    headersToForward['Cache-Control'] = 'no-transform'; // tránh CF/edge nén
    headersToForward['Connection'] = 'close';

    // Thiết lập status và headers cho response trả về ESP32
    res.status(response.status);
    res.set(headersToForward);

    const nodeStream = Readable.fromWeb(response.body);
    nodeStream.on('error', (err) => {
      console.log('⚠️ Lỗi stream:', err.message);
      // nếu còn header chưa gửi, gửi lỗi; cuối cùng close response
      try { res.end(); } catch (e) { /* ignore */ }
    });

    nodeStream.pipe(res);
  } catch (err) {
    console.error("🔥 Lỗi stream audio:", err);
    if (!res.headersSent) {
      res.status(500).send("Lỗi stream: " + err.message);
    }
  }
});


// API để lấy lời bài hát
app.get("/lyric", async (req, res) => {
  const songId = req.query.id;

  if (!songId) {
    return res.status(400).json({ error: "Thiếu ID bài hát" });
  }

  try {
    console.log("🎼 Lấy lời bài hát cho ID:", songId);

    const lyricDetail = await zing.ZingMp3.getLyric(songId);
    const parsed = parseLyricDetail(lyricDetail);
    console.log('🎼 /lyric parsed type =', parsed.type);

    if (parsed.type === 'sentences') {
      const lyrics = parsed.sentences.map(sentence => ({
        time: sentence.words[0]?.startTime || 0,
        text: (sentence.words || []).map(word => word.data).join(' ').replace(/\s+/g, ' ').trim()
      }));

      return res.json({ lyrics: lyrics, total: lyrics.length });
    }

    if (parsed.type === 'text') {
      // Return plain text lines as fallback; time=0 for each line
      const lines = parsed.text.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
      const lyrics = lines.map(line => ({ time: 0, text: line }));
      return res.json({ lyrics: lyrics, total: lyrics.length, raw: parsed.text });
    }

    if (parsed.type === 'file') {
      try {
        console.log('🎼 /lyric fetching external LRC file:', parsed.url);
        const r = await fetch(parsed.url);
        if (!r.ok) throw new Error('Failed to fetch LRC file: ' + r.status);
        const text = await r.text();
        const lines = text.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
        const lyrics = lines.map(line => ({ time: 0, text: line }));
        return res.json({ lyrics: lyrics, total: lyrics.length, raw: text, source: parsed.url });
      } catch (e) {
        console.log('⚠️ Failed to fetch external LRC file for', songId, e.message);
        return res.status(502).json({ error: 'Không thể tải file lời từ nguồn ngoài' });
      }
    }
    try {
      console.log('⚠️ /lyric no parsed lyric for', songId, '- raw lyricDetail:', JSON.stringify(lyricDetail).slice(0,20000));
    } catch (e) {
      console.log('⚠️ /lyric no parsed lyric and failed to stringify lyricDetail for', songId);
    }
    return res.status(404).json({ error: 'Không có lời bài hát' });

  } catch (err) {
    console.error("🔥 Lỗi lấy lời bài hát:", err);
    res.status(500).json({ error: "Lỗi server: " + err.message });
  }
});

// API trả lời lời bài hát ở định dạng .lrc (plain text) — phù hợp với client/ESP32 mong đợi
app.get("/lyric.lrc", async (req, res) => {
  const songId = req.query.id;

  if (!songId) {
    return res.status(400).send("Thiếu ID bài hát");
  }

  try {
    console.log("🎼 Lấy lời bài hát (LRC) cho ID:", songId);

    const lyricDetail = await zing.ZingMp3.getLyric(songId);
  const parsed = parseLyricDetail(lyricDetail);
  console.log('🎼 /lyric.lrc parsed type =', parsed.type);

    if (parsed.type === 'sentences') {
      const sentences = parsed.sentences;

      const lines = [];
      // Optional header metadata
      if (parsed.metadata) {
        const meta = parsed.metadata;
        if (meta.title) lines.push(`[ti:${meta.title}]`);
        if (meta.artists) lines.push(`[ar:${meta.artists}]`);
        if (meta.album) lines.push(`[al:${meta.album}]`);
      }

      for (const sentence of sentences) {
        const startMs = sentence.words && sentence.words[0] && sentence.words[0].startTime ? +sentence.words[0].startTime : 0;

        const mm = Math.floor(startMs / 60000).toString().padStart(2, '0');
        const ss = Math.floor((startMs % 60000) / 1000).toString().padStart(2, '0');
        const cs = Math.floor((startMs % 1000) / 10).toString().padStart(2, '0');
        const timestamp = `${mm}:${ss}.${cs}`;

        // Ghép các từ bằng một khoảng trắng và chuẩn hoá khoảng trắng
        const text = ((sentence.words || []).map(w => w.data).join(' ')).replace(/\s+/g, ' ').trim() || '';
        lines.push(`[${timestamp}]${text}`);
      }

      const lrc = lines.join('\n');
      res.set('Content-Type', 'text/plain; charset=utf-8');
      return res.send(lrc);
    }

    if (parsed.type === 'text') {
      // If text already contains LRC-like timestamps, return as-is; otherwise return plain text lines as LRC body
      const text = parsed.text;
      const hasTimestamp = /\[\d{1,2}:\d{2}(?:\.\d{1,2})?\]/.test(text);
      res.set('Content-Type', 'text/plain; charset=utf-8');
      if (hasTimestamp) return res.send(text);

      // No timestamps — return text lines (ESP32 may parse plain LRC without timestamps)
      const lines = text.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
      return res.send(lines.join('\n'));
    }

    if (parsed.type === 'file') {
      try {
        console.log('🎼 /lyric.lrc fetching external LRC file:', parsed.url);
        const r = await fetch(parsed.url);
        if (!r.ok) throw new Error('Failed to fetch LRC file: ' + r.status);
        const text = await r.text();
        res.set('Content-Type', 'text/plain; charset=utf-8');
        return res.send(text);
      } catch (e) {
        console.log('⚠️ Failed to fetch external LRC file for', songId, e.message);
        return res.status(502).send('Không thể tải file lời từ nguồn ngoài');
      }
    }

    try {
      console.log('⚠️ /lyric.lrc no parsed lyric for', songId, '- raw lyricDetail:', JSON.stringify(lyricDetail).slice(0,20000));
    } catch (e) {
      console.log('⚠️ /lyric.lrc no parsed lyric and failed to stringify lyricDetail for', songId);
    }
    return res.status(404).send("Không có lời bài hát");

  } catch (err) {
    console.error("🔥 Lỗi lấy lời bài hát (LRC):", err);
    res.status(500).send("Lỗi server: " + err.message);
  }
});

// Health check endpoint
app.get("/health", (req, res) => {
  res.json({ 
    status: "OK", 
    message: "ZingMP3 API Server for ESP32",
    timestamp: new Date().toISOString()
  });
});

// Endpoint để ESP32 lấy thời gian server (không cần auth)
app.get("/time", (req, res) => {
  const serverTime = Math.floor(Date.now() / 1000);
  console.log(`🕐 Time request - Server timestamp: ${serverTime}`);
  
  res.json({
    timestamp: serverTime,
    iso: new Date().toISOString(),
    message: "Server time for ESP32 synchronization"
  });
});

app.listen(PORT, () => {
  console.log(`✅ ESP32 Music Server đang chạy tại http://localhost:${PORT}`);
  console.log(`📋 Endpoints:`);
  console.log(`   - GET /stream_pcm?song=<tên bài>&artist=<nghệ sĩ> (cho ESP32 - có xác thực)`);
  console.log(`   - GET /stream_pcm_debug?song=<tên bài>&artist=<nghệ sĩ> (test - không xác thực)`);
  console.log(`   - GET /audio?url=<encoded_url> (stream audio)`);
  console.log(`   - GET /lyric?id=<song_id> (lời bài hát)`);
  console.log(`   - GET /time (lấy thời gian server cho ESP32)`);
  console.log(`   - GET /health (kiểm tra trạng thái)`);
  console.log(`🔐 Authentication: Secret key = "${SECRET_KEY}"`);
  console.log(`⏰ Timestamp tolerance: 30 minutes (auto-skip if ESP32 not synced)`);
});

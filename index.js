import express from "express";
import * as zing from "zingmp3-api-full";
import { Readable } from "stream";
import crypto from "crypto";

const app = express();
const PORT = 5005;

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

    // 🎼 Lấy link lời bài hát (nếu có)
    let lyricUrl = "";
    try {
      const lyricDetail = await zing.ZingMp3.getLyric(result.encodeId);
      if (lyricDetail.data && lyricDetail.data.sentences) {
        lyricUrl = `/lyric?id=${result.encodeId}`;
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
    const response = {
      artist: result.artistsNames || artist,
      title: result.title || song,
      audio_url: `/audio?url=${encodeURIComponent(url128)}`,
      lyric_url: "",
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

    const response = await fetch(decodeURIComponent(audioUrl));

    if (!response.ok) throw new Error("Không thể tải nhạc");

    res.setHeader("Content-Type", "audio/mpeg");
    res.setHeader("Cache-Control", "no-transform"); // 🔥 tránh CF nén/ghi đè
    res.setHeader("Connection", "keep-alive");
    res.setHeader("Accept-Ranges", "bytes");

    const nodeStream = Readable.fromWeb(response.body);
    nodeStream.on("error", (err) => {
      console.log("⚠️ Lỗi stream:", err.message);
      res.end();
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
    
    if (!lyricDetail.data || !lyricDetail.data.sentences) {
      return res.status(404).json({ error: "Không có lời bài hát" });
    }

    // Chuyển đổi format lời bài hát cho ESP32
    const lyrics = lyricDetail.data.sentences.map(sentence => ({
      time: sentence.words[0]?.startTime || 0,
      text: sentence.words.map(word => word.data).join('')
    }));

    res.json({
      lyrics: lyrics,
      total: lyrics.length
    });

  } catch (err) {
    console.error("🔥 Lỗi lấy lời bài hát:", err);
    res.status(500).json({ error: "Lỗi server: " + err.message });
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

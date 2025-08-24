# PLAYMAX-
PLAYMAX 
import express from "express";
import bodyParser from "body-parser";
import multer from "multer";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import { Pool } from "pg";
import { SQSClient, SendMessageCommand } from "@aws-sdk/client-sqs";
import { Storage } from "@google-cloud/storage";
import dotenv from "dotenv";
import fsSync from "fs";
import rateLimit from "express-rate-limit";
import cors from "cors";
import axios from "axios";
import speakeasy from "speakeasy";

dotenv.config();

const app = express();
app.use(bodyParser.json());
app.use(cors());

// Environment variables and service clients
const JWT_SECRET = process.env.JWT_SECRET || "supersecret";
const GCS_BUCKET = process.env.GCS_BUCKET || "your-gcs-bucket";
const GOOGLE_PROJECT_ID = process.env.GOOGLE_PROJECT_ID || "your-project-id";
const GOOGLE_KEYFILE = process.env.GOOGLE_KEYFILE || "./gcs-key.json";
const SQS_QUEUE_URL = process.env.SQS_QUEUE_URL;
const AWS_REGION = process.env.AWS_REGION || "us-east-1";
const STANDARD_API_KEY = process.env.STANDARD_API_KEY;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || "postgres://user:pass@localhost:5432/videosdb",
  max: 20,
  idleTimeoutMillis: 30000,
});

const storage = new Storage({
  projectId: GOOGLE_PROJECT_ID,
  keyFilename: GOOGLE_KEYFILE,
});
const bucket = storage.bucket(GCS_BUCKET);

const sqsClient = new SQSClient({ region: AWS_REGION });

if (!fsSync.existsSync("uploads")) fsSync.mkdirSync("uploads");

const upload = multer({
  dest: "uploads/",
  limits: { fileSize: 5000 * 1024 * 1024 }
});

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(limiter);

async function initDb() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        phone_number VARCHAR(20) UNIQUE,
        otp_secret VARCHAR(255),
        is_verified BOOLEAN DEFAULT FALSE
      );
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS videos (
        id SERIAL PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        description TEXT,
        gcs_path VARCHAR(255) NOT NULL,
        thumbnail_path VARCHAR(255),
        transcoded_paths JSONB,
        user_id INTEGER REFERENCES users(id),
        status VARCHAR(20) DEFAULT 'uploaded',
        upload_date TIMESTAMP DEFAULT NOW(),
        views INTEGER DEFAULT 0,
        search_vector TSVECTOR,
        retry_count INTEGER DEFAULT 0,
        privacy_status VARCHAR(20) DEFAULT 'public',
        tags TEXT[],
        category VARCHAR(50)
      );
    `);
    await client.query(`CREATE INDEX IF NOT EXISTS search_idx ON videos USING GIN (search_vector);`);
    
    // Create new tables for comments, likes, and playlists
    await client.query(`
      CREATE TABLE IF NOT EXISTS comments (
        id SERIAL PRIMARY KEY,
        video_id INTEGER REFERENCES videos(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        comment_text TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS video_likes (
        id SERIAL PRIMARY KEY,
        video_id INTEGER REFERENCES videos(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        is_like BOOLEAN NOT NULL,
        UNIQUE(video_id, user_id)
      );
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS playlists (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        title VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS playlist_videos (
        playlist_id INTEGER REFERENCES playlists(id) ON DELETE CASCADE,
        video_id INTEGER REFERENCES videos(id) ON DELETE CASCADE,
        added_at TIMESTAMP DEFAULT NOW(),
        PRIMARY KEY (playlist_id, video_id)
      );
    `);
  } catch (err) {
    console.error("Database initialization failed:", err);
  } finally {
    client.release();
  }
}
initDb();

function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res.status(401).json({ error: "Authorization token missing." });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: "Invalid token." });
  }
}

async function createSignedUrl(gcsPath) {
  const [url] = await bucket.file(gcsPath).getSignedUrl({
    action: "read",
    expires: Date.now() + 3600 * 1000
  });
  return url;
}

// Function to send OTP via Standard.com API
async function sendOtpWithStandard(phoneNumber, otp) {
  if (!STANDARD_API_KEY) {
    console.error("STANDARD_API_KEY is not set. Cannot send OTP.");
    return false;
  }
  
  try {
    const response = await axios.post(
      "https://api.standard.com/v1/otp/send",
      {
        phone_number: phoneNumber,
        otp_code: otp,
        message: `आपका OTP है: ${otp}. यह 5 मिनट के लिए वैध है।`, 
      },
      {
        headers: {
          Authorization: `Bearer ${STANDARD_API_KEY}`,
          "Content-Type": "application/json",
        },
      }
    );
    console.log("OTP sent via Standard.com:", response.data);
    return true;
  } catch (error) {
    console.error("Error sending OTP via Standard.com:", error.response?.data || error.message);
    return false;
  }
}

app.post("/api/auth/register", async (req, res) => {
  const { username, password, phone_number } = req.body;
  if (!username || !password || !phone_number) {
    return res.status(400).json({ error: "Username, password, and phone number are required." });
  }

  try {
    const password_hash = await bcrypt.hash(password, 10);
    const otp_secret = speakeasy.generateSecret().base32;

    const { rows } = await pool.query(
      `INSERT INTO users(username, password_hash, phone_number, otp_secret) VALUES($1, $2, $3, $4) RETURNING id, username`,
      [username, password_hash, phone_number, otp_secret]
    );

    const otp = speakeasy.totp({
      secret: otp_secret,
      encoding: 'base32',
      step: 60 * 5
    });

    const otpSent = await sendOtpWithStandard(phone_number, otp);
    if (!otpSent) {
      return res.status(500).json({ error: "User registered, but failed to send OTP. Please try requesting OTP again." });
    }

    res.status(201).json({ message: "User registered successfully. An OTP has been sent to your phone number." });
  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({ error: "Username or phone number already exists." });
    }
    console.error("Registration failed:", err);
    res.status(500).json({ error: "Registration failed." });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const { rows } = await pool.query("SELECT id, password_hash, is_verified FROM users WHERE username = $1", [username]);
    if (rows.length === 0) {
      return res.status(401).json({ error: "Invalid username or password." });
    }

    const user = rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).json({ error: "Invalid username or password." });
    }

    if (user.is_verified) {
      const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "1h" });
      return res.json({ message: "Login successful.", token, user: { id: user.id, username } });
    } else {
      return res.status(200).json({ message: "Account not verified. Please verify your phone number.", requires_otp_verification: true });
    }
  } catch (err) {
    console.error("Login failed:", err);
    res.status(500).json({ error: "Login failed." });
  }
});

app.post("/api/auth/request-otp", async (req, res) => {
    const { username } = req.body;
    try {
        const { rows } = await pool.query("SELECT id, username, phone_number, otp_secret FROM users WHERE username = $1", [username]);
        if (rows.length === 0) {
            return res.status(404).json({ error: "User not found." });
        }
        const user = rows[0];

        const otp = speakeasy.totp({
          secret: user.otp_secret,
          encoding: 'base32',
          step: 60 * 5
        });

        const otpSent = await sendOtpWithStandard(user.phone_number, otp);
        if (!otpSent) {
          return res.status(500).json({ error: "Failed to send OTP. Please try again." });
        }

        res.json({ message: "A new OTP has been sent to your phone number." });
    } catch (err) {
        console.error("Failed to request OTP:", err);
        res.status(500).json({ error: "Failed to request OTP." });
    }
});

app.post("/api/auth/verify-otp", async (req, res) => {
  const { username, otp } = req.body;
  if (!username || !otp) {
    return res.status(400).json({ error: "Username and OTP are required." });
  }

  try {
    const { rows } = await pool.query("SELECT id, otp_secret, is_verified FROM users WHERE username = $1", [username]);
    if (rows.length === 0) {
      return res.status(401).json({ error: "Invalid username or OTP." });
    }

    const user = rows[0];

    const is_valid = speakeasy.totp.verify({
      secret: user.otp_secret,
      encoding: 'base32',
      token: otp,
      step: 60 * 5,
      window: 1
    });

    if (is_valid) {
      if (!user.is_verified) {
        await pool.query("UPDATE users SET is_verified = TRUE WHERE id = $1", [user.id]);
      }
      const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "1h" });
      res.json({ message: "Phone number verified successfully.", token, user: { id: user.id, username } });
    } else {
      res.status(401).json({ error: "Invalid OTP. Please try again." });
    }
  } catch (err) {
    console.error("OTP verification failed:", err);
    res.status(500).json({ error: "OTP verification failed." });
  }
});

app.post("/api/videos/upload", auth, upload.single("video"), async (req, res) => {
  const file = req.file;
  const { title, description, privacy_status = 'public', tags = [], category = 'Other' } = req.body;
  if (!file || !title) {
    if (file) {
      await fsSync.promises.unlink(file.path);
    }
    return res.status(400).json({ error: "Missing video file or title." });
  }
  if (!['public', 'private', 'only_me'].includes(privacy_status)) {
    return res.status(400).json({ error: "Invalid privacy status." });
  }

  const tagArray = Array.isArray(tags) ? tags : [tags];

  try {
    const gcsPath = `videos/original/${file.filename}`;
    await bucket.upload(file.path, {
      destination: gcsPath,
      metadata: { contentType: "video/mp4" }
    });

    const searchVector = `to_tsvector('english', $1 || ' ' || $2 || ' ' || array_to_string($3, ' '))`;
    const { rows } = await pool.query(
      `INSERT INTO videos(title, description, gcs_path, user_id, search_vector, privacy_status, tags, category) 
       VALUES($1, $2, $3, $4, ${searchVector}, $5, $6, $7) RETURNING *`,
      [title, description, gcsPath, req.user.id, privacy_status, tagArray, category]
    );
    const video = rows[0];

    const messageBody = JSON.stringify({
      videoId: video.id,
      gcsPath: gcsPath,
    });

    const sendParams = {
      QueueUrl: SQS_QUEUE_URL,
      MessageBody: messageBody,
    };

    await sqsClient.send(new SendMessageCommand(sendParams));

    res.status(202).json({
      message: "Video upload successful. Your video is being processed.",
      video: { id: video.id, title: video.title, user_id: video.user.id, status: video.status }
    });
  } catch (err) {
    console.error("Upload failed:", err);
    res.status(500).json({ error: "Upload failed.", details: err.message });
  } finally {
    if (file) {
      await fsSync.promises.unlink(file.path);
    }
  }
});

app.get("/api/videos/:id", async (req, res) => {
  try {
    const videoId = req.params.id;
    const token = req.headers.authorization?.split(" ")[1];
    let userId = null;
    if (token) {
      try {
        const decoded = jwt.verify(token, JWT_SECRET);
        userId = decoded.id;
      } catch (err) {
        // Invalid token, continue without a user ID
      }
    }

    const { rows } = await pool.query(
      "SELECT v.*, u.username FROM videos v JOIN users u ON v.user_id = u.id WHERE v.id = $1",
      [videoId]
    );
    if (rows.length === 0) {
      return res.status(404).json({ error: "Video not found." });
    }

    const video = rows[0];

    if (video.status !== 'processed') {
      return res.status(200).json({
        message: `Video is currently ${video.status}. Please check back later.`,
        status: video.status
      });
    }

    if (video.privacy_status === 'private' || video.privacy_status === 'only_me') {
      if (!userId || video.user_id !== userId) {
        return res.status(403).json({ error: "Access Denied. This video is private." });
      }
    }

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("UPDATE videos SET views = views + 1 WHERE id = $1", [videoId]);
      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK");
      console.error("Failed to update video views:", err);
    } finally {
      client.release();
    }

    const transcodedUrls = {};
    let thumbUrl = video.thumbnail_path;

    if (video.privacy_status === 'private' || video.privacy_status === 'only_me') {
      for (const [quality, gcsPath] of Object.entries(video.transcoded_paths)) {
        transcodedUrls[quality] = await createSignedUrl(gcsPath);
      }
      if (thumbUrl) {
        thumbUrl = await createSignedUrl(thumbUrl);
      }
    } else {
      Object.assign(transcodedUrls, video.transcoded_paths);
    }
    
    const responseVideo = {
      id: video.id,
      title: video.title,
      description: video.description,
      user_id: video.user_id,
      username: video.username,
      status: video.status,
      privacy_status: video.privacy_status,
      upload_date: video.upload_date,
      views: video.views + 1,
      transcodedUrls,
      thumbUrl
    };

    res.json(responseVideo);
  } catch (err) {
    console.error("Error fetching video:", err);
    res.status(500).json({ error: "Error fetching video.", details: err.message });
  }
});

app.post("/api/videos/:id/comment", auth, async (req, res) => {
  const { comment_text } = req.body;
  const videoId = req.params.id;
  if (!comment_text) {
    return res.status(400).json({ error: "Comment text is required." });
  }

  try {
    await pool.query(
      `INSERT INTO comments (video_id, user_id, comment_text) VALUES ($1, $2, $3)`,
      [videoId, req.user.id, comment_text]
    );
    res.status(201).json({ message: "Comment added successfully." });
  } catch (err) {
    console.error("Failed to add comment:", err);
    res.status(500).json({ error: "Failed to add comment." });
  }
});

app.get("/api/videos/:id/comments", async (req, res) => {
  const videoId = req.params.id;
  try {
    const { rows } = await pool.query(
      `SELECT c.comment_text, c.created_at, u.username
       FROM comments c
       JOIN users u ON c.user_id = u.id
       WHERE c.video_id = $1
       ORDER BY c.created_at DESC`,
      [videoId]
    );
    res.json(rows);
  } catch (err) {
    console.error("Failed to fetch comments:", err);
    res.status(500).json({ error: "Failed to fetch comments." });
  }
});

app.post("/api/videos/:id/like", auth, async (req, res) => {
  const videoId = req.params.id;
  try {
    await pool.query(
      `INSERT INTO video_likes (video_id, user_id, is_like) VALUES ($1, $2, TRUE)
       ON CONFLICT (video_id, user_id) DO UPDATE SET is_like = TRUE`,
      [videoId, req.user.id]
    );
    res.json({ message: "Video liked successfully." });
  } catch (err) {
    console.error("Failed to like video:", err);
    res.status(500).json({ error: "Failed to like video." });
  }
});

app.post("/api/videos/:id/dislike", auth, async (req, res) => {
  const videoId = req.params.id;
  try {
    await pool.query(
      `INSERT INTO video_likes (video_id, user_id, is_like) VALUES ($1, $2, FALSE)
       ON CONFLICT (video_id, user_id) DO UPDATE SET is_like = FALSE`,
      [videoId, req.user.id]
    );
    res.json({ message: "Video disliked successfully." });
  } catch (err) {
    console.error("Failed to dislike video:", err);
    res.status(500).json({ error: "Failed to dislike video." });
  }
});

app.post("/api/playlists", auth, async (req, res) => {
  const { title } = req.body;
  if (!title) {
    return res.status(400).json({ error: "Playlist title is required." });
  }
  try {
    const { rows } = await pool.query(
      `INSERT INTO playlists (user_id, title) VALUES ($1, $2) RETURNING id, title`,
      [req.user.id, title]
    );
    res.status(201).json({ message: "Playlist created.", playlist: rows[0] });
  } catch (err) {
    console.error("Failed to create playlist:", err);
    res.status(500).json({ error: "Failed to create playlist." });
  }
});

app.post("/api/playlists/:playlistId/add/:videoId", auth, async (req, res) => {
  const { playlistId, videoId } = req.params;
  try {
    const { rows } = await pool.query(
      `SELECT user_id FROM playlists WHERE id = $1`,
      [playlistId]
    );
    if (rows.length === 0 || rows[0].user_id !== req.user.id) {
      return res.status(403).json({ error: "You can only add videos to your own playlists." });
    }
    await pool.query(
      `INSERT INTO playlist_videos (playlist_id, video_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
      [playlistId, videoId]
    );
    res.json({ message: "Video added to playlist." });
  } catch (err) {
    console.error("Failed to add video to playlist:", err);
    res.status(500).json({ error: "Failed to add video to playlist." });
  }
});

if (process.env.NODE_ENV !== "test") {
  app.listen(3000, () => console.log("Server running on http://localhost:3000"));
}

export default app;



import { SQSClient, ReceiveMessageCommand, DeleteMessageCommand } from "@aws-sdk/client-sqs";
import { Storage } from "@google-cloud/storage";
import { Pool } from "pg";
import ffmpeg from "fluent-ffmpeg";
import fs from "fs/promises";
import fsSync from "fs";
import dotenv from "dotenv";

dotenv.config();

const GCS_BUCKET = process.env.GCS_BUCKET || "your-gcs-bucket";
const GOOGLE_PROJECT_ID = process.env.GOOGLE_PROJECT_ID || "your-project-id";
const GOOGLE_KEYFILE = process.env.GOOGLE_KEYFILE || "./gcs-key.json";
const SQS_QUEUE_URL = process.env.SQS_QUEUE_URL;
const AWS_REGION = process.env.AWS_REGION || "us-east-1";
const WATERMARK_PATH = process.env.WATERMARK_PATH || "./logo.png";

fs.mkdir("transcoded", { recursive: true }).catch(err => console.error("Failed to create transcoded directory:", err));
fs.mkdir("uploads", { recursive: true }).catch(err => console.error("Failed to create uploads directory:", err));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || "postgres://user:pass@localhost:5432/videosdb",
});

const storage = new Storage({
  projectId: GOOGLE_PROJECT_ID,
  keyFilename: GOOGLE_KEYFILE,
});
const bucket = storage.bucket(GCS_BUCKET);

const sqsClient = new SQSClient({ region: AWS_REGION });

const MAX_RETRIES = 3;

async function uploadFile(sourcePath, destinationPath, mimetype) {
  await bucket.upload(sourcePath, {
    destination: destinationPath,
    metadata: { contentType: mimetype }
  });
  return destinationPath;
}

async function processVideo(videoId, gcsPath, retryCount) {
  console.log(`Processing video ${videoId} (Attempt ${retryCount + 1}/${MAX_RETRIES})`);
  const localVideoPath = `/tmp/${videoId}_original.mp4`;
  const transcodedPaths = {};
  const qualities = {
    '1080p': { resolution: '1920x1080', bitrate: '5M' },
    '720p': { resolution: '1280x720', bitrate: '2.5M' },
    '480p': { resolution: '854x480', bitrate: '1M' },
  };

  const client = await pool.connect();
  try {
    await client.query(`UPDATE videos SET status = 'processing' WHERE id = $1`, [videoId]);
    const { rows } = await client.query("SELECT privacy_status FROM videos WHERE id = $1", [videoId]);
    const privacyStatus = rows[0]?.privacy_status || 'public';

    await bucket.file(gcsPath).download({ destination: localVideoPath });

    const thumbPath = `/tmp/${videoId}_thumb.jpg`;
    await new Promise((resolve, reject) => {
      ffmpeg(localVideoPath)
        .screenshots({ count: 1, folder: "/tmp", filename: `${videoId}_thumb.jpg`, size: "320x240" })
        .on("end", resolve)
        .on("error", (err) => {
          console.error(`Error generating thumbnail for ${videoId}:`, err);
          reject(err);
        });
    });

    const gcsThumbPath = `thumbnails/${videoId}_thumb.jpg`;
    await uploadFile(thumbPath, gcsThumbPath, "image/jpeg");
    if (privacyStatus === 'public') {
      await bucket.file(gcsThumbPath).makePublic();
    }
    await fs.unlink(thumbPath);

    const outputDir = `/tmp/${videoId}_hls`;
    await fs.mkdir(outputDir, { recursive: true });

    const hlsPromise = new Promise((resolve, reject) => {
      const command = ffmpeg(localVideoPath);
      command.input(WATERMARK_PATH).complexFilter(
        `overlay=W-w-10:H-h-10`
      );

      command
        .outputOptions([
          '-c:v libx264',
          '-c:a aac',
          '-hls_time 10',
          '-hls_list_size 0',
          '-start_number 1',
          '-f hls'
        ])
        .output(`${outputDir}/video.m3u8`)
        .on('end', () => resolve())
        .on('error', (err) => reject(err));
      
      command.run();
    });

    await hlsPromise;

    const hlsFiles = await fs.readdir(outputDir);
    for (const file of hlsFiles) {
      const localFilePath = `${outputDir}/${file}`;
      const gcsFilePath = `videos/${videoId}/hls/${file}`;
      await uploadFile(localFilePath, gcsFilePath, file.endsWith('.ts') ? 'video/mp2t' : 'application/x-mpegURL');
      if (privacyStatus === 'public') {
        await bucket.file(gcsFilePath).makePublic();
      }
    }
    transcodedPaths.hls = `videos/${videoId}/hls/video.m3u8`;

    await client.query(
      `UPDATE videos SET transcoded_paths = $1, thumbnail_path = $2, status = 'processed', retry_count = $3 WHERE id = $4`,
      [JSON.stringify(transcodedPaths), gcsThumbPath, 0, videoId]
    );

    console.log(`Transcoding for video ${videoId} completed successfully.`);
    return true;
  } catch (err) {
    console.error(`Transcoding for video ${videoId} failed on attempt ${retryCount + 1}:`, err);
    if (retryCount < MAX_RETRIES - 1) {
      await client.query(`UPDATE videos SET status = 'retrying', retry_count = $1 WHERE id = $2`, [retryCount + 1, videoId]);
      console.log(`Retrying video ${videoId} later...`);
    } else {
      await client.query(`UPDATE videos SET status = 'failed' WHERE id = $1`, [videoId]);
      console.log(`Video ${videoId} failed after ${MAX_RETRIES} attempts.`);
    }
    return false;
  } finally {
    if (fsSync.existsSync(localVideoPath)) await fs.unlink(localVideoPath).catch(console.error);
    const outputDir = `/tmp/${videoId}_hls`;
    if (fsSync.existsSync(outputDir)) await fs.rm(outputDir, { recursive: true, force: true }).catch(console.error);
    client.release();
  }
}

async function pollQueue() {
  while (true) {
    try {
      const receiveParams = {
        QueueUrl: SQS_QUEUE_URL,
        MaxNumberOfMessages: 1,
        WaitTimeSeconds: 20,
      };

      const command = new ReceiveMessageCommand(receiveParams);
      const data = await sqsClient.send(command);

      if (data.Messages && data.Messages.length > 0) {
        await Promise.all(data.Messages.map(async (message) => {
          try {
            const body = JSON.parse(message.Body);
            const success = await processVideo(body.videoId, body.gcsPath, body.retryCount || 0);
            if (success) {
              const deleteParams = {
                QueueUrl: SQS_QUEUE_URL,
                ReceiptHandle: message.ReceiptHandle,
              };
              await sqsClient.send(new DeleteMessageCommand(deleteParams));
            } else {
              console.log(`Message not deleted, will be retried: ${message.ReceiptHandle}`);
            }
          } catch (err) {
            console.error("Error processing a message:", err);
          }
        }));
      }
    } catch (err) {
      console.error("Error receiving messages from SQS:", err);
    }
  }
}

if (process.env.NODE_ENV !== "test") {
  pollQueue();
  console.log("Video processing worker started.");
}




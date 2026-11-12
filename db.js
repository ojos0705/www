// db.js
const mongoose = require('mongoose');

let cachedDb = global.mongoose;

if (!cachedDb) {
  cachedDb = global.mongoose = { conn: null, promise: null };
}

async function connectDB() {
  if (cachedDb.conn) {
    return cachedDb.conn;
  }

  if (!cachedDb.promise) {
    const opts = {
      bufferCommands: false, // Nonaktifkan buffering Mongoose agar langsung error jika gagal alih-alih timeout
      serverSelectionTimeoutMS: 5000, // Timeout lebih cepat (5 detik) untuk mendeteksi masalah jaringan
    };

    cachedDb.promise = mongoose.connect(process.env.MONGO_URI, opts).then((mongoose) => {
      return mongoose;
    });
  }

  try {
    cachedDb.conn = await cachedDb.promise;
  } catch (e) {
    cachedDb.promise = null;
    throw e;
  }

  return cachedDb.conn;
}

module.exports = connectDB;
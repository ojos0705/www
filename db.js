// db.js
const mongoose = require('mongoose');

let cachedDb = global.mongoose;

if (!cachedDb) {
  cachedDb = global.mongoose = { conn: null, promise: null };
}

async function connectDB() {
  if (!process.env.MONGO_URI) {
    return null;
  }

  if (cachedDb.conn) {
    return cachedDb.conn;
  }

  if (!cachedDb.promise) {
    const opts = {
      bufferCommands: false,
      serverSelectionTimeoutMS: 5000,
    };

    cachedDb.promise = mongoose.connect(process.env.MONGO_URI, opts).then((mongooseInstance) => {
      return mongooseInstance;
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
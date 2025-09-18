const mongoose = require('mongoose');

const appSchema = new mongoose.Schema({
  name: { type: String, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  port: { type: Number, required: true },
  subdomain: { type: String, required: true },
  status: { type: String, default: 'created' }, // created, building, running, failed
  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model('App', appSchema);

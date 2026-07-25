require('dotenv').config();
const express = require('express');
const cors = require('cors');
const pool = require('./db');

const app = express();
app.use(cors());
app.use(express.json());

const authRoutes = require('./auth');
app.use('/auth', authRoutes);

const servicesRoutes = require('./services');
app.use('/services', servicesRoutes);

const messagesRoutes = require('./messages');
app.use('/messages', messagesRoutes);

const adminRoutes = require('./admin');
app.use('/admin', adminRoutes);

const { router: notificationsRoutes } = require('./notifications');
app.use('/notifications', notificationsRoutes);

app.get('/', (req, res) => {
  res.send('ZedEvents server is running.');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

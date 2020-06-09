const express = require('express');
const db = require('./config/db');
const cors = require('cors');

const app = express();

db();

app.use(cors());
app.use( express.json({ extended: true }));

const port = process.env.PORT || 5000;

app.use('/api/users', require('./routes/user'));
app.use('/api/auth', require('./routes/auth'));

app.listen(port, '0.0.0.0', () => {
    console.log(`Express server listening ${port}`);
});

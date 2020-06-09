const mongoose = require('mongoose');
require('dotenv').config({ path: '.env' });

const db = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI, {
      useCreateIndex: true,
      useNewUrlParser: true,
      useUnifiedTopology: true,
      useFindAndModify: false,
    });
    console.log('DB started');
  } catch (error) {
    console.log('Something was wrong');
    console.log(error);
    process.exit(1);
  }
};

module.exports = db;

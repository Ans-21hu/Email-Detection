const mongoose = require('mongoose');
const User = require('./models/User');
require('dotenv').config();

const uri = process.env.MONGODB_URI;

if (!uri) {
    console.error("❌ MONGODB_URI is missing in .env file");
    process.exit(1);
}

console.log("🔄 Connecting to MongoDB...");

mongoose.connect(uri)
    .then(async () => {
        console.log("✅ Connected successfully!");

        console.log("🔍 Fetching all users...");
        const users = await User.find({});

        if (users.length === 0) {
            console.log("⚠️ No users found in the database.");
        } else {
            console.log(`✅ Found ${users.length} users:`);
            users.forEach((user, index) => {
                console.log(`\n--- User ${index + 1} ---`);
                console.log(`ID: ${user._id}`);
                console.log(`Username: ${user.username}`);
                console.log(`Email: ${user.email}`);
                console.log(`Name: ${user.firstName} ${user.lastName}`);
                console.log(`Created At: ${user.createdAt}`);
            });
        }

        mongoose.connection.close();
    })
    .catch(err => {
        console.error("❌ Connection error:", err);
        process.exit(1);
    });

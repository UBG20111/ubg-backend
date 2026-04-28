const fs = require("fs");
const path = require("path");
const { Pool } = require("pg");

const databaseUrl = process.env.DATABASE_URL;

if (!databaseUrl) {
  console.error("DATABASE_URL is missing. Add it in Render Environment Variables.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: databaseUrl,
  ssl: {
    rejectUnauthorized: false
  }
});

async function migrate() {
  try {
    const schemaPath = path.join(__dirname, "schema.sql");
    const sql = fs.readFileSync(schemaPath, "utf8");

    await pool.query(sql);

    console.log("UBG database migration completed successfully.");
  } catch (error) {
    console.error("UBG database migration failed:");
    console.error(error.message);
    process.exit(1);
  } finally {
    await pool.end();
  }
}

migrate();

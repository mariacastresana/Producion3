import crypto from "crypto";
import dotenv from "dotenv";
import sql from "mssql";

dotenv.config();

async function migratePasswords() {
  try {
    console.log("Starting password migration with direct connection...");
    
    // Create config directly in migration script
    const azureConfig = {
      server: process.env.AZURE_SQL_SERVER,
      port: parseInt(process.env.AZURE_SQL_PORT, 10),
      database: process.env.AZURE_SQL_DATABASE,
      user: process.env.AZURE_SQL_USER,
      password: process.env.AZURE_SQL_PASSWORD,
      options: {
        encrypt: true,
        trustServerCertificate: true,
      },
    };

    console.log("Config validation:");
    console.log("Server:", typeof azureConfig.server, azureConfig.server?.length);
    console.log("Database:", typeof azureConfig.database, azureConfig.database?.length);
    console.log("User:", typeof azureConfig.user, azureConfig.user?.length);
    console.log("Port:", typeof azureConfig.port, azureConfig.port);

    // Create new connection pool
    const pool = new sql.ConnectionPool(azureConfig);
    await pool.connect();
    console.log("Connected to Azure SQL Server");

    // Get all users with unhashed passwords
    const users = await pool
      .request()
      .query("SELECT UserID, password FROM dbo.Users");

    let migratedCount = 0;

    for (const user of users.recordset) {
      // Check if password is already hashed (has 10-char salt + 64-char hash = 74+ chars)
      if (user.password.length < 74) {
        console.log(`Migrating user ${user.UserID}`);

        // Hash the existing plain text password
        const salt = crypto.randomBytes(5).toString("hex");
        const preHash = salt + user.password;
        const hashing = crypto.createHash("sha256");
        const hash = hashing.update(preHash).digest("hex");
        const hashedPassword = salt + hash;

        // Update the user's password
        await pool
          .request()
          .input("userId", sql.Int, user.UserID)
          .input("hashedPassword", sql.VarChar, hashedPassword)
          .query(
            "UPDATE dbo.Users SET password = @hashedPassword WHERE UserID = @userId"
          );
        
        migratedCount++;
      } else {
        console.log(`User ${user.UserID} already has hashed password, skipping...`);
      }
    }

    console.log(`Password migration completed! Migrated ${migratedCount} users.`);
    
    // Close the connection
    await pool.close();
    process.exit(0);
  } catch (error) {
    console.error("Migration error:", error);
    process.exit(1);
  }
}

migratePasswords();
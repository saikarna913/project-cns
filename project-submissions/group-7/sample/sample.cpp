#include <iostream>
#include <sqlite3.h>
#include <string>

int executeSQL(sqlite3* DB, const std::string& sql, char** messageError) {
    return sqlite3_exec(DB, sql.c_str(), NULL, 0, messageError);
}

bool transferMoney(sqlite3* DB, const std::string& fromAccount, const std::string& toAccount, const std::string& amountStr) {
    char* messageError;

    // Begin transaction
    std::string beginTransaction = "BEGIN TRANSACTION;";
    if (executeSQL(DB, beginTransaction, &messageError) != SQLITE_OK) {
        std::cerr << "Transaction start error: " << messageError << std::endl;
        sqlite3_free(messageError);
        return false;
    }

    // Create SQL commands for updating the accounts
    std::string withdrawSQL = "UPDATE accounts SET balance = balance - " + amountStr + " WHERE account_id = '" + fromAccount + "';";
    std::string depositSQL = "UPDATE accounts SET balance = balance + " + amountStr + " WHERE account_id = '" + toAccount + "';";

    // Execute withdraw command
    if (executeSQL(DB, withdrawSQL, &messageError) != SQLITE_OK) {
        std::cerr << "Withdraw error: " << messageError << std::endl;
        sqlite3_free(messageError);
        // Rollback transaction
        std::string rollbackTransaction = "ROLLBACK;";
        executeSQL(DB, rollbackTransaction, nullptr);
        return false;
    }

    // Execute deposit command
    if (executeSQL(DB, depositSQL, &messageError) != SQLITE_OK) {
        std::cerr << "Deposit error: " << messageError << std::endl;
        sqlite3_free(messageError);
        // Rollback transaction
        std::string rollbackTransaction = "ROLLBACK;";
        executeSQL(DB, rollbackTransaction, nullptr);
        return false;
    }

    // Commit transaction
    std::string commitTransaction = "COMMIT;";
    if (executeSQL(DB, commitTransaction, &messageError) != SQLITE_OK) {
        std::cerr << "Transaction commit error: " << messageError << std::endl;
        sqlite3_free(messageError);
        return false;
    }

    std::cout << "Transfer successful!" << std::endl;
    return true;
}

void createAccountsTable(sqlite3* DB) {
    char* messageError;
    std::string createTableSQL = "CREATE TABLE IF NOT EXISTS accounts ("
                                  "account_id TEXT PRIMARY KEY NOT NULL, "
                                  "balance REAL NOT NULL);";
    
    if (executeSQL(DB, createTableSQL, &messageError) != SQLITE_OK) {
        std::cerr << "Table creation error: " << messageError << std::endl;
        sqlite3_free(messageError);
    }
}

void insertSampleAccounts(sqlite3* DB) {
    char* messageError;
    std::string insertSQL1 = "INSERT INTO accounts (account_id, balance) VALUES ('12345', 500.00);";
    std::string insertSQL2 = "INSERT INTO accounts (account_id, balance) VALUES ('67890', 300.00);";

    executeSQL(DB, insertSQL1, &messageError);
    if (messageError) {
        std::cerr << "Insert error for account 12345: " << messageError << std::endl;
        sqlite3_free(messageError);
    }

    executeSQL(DB, insertSQL2, &messageError);
    if (messageError) {
        std::cerr << "Insert error for account 67890: " << messageError << std::endl;
        sqlite3_free(messageError);
    }
}

int main() {
    sqlite3* DB;
    int exit = sqlite3_open("example.db", &DB);
    
    if (exit) {
        std::cerr << "Error open DB: " << sqlite3_errmsg(DB) << std::endl;
        return -1;
    } 

    // Create accounts table
    createAccountsTable(DB);

    // Insert sample accounts
    insertSampleAccounts(DB);

    // Example account IDs and amount to transfer
    std::string fromAccount = "12345";
    std::string toAccount = "67890";
    std::string amount = "100.00"; // Transfer amount as a string

    // Perform money transfer
    if (!transferMoney(DB, fromAccount, toAccount, amount)) {
        std::cerr << "Money transfer failed!" << std::endl;
    }

    sqlite3_close(DB);
    return 0;
}
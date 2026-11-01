#pragma once

#include <cstdint>
#include <memory>

struct sqlite3;
struct sqlite3_stmt;

namespace Cipherazzi::Sqlite
{
struct DatabaseCloser { void operator()(sqlite3* value) const; };
struct StatementCloser { void operator()(sqlite3_stmt* value) const; };
using Database = std::unique_ptr<sqlite3, DatabaseCloser>;
using Statement = std::unique_ptr<sqlite3_stmt, StatementCloser>;

// Each helper throws the connection's SQLite error message when the statement fails.
Statement prepare(sqlite3* database, const char* sql);
void execute(sqlite3* database, const char* sql);
int64_t scalar(sqlite3* database, const char* sql);
}

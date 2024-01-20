import sqlite3

class Database:
    def __init__(self, database_name):
        conn = sqlite3.connect(database_name)
        self.drop_table(database_name)
        conn.execute("create table IF NOT EXISTS storage (resource_id, level, file, iv, hash, signature)")

        conn.close()

    def insert_query(self, database_name, resource_id, level, document, iv, hash_value, signature):
        conn = sqlite3.connect(database_name)
        cursor = conn.cursor()
        cursor.execute("insert into storage (resource_id, level, file, iv, hash, signature) values (?,?,?,?,?,?)", (resource_id, level, document, iv, hash_value, signature))
        conn.commit()

        conn.close()
    
    def level_query(self, database_name, resource_id):
        conn = sqlite3.connect(database_name)
        cur = conn.cursor()
        cur.execute("select * from storage where resource_id=:id", {"id": str(resource_id)})
        rows = cur.fetchall()
        
        conn.close()

        return rows

    def drop_table(self, database_name):
        conn = sqlite3.connect(database_name)
        conn.execute("DROP TABLE IF EXISTS storage")
        conn.close()


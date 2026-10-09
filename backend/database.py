import os
import re
import logging
import psycopg2
from psycopg2 import pool, extras
from config import Config

logger = logging.getLogger(__name__)

db_pool = None

def _clean_postgres_query(query: str, params=()) -> str:
    # 1. Convert MySQL DATE_FORMAT to PostgreSQL TO_CHAR
    q = re.sub(r"DATE_FORMAT\s*\(\s*(\w+)\s*,\s*'%H:00'\s*\)", r"TO_CHAR(\1, 'HH24:00')", query, flags=re.IGNORECASE)
    q = re.sub(r"DATE_FORMAT\s*\(\s*(\w+)\s*,\s*'%Y-%m-%d'\s*\)", r"TO_CHAR(\1, 'YYYY-MM-DD')", q, flags=re.IGNORECASE)
    
    # 2. Escape literal % in psycopg2 to prevent tuple index out of range
    if not params:
        # When there are no parameters, all single % are literal
        q = re.sub(r"(?<!%)%(?!%)", "%%", q)
    else:
        # When parameters are supplied, escape % that are not %s placeholders
        q = re.sub(r"(?<!%)%(?!s|%)", "%%", q)
        
    return q

def _try_create_pool(host):
    timeout_sec = int(os.getenv('POSTGRES_TIMEOUT', 10))
    kwargs = {
        'minconn': 1,
        'maxconn': 10 if os.getenv('VERCEL') else 20,
        'host': host,
        'port': Config.DB_PORT,
        'user': Config.DB_USER,
        'password': Config.DB_PASSWORD,
        'dbname': Config.DB_NAME,
        'connect_timeout': timeout_sec
    }
    if Config.POSTGRES_SSLMODE:
        kwargs['sslmode'] = Config.POSTGRES_SSLMODE
    return psycopg2.pool.ThreadedConnectionPool(**kwargs)

def init_postgres_tables():
    conn = get_db_connection()
    if not conn:
        return False
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        schema_path = os.path.join(base_dir, 'database', 'complete_postgres_schema.sql')
        seed_path = os.path.join(base_dir, 'database', 'postgres_seed.sql')

        with conn.cursor() as cur:
            if os.path.exists(schema_path):
                with open(schema_path, 'r', encoding='utf-8') as f:
                    schema_sql = f.read()
                cur.execute(schema_sql)
            if os.path.exists(seed_path):
                with open(seed_path, 'r', encoding='utf-8') as f:
                    seed_sql = f.read()
                cur.execute(seed_sql)
            cur.execute("""
                UPDATE users 
                SET password_hash = 'scrypt:32768:8:1$BzF6ep40u2fQMmEU$aaa34192466fb8c02bf8509a385988f983cf8ac0eb0c6500771fef8ae15b3b2ba4d7a4e6ec7f6a55d7e540cef5586f5facfac3bdf6796b14de121b65c1e0373f'
                WHERE email = 'admin@netshield.ai';
                UPDATE users 
                SET password_hash = 'scrypt:32768:8:1$piLoX0a4POvwDDkm$82df5c8fcb0086e6c0ba83e800b5384108c5415787b2416825f4548a39883f9ed6f9763d1d4bd6448641c6472aa100d5e01bd3f0a8121c6b79093bfd3cf5676f'
                WHERE email = 'analyst@netshield.ai';
            """)
        conn.commit()
        logger.info("PostgreSQL schema and baseline seed verification complete.")
        return True
    except Exception as e:
        if conn:
            try:
                conn.rollback()
            except Exception:
                pass
        logger.warning(f"Note on PostgreSQL table initialization: {str(e)}")
        return False
    finally:
        put_db_connection(conn)

def init_db_pool():
    global db_pool
    candidates = []
    
    if Config.DB_HOST:
        candidates.append(Config.DB_HOST)
        if '.' not in Config.DB_HOST and Config.DB_HOST not in ("127.0.0.1", "localhost"):
            for region in [
                "oregon-postgres.render.com",
                "frankfurt-postgres.render.com",
                "singapore-postgres.render.com",
                "ohio-postgres.render.com",
                "virginia-postgres.render.com"
            ]:
                candidates.append(f"{Config.DB_HOST}.{region}")
                
    if not os.getenv('VERCEL') and "127.0.0.1" not in candidates:
        candidates.append("127.0.0.1")
        
    last_err = None
    for h in candidates:
        try:
            db_pool = _try_create_pool(h)
            logger.info(f"PostgreSQL primary connection pool initialized successfully ({h}:{Config.DB_PORT}/{Config.DB_NAME}).")
            try:
                init_postgres_tables()
            except Exception:
                pass
            return True
        except Exception as e:
            last_err = e
            
    logger.error(f"Failed to initialize PostgreSQL pool across hosts: {str(last_err)}")
    db_pool = None
    return False

def close_db_pool():
    global db_pool
    if db_pool:
        try:
            db_pool.closeall()
            logger.info("PostgreSQL connection pool closed.")
        except Exception as e:
            logger.warning(f"Error closing DB pool: {e}")
        db_pool = None

def check_db_connection():
    try:
        conn = get_db_connection()
        if conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1;")
            put_db_connection(conn)
            return True
    except Exception as e:
        logger.warning(f"Database health check failed: {e}")
    return False

def get_db_connection():
    global db_pool
    if db_pool is None:
        init_db_pool()
    if db_pool:
        try:
            return db_pool.getconn()
        except Exception as e:
            logger.error(f"Error getting connection from PostgreSQL pool: {str(e)}")
            for h in [Config.DB_HOST, "127.0.0.1"]:
                try:
                    kwargs = {
                        'host': h,
                        'port': Config.DB_PORT,
                        'user': Config.DB_USER,
                        'password': Config.DB_PASSWORD,
                        'dbname': Config.DB_NAME,
                        'connect_timeout': 5
                    }
                    if Config.POSTGRES_SSLMODE:
                        kwargs['sslmode'] = Config.POSTGRES_SSLMODE
                    return psycopg2.connect(**kwargs)
                except Exception:
                    continue
    return None

def put_db_connection(conn):
    global db_pool
    if conn:
        if db_pool:
            try:
                db_pool.putconn(conn)
                return
            except Exception:
                pass
        try:
            conn.close()
        except Exception:
            pass

def execute_query(query, params=(), commit=True):
    query = _clean_postgres_query(query, params)
    is_insert = query.strip().upper().startswith("INSERT INTO")
    has_returning = "RETURNING" in query.upper()
    if is_insert and not has_returning:
        query = query.rstrip("; ") + " RETURNING id"
        has_returning = True

    conn = get_db_connection()
    if not conn:
        raise Exception("PostgreSQL primary database connection unavailable.")
    try:
        with conn.cursor(cursor_factory=extras.RealDictCursor) as cursor:
            cursor.execute(query, params)
            last_id = None
            if has_returning:
                row = cursor.fetchone()
                if row:
                    last_id = row.get("id", 1)
            if commit:
                conn.commit()
            return last_id or 1
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"PostgreSQL query error: {str(e)} | Query: {query}")
        raise e
    finally:
        put_db_connection(conn)

def fetch_one(query, params=()):
    query = _clean_postgres_query(query, params)
    conn = get_db_connection()
    if not conn:
        return None
    try:
        with conn.cursor(cursor_factory=extras.RealDictCursor) as cursor:
            cursor.execute(query, params)
            row = cursor.fetchone()
            return dict(row) if row else None
    except Exception as e:
        logger.error(f"PostgreSQL fetch_one error: {str(e)} | Query: {query}")
        return None
    finally:
        put_db_connection(conn)

def fetch_all(query, params=()):
    query = _clean_postgres_query(query, params)
    conn = get_db_connection()
    if not conn:
        return []
    try:
        with conn.cursor(cursor_factory=extras.RealDictCursor) as cursor:
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(r) for r in rows] if rows else []
    except Exception as e:
        logger.error(f"PostgreSQL fetch_all error: {str(e)} | Query: {query}")
        return []
    finally:
        put_db_connection(conn)

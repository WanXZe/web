CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(36) UNIQUE NOT NULL,
    user_name VARCHAR(20) UNIQUE NOT NULL,
    user_password VARCHAR(256) NOT NULL,
    user_mail VARCHAR(256) NOT NULL,
    user_identity VARCHAR(13) NOT NULL DEFAULT 'visitor',
    last_update_name TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS articles (
    id INTEGER PRIMARY KEY AUTOINCREMENT, -- 文章自增ID
    title VARCHAR(100) NOT NULL,          -- 文章标题
    content TEXT NOT NULL,                -- 文章内容
    author VARCHAR(36) NOT NULL,         -- 文章作者
    author_id  VARCHAR(36) NOT NULL DEFAULT 'e5438ea0-a50b-4bfe-9faa-1669428f9cea', --文章作者ID
    last_update TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO users (id, user_name, user_password, user_mail, user_identity)
VALUES ('e5438ea0-a50b-4bfe-9faa-1669428f9cea', 'WanXZe', 'e20d9d50ac3a1d137a687628f5c3f39ee26ffee9d3d896fbafcc5b4a680041de', "1409882253@qq.com", 'administrator');

INSERT OR IGNORE INTO articles (id, title, content, author, author_id)
VALUES
(1,'欢迎使用WanXZe博客系统！', '这是您的第一篇文章，您可以通过后台管理界面编辑或删除这篇文章。祝您使用愉快！', 'WanXZe', 'e5438ea0-a50b-4bfe-9faa-1669428f9cea');
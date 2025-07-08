INSERT INTO Users (name, password_hash, password_salt) VALUES (
    'admin',
    '$argon2id$v=19$m=19456,t=2,p=1$PQTe4vwV0PoWO5P7kv4rNw$uEb9BvG5YXGVFfJxqZ43qxTkjiUq3ZkLDPGS4N7lU4o',
    'PQTe4vwV0PoWO5P7kv4rNw'
);

INSERT INTO Categorys (name) VALUES ('General');
INSERT INTO Categorys (name) VALUES ('Off-Topic');


INSERT INTO Posts (user_id, category_id, title, body) VALUES (
    (SELECT id FROM Users WHERE name = 'admin'),
    (SELECT id FROM Categorys WHERE name = 'General'),
    'Hello World Every lizard!',
    'This is Neat!! This part is my body'
);

INSERT INTO Posts (user_id, category_id, title, body) VALUES (
    (SELECT id FROM Users WHERE name = 'admin'),
    (SELECT id FROM Categorys WHERE name = 'Off-Topic'),
    'Bird post!',
    'Tweet-type behavior'
);

INSERT INTO Posts (user_id, category_id, title, body) VALUES (
    (SELECT id FROM Users WHERE name = 'admin'),
    (SELECT id FROM Categorys WHERE name = 'General'),
    'This is a second lizard-post!',
    'Good to see we can have multiple posts'
);
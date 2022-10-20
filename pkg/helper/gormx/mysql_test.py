import mysql.connector

conn = mysql.connector.connect(
    user="x509_user",
    host="127.0.0.1",
    database="mysql",
    ssl_ca="/usr/local/var/mysql/ca.pem",
    ssl_cert="/usr/local/var/mysql/client-cert.pem",
    ssl_key="/usr/local/var/mysql/client-key.pem",
    ssl_verify_cert=True,
    ssl_verify_identity=True,  # hostname check를 하는데, 기본 인증서는 없어요...
    # 근데
)

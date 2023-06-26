# MySQL TLS; Secure Connection

- TLS를 이용하여 암호화된 통신을 제공하고
- 서버의 Identity를 확인하는 기능: 클라이언트의 옵션
  - `--ssl-mode`=`PREFERRED`,`REQUIRED`,`VERIFFY_CA`,`VERIFY_IDENTITY`
- 즉, 연결 암화만 제공하고, 클라이언트별 별도의 인증서를 제공하지는 않음
- 서버의 identity를 확인하는 것은 클라이언트의 책임

## proxy를 둔다면?

- client의 peer ip가 proxy의 ip일 것이므로, `user@host` 형태에서 `host`를 기준으로 ACL하는 것이 안됨

## Server: 자체 인증서 생성

### SSL/TLS 현재 상태 확인

    show variables like '%ssl%';

### 서버 키 생성

    mysql_ssl_rsa_setup

### 연결에 ssl을 강제하기

    [mysqld]
    # Require clients to connect either using SSL
    # or through a local socket file
    require_secure_transport = ON

### User & Role

    CREATE USER secure_user@localhost REQUIRE SSL;
    GRANT ALL ON *.* TO secure_user@localhost;
    FLUSH PRIVILEGES;

### try connect with non secure mode

    mysql -u secure_user -h 127.0.0.1 --ssl-mode=disabled

    실패해야 정상

## Trusted CA를 이용하는 방볍

    CREATE USER x509_user@localhost REQUIRE SUBJECT "/CN=MySQL_Server_8.0.30_Auto_Generated_Client_Certificate";
    GRANT ALL ON *.* TO x509_user@localhost;

    ALTER USER x509_user@localhost REQUIRE SUBJECT "/CN=MySQL_Server_8.0.30_Auto_Generated_CA_Certificate";
    FLUSH PRIVILEGES;

`X509` 옵션은 클라이언트가 CA가 서명한 인증서를 이용한 연결을 필요로한다.
`x509_user`로 연결하면 access denied 오류가 발생하며, 연결을 거부함

### 연결

    mysql -u x509_user -h 127.0.0.1  \
        --ssl-ca=/usr/local/var/mysql/ca.pem \
        --ssl-cert=/usr/local/var/mysql/client-cert.pem \
        --ssl-key=/usr/local/var/mysql/client-key.pem

`trusted ca`라고는 하지만,

## References

- <https://dev.mysql.com/doc/refman/8.0/en/encrypted-connections.html>
- <https://www.digitalocean.com/community/tutorials/how-to-configure-ssl-tls-for-mysql-on-ubuntu-16-04>
- <https://smallstep.com/hello-mtls/doc/server/mysql>

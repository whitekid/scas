# API

file storage repository

```text
    certs
     └ :project_id
        └ example.com: capool: contains ca certs, subordinate certs
            └ server.example.com: certs
```

create capool

```http
POST /v1alpha1/:projectID/capools/

{
    "name": "example.com"
}
```

generate root CA

```http
POST /v1alpha1/:projectID/capools/:capool/ca/

{
    "cn": "example.com",
    "hosts": ["example.com"]
}
```

generate subordinate ca

```http
POST /v1alpha1/:projectID/capools/:capool/ca/

{
    "cn": "example.com",
    "ca": {
        "expiry": "42720h"
    }
}
```

generate server certificate

```http
POST /v1alpha1/:projectID/capools/:capool/certificates/

{
    "cn": "server.example.com",
    "hosts": ["server.example.com", "127.0.0.1"]
}
```

get server certificate

```http
GET /v1alpha1/:projectID/capools/:capool/certificates/:cn/

{
    "key": ....,
    "cert": ....,
    "chain": ...
}
```

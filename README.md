# Argon2

An Argon2 hash encoder and decoder for Go with `sql.Scanner` and `driver.Valuer` implemented.

- [x] Implemented `sql.Sanner` and `driver.Valuer` to read to and write from SQL databases.

## Usage

```bash
go get github.com/merajsahebdar/argon2
```

```go
type User struct {
    ID       uint64
    Password argon2.Argon2
}

func NewUser() *User {
    return &User{
        ID:       1,
        Password: argon2.MustNew(),
    }
}
```

## License

This module is licensed under Apache 2.0 as found in the [LICENSE file](LICENSE).

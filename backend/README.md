Инициализация зависимостей
```
go mod init github.com/EvgeniyBudaev/golang-react-oauth--flow/backend
```

Сборка
```
go build -v ./cmd/
```

Удаление неиспользуемых зависимостей
```
go mod tidy -v
```

Библиотека для работы с маршрутами
https://github.com/gorilla/mux
```
go get -u github.com/gorilla/mux
```

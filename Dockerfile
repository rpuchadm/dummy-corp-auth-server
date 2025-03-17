#rust:latest

# Usa una imagen base de Go para compilar la aplicación
FROM rust:latest AS builder

# Establece el directorio de trabajo en el contenedor
WORKDIR /app

# Copia el código fuente del programa Go al contenedor
COPY . .

# Compila el programa Rust para crear un binario
RUN cargo build --release

# Usa una imagen base ligera de Ubuntu para ejecutar el binario
FROM ubuntu:noble

# Actualizar los repositorios e instalar curl
RUN apt-get update && apt-get install -y curl && apt-get clean

# Establece el directorio de trabajo en el contenedor
WORKDIR /app

# Copia el binario compilado desde el contenedor builder
COPY --from=builder /app/target/release/dummy-corp-auth-server .
COPY Rocket.toml .

# Expone el puerto en el que el servidor de Go escucha
EXPOSE 8080

# Define el comando para ejecutar el binario de Go
CMD ["./dummy-corp-auth-server"]

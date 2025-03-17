// funcion para generar un token aleatorio de n caracteres
pub fn random_token(n: usize) -> String {
    use rand::distributions::Alphanumeric;
    use rand::{Rng, thread_rng};

    thread_rng()
        .sample_iter(&Alphanumeric) // Genera una secuencia de caracteres alfanuméricos
        .take(n) // Toma `n` caracteres
        .map(char::from) // Convierte cada u8 a char
        .collect() // Recolecta en un String
}

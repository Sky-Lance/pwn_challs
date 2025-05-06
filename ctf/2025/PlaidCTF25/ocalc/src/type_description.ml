open Ctypes

module Types (F: Ctypes.TYPE) = struct
  open F

  type mpz
  let mpz_struct: mpz structure typ = typedef (structure "") "__mpz_struct"
  let () = seal mpz_struct
  let mpz = ptr mpz_struct
end
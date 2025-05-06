open Ctypes

module Functions (F : Ctypes.FOREIGN) = struct
  open F
  open Types_generated

  let mpz_init = foreign "mpz_init" (mpz @-> returning void)
  let mpz_clear = foreign "mpz_clear" (mpz @-> returning void)
  let mpz_set_si = foreign "mpz_set_si" (mpz @-> int @-> returning void)

  let mpz_set_str =
    foreign "mpz_set_str" (mpz @-> string @-> int @-> returning int)

  let mpz_get_str =
    foreign "mpz_get_str" (ptr char @-> int @-> mpz @-> returning (ptr char))

  let free_char_ptr = foreign "free" (ptr char @-> returning void)
  let mpz_swap = foreign "mpz_swap" (mpz @-> mpz @-> returning void)
  let mpz_get_si = foreign "mpz_get_si" (mpz @-> returning long)
  let mpz_add = foreign "mpz_add" (mpz @-> mpz @-> mpz @-> returning void)
  let mpz_sub = foreign "mpz_sub" (mpz @-> mpz @-> mpz @-> returning void)
  let mpz_mul = foreign "mpz_mul" (mpz @-> mpz @-> mpz @-> returning void)
  let mpz_cmp = foreign "mpz_cmp" (mpz @-> mpz @-> returning int)
  let mpz_set = foreign "mpz_set" (mpz @-> mpz @-> returning void)
  let mpz_addmul = foreign "mpz_addmul" (mpz @-> mpz @-> mpz @-> returning void)
  let mpz_neg = foreign "mpz_neg" (mpz @-> mpz @-> returning void)
  let mpz_abs = foreign "mpz_abs" (mpz @-> mpz @-> returning void)
end
